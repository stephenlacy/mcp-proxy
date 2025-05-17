use crate::auth::{AuthClient, AuthError};
use crate::config::{AuthConfig, ConfigError, ConfigManager, LockFile};
use crate::utils::DEFAULT_COORDINATION_TIMEOUT;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use log::{debug, error};
use serde::Deserialize;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::mpsc;

const STYLE: &str = "<style>html{font-family: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'}</style>";

#[derive(Debug, Error)]
pub enum CoordinationError {
    #[error("Auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Coordination timeout")]
    Timeout,
    #[error("Coordination error: {0}")]
    Other(String),
}

#[derive(Clone, Debug)]
pub enum AuthCoordinationResult {
    HandleAuth { auth_url: String },
    WaitForAuth { lock_file: LockFile },
    AuthDone { auth_config: AuthConfig },
}

// OAuth callback query parameters
#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

// Shared state between the server routes
#[derive(Clone)]
struct ServerState {
    auth_client: Arc<AuthClient>,
    auth_done_tx: mpsc::Sender<AuthConfig>,
}

pub async fn coordinate_auth(
    server_url_hash: &str,
    auth_client: Arc<AuthClient>,
    callback_port: u16,
    _timeout_seconds: Option<u64>,
) -> Result<AuthCoordinationResult, CoordinationError> {
    let config_manager = ConfigManager::new();

    // First, try to get existing auth config
    match auth_client.get_auth_config().await {
        Ok(config) => {
            debug!("Found valid auth config");
            Ok(AuthCoordinationResult::AuthDone {
                auth_config: config,
            })
        }
        Err(AuthError::AuthRequired) => {
            debug!("Auth required, continuing with coordination");

            // Try to create a lock file
            let server_url = auth_client.server_url.clone();
            match config_manager.create_lock_file(server_url_hash, &server_url, callback_port) {
                Ok(lock_file) => {
                    if lock_file.pid == std::process::id() {
                        // We created the lock, so we'll handle auth
                        debug!("We have the lock, starting OAuth flow");
                        let auth_url = auth_client.initialize_auth().await?;

                        Ok(AuthCoordinationResult::HandleAuth { auth_url })
                    } else {
                        // Another instance is handling auth
                        debug!("Another process is handling auth, waiting");
                        Ok(AuthCoordinationResult::WaitForAuth { lock_file })
                    }
                }
                Err(e) => {
                    error!("Failed to create lock file: {}", e);
                    Err(e.into())
                }
            }
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn handle_auth(
    auth_client: Arc<AuthClient>,
    auth_url: &str,
    callback_port: u16,
) -> Result<AuthConfig, CoordinationError> {
    debug!("Starting auth server on port {}", callback_port);

    // Create channel for receiving auth result
    let (auth_done_tx, mut auth_done_rx) = mpsc::channel::<AuthConfig>(1);

    // Create shared server state
    let state = ServerState {
        auth_client: auth_client.clone(),
        auth_done_tx,
    };

    // Create the server
    let app = Router::new()
        .route("/oauth/callback", get(oauth_callback))
        .route("/", get(root_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], callback_port));
    debug!("Starting OAuth callback server at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Spawn the server in a separate task
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Open the browser with the auth URL
    debug!("Opening browser with URL: {}", auth_url);
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(auth_url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", auth_url])
            .spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open").arg(auth_url).spawn()?;
    }

    // Wait for auth to complete or timeout
    debug!("Waiting for OAuth callback...");
    let timeout_duration = Duration::from_secs(DEFAULT_COORDINATION_TIMEOUT * 2);

    let result = match tokio::time::timeout(timeout_duration, auth_done_rx.recv()).await {
        Ok(Some(auth_config)) => {
            debug!("Auth completed successfully");
            Ok(auth_config)
        }
        Ok(None) => {
            error!("Auth failed - channel closed");
            Err(CoordinationError::Other(
                "Auth channel closed unexpectedly".to_string(),
            ))
        }
        Err(_) => {
            error!("Auth timed out");
            Err(CoordinationError::Timeout)
        }
    };
    // Give some time for the server to shut down
    tokio::time::sleep(Duration::from_secs(1)).await;

    server_handle.abort();

    result
}

pub async fn wait_for_auth(
    auth_client: Arc<AuthClient>,
    lock_file: &LockFile,
) -> Result<AuthConfig, CoordinationError> {
    let server_url_hash = auth_client.get_server_url_hash();

    // Check if the lock is still valid
    let config_manager = ConfigManager::new();
    match config_manager.read_lock_file(server_url_hash) {
        Ok(current_lock) => {
            if current_lock.pid != lock_file.pid || is_lock_expired(&current_lock) {
                debug!("Lock changed or expired, retrying with our own auth");
                return Err(CoordinationError::Other(
                    "Lock changed or expired".to_string(),
                ));
            }
        }
        Err(ConfigError::NotFound) => {
            debug!("Lock file removed, auth may be complete");
            // Fall through to check auth config
        }
        Err(e) => {
            error!("Error reading lock file: {}", e);
            return Err(e.into());
        }
    }

    // Try to get the auth config
    match auth_client.get_auth_config().await {
        Ok(config) => {
            debug!("Auth complete, found valid config");
            return Ok(config);
        }
        Err(AuthError::AuthRequired) => {
            debug!("Still waiting for auth to complete");
        }
        Err(e) => {
            error!("Error getting auth config: {}", e);
            return Err(e.into());
        }
    }

    error!("Timed out waiting for auth");
    Err(CoordinationError::Timeout)
}

fn is_lock_expired(lock: &LockFile) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Lock expires after 10 minutes
    now > lock.created_at + 600
}

// OAuth callback handler
async fn oauth_callback(
    State(state): State<ServerState>,
    Query(params): Query<OAuthCallback>,
) -> impl IntoResponse {
    debug!("Received OAuth callback: {:?}", params);

    // Check if we received an error from the OAuth server
    if let Some(error) = &params.error {
        let error_description = params
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");

        error!("OAuth error: {} - {}", error, error_description);

        // If we got invalid_client error, we need to register the client
        if error == "invalid_client" {
            return (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<html>{STYLE}<body><h1>Authentication Error</h1>
                    <p>Client registration error: {}</p>
                    <p>Please restart the application to trigger client registration.</p>
                    </body></html>",
                    error_description
                )),
            );
        }

        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<html>{STYLE}<body><h1>Authentication Error</h1><p>{}: {}</p></body></html>",
                error, error_description
            )),
        );
    }

    // Check if we have a code
    let code = match &params.code {
        Some(code) => code,
        None => {
            error!("Missing authorization code in callback");
            return (
                StatusCode::BAD_REQUEST,
                Html(format!("<html>{STYLE}<body><h1>Authentication Error</h1><p>Missing authorization code</p></body></html>")),
            );
        }
    };

    // Process the callback with the code
    match state.auth_client.handle_callback(code, &params.state).await {
        Ok(config) => {
            if let Err(e) = state.auth_done_tx.send(config).await {
                error!("Failed to send auth completion: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(
                        format!("<html>{STYLE}<body><h1>Error</h1><p>Internal server error</p></body></html>")
                    ),
                );
            }

            (
                StatusCode::OK,
                Html(format!("<html>{STYLE}<body><h1>Authentication Complete</h1><p>You can close this window.</p></body></html>")),
            )
        }
        Err(e) => {
            error!("Auth callback error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(format!(
                    "<html>{STYLE}<body><h1>Authentication Error</h1><p>{}</p></body></html>",
                    e
                )),
            )
        }
    }
}

// Root handler for the OAuth server
async fn root_handler() -> impl IntoResponse {
    Html(format!("<html>{STYLE}<body><h1>MCP OAuth Server</h1><p>This server handles OAuth callbacks for MCP authentication.</p></body></html>"))
}
