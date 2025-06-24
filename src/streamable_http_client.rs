use futures::stream::BoxStream;
use log::debug;
use rmcp::{
    model::{ClientCapabilities, ClientInfo, ClientJsonRpcMessage},
    transport::{
        stdio,
        streamable_http_client::{
            SseError, StreamableHttpClient, StreamableHttpClientTransport,
            StreamableHttpClientTransportConfig, StreamableHttpError, StreamableHttpPostResponse,
        },
    },
    ServiceExt,
};
use std::{collections::HashMap, error::Error as StdError, sync::Arc};
use tracing::info;

use crate::{
    auth::AuthClient,
    coordination::{self, AuthCoordinationResult},
    proxy_handler::ProxyHandler,
    utils::DEFAULT_CALLBACK_PORT,
};

/// Configuration for the Streamable HTTP client
pub struct StreamableHttpClientConfig {
    pub url: String,
    pub headers: HashMap<String, String>,
}

#[derive(Clone)]
struct AuthenticatedHttpClient {
    client: reqwest::Client,
    auth_token: Arc<tokio::sync::RwLock<String>>,
    auth_client: Option<Arc<AuthClient>>,
}

impl AuthenticatedHttpClient {
    async fn refresh_token_if_needed(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let Some(auth_client) = &self.auth_client else {
            return Ok(false);
        };

        let current_config = auth_client.get_auth_config().await?;
        match auth_client.refresh_token(&current_config).await {
            Ok(refreshed_config) => {
                let new_token = refreshed_config.access_token.unwrap_or_default();
                tracing::info!("Successfully refreshed token");
                *self.auth_token.write().await = new_token;
                Ok(true)
            }
            Err(e) => {
                tracing::warn!("Refresh token failed: {}", e);
                Ok(false)
            }
        }
    }

    async fn start_fresh_oauth_flow(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(auth_client) = &self.auth_client else {
            return Ok(());
        };

        tracing::info!("Starting fresh OAuth flow due to invalid tokens");

        let server_url_hash = auth_client.get_server_url_hash().to_string();
        let config_manager = crate::config::ConfigManager::new();
        let auth_path = config_manager.get_auth_config_path(&server_url_hash);
        if auth_path.exists() {
            std::fs::remove_file(&auth_path).ok();
            tracing::info!("Cleared invalid auth config");
        }

        let auth_result = crate::coordination::coordinate_auth(
            &server_url_hash,
            auth_client.clone(),
            crate::utils::DEFAULT_CALLBACK_PORT,
            None,
        )
        .await?;

        let auth_config = match auth_result {
            crate::coordination::AuthCoordinationResult::HandleAuth { auth_url } => {
                tracing::info!("Opening browser for re-authentication. If it doesn't open automatically, please visit this URL:");
                tracing::info!("{}", auth_url);
                crate::coordination::handle_auth(
                    auth_client.clone(),
                    &auth_url,
                    crate::utils::DEFAULT_CALLBACK_PORT,
                )
                .await?
            }
            crate::coordination::AuthCoordinationResult::WaitForAuth { lock_file } => {
                tracing::info!("Another instance is handling re-authentication. Waiting...");
                crate::coordination::wait_for_auth(auth_client.clone(), &lock_file).await?
            }
            crate::coordination::AuthCoordinationResult::AuthDone { auth_config } => {
                tracing::info!("Re-authentication already completed");
                auth_config
            }
        };

        if let Some(new_token) = auth_config.access_token {
            *self.auth_token.write().await = new_token;
            tracing::info!("Successfully completed fresh OAuth flow");
        }
        Ok(())
    }

    async fn get_auth_token(&self) -> Option<String> {
        let token = self.auth_token.read().await.clone();
        if token.is_empty() {
            None
        } else {
            Some(token)
        }
    }

    async fn handle_auth_error(
        &self,
        error: &StreamableHttpError<reqwest::Error>,
        is_retry: bool,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let StreamableHttpError::Client(ref reqwest_error) = error else {
            return Ok(false);
        };

        let Some(status) = reqwest_error.status() else {
            return Ok(false);
        };

        if status != reqwest::StatusCode::UNAUTHORIZED || self.auth_client.is_none() {
            return Ok(false);
        }

        if is_retry {
            tracing::warn!("Got 401 even after token refresh, starting fresh OAuth flow");
            self.start_fresh_oauth_flow().await?;
            tracing::info!("Fresh OAuth flow completed, should retry");
            return Ok(true);
        }

        tracing::info!("Got 401, attempting token refresh");
        match self.refresh_token_if_needed().await? {
            true => {
                tracing::info!("Token refresh completed, will retry");
                Ok(true)
            }
            false => {
                tracing::warn!("Token refresh failed, starting fresh OAuth flow");
                self.start_fresh_oauth_flow().await?;
                tracing::info!("Fresh OAuth flow completed, should retry");
                Ok(true)
            }
        }
    }
}

impl StreamableHttpClient for AuthenticatedHttpClient {
    type Error = reqwest::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        _auth_header: Option<String>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let auth_token = self.get_auth_token().await;

        match self
            .client
            .post_message(uri.clone(), message.clone(), session_id.clone(), auth_token)
            .await
        {
            Ok(response) => Ok(response),
            Err(error) => match self.handle_auth_error(&error, false).await {
                Ok(true) => {
                    let new_auth_token = self.get_auth_token().await;
                    match self
                        .client
                        .post_message(
                            uri.clone(),
                            message.clone(),
                            session_id.clone(),
                            new_auth_token,
                        )
                        .await
                    {
                        Ok(response) => Ok(response),
                        Err(retry_error) => {
                            match self.handle_auth_error(&retry_error, true).await {
                                Ok(true) => {
                                    let final_auth_token = self.get_auth_token().await;
                                    self.client
                                        .post_message(uri, message, session_id, final_auth_token)
                                        .await
                                }
                                Ok(false) => Err(retry_error),
                                Err(auth_error) => {
                                    tracing::error!("Auth error after retry: {}", auth_error);
                                    Err(retry_error)
                                }
                            }
                        }
                    }
                }
                Ok(false) => Err(error),
                Err(auth_error) => {
                    tracing::error!("Auth error: {}", auth_error);
                    Err(error)
                }
            },
        }
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        _auth_header: Option<String>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let auth_token = self.get_auth_token().await;
        self.client
            .delete_session(uri, session_id, auth_token)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        last_event_id: Option<String>,
        _auth_header: Option<String>,
    ) -> Result<
        BoxStream<'static, Result<sse_stream::Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        let auth_token = self.get_auth_token().await;
        self.client
            .get_stream(uri, session_id, last_event_id, auth_token)
            .await
    }
}

pub async fn run_streamable_http_client(
    config: StreamableHttpClientConfig,
) -> Result<(), Box<dyn StdError>> {
    info!("Running Streamable HTTP client with URL: {}", config.url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let req = http_client.get(&config.url).send().await?;
    let (auth_config, auth_client) = match req.status() {
        reqwest::StatusCode::OK => {
            info!("No authentication required");
            (None, None)
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            info!("Authentication required");

            let auth_client = Arc::new(AuthClient::new(config.url.clone(), DEFAULT_CALLBACK_PORT)?);
            let server_url_hash = auth_client.get_server_url_hash().to_string();
            let auth_result = coordination::coordinate_auth(
                &server_url_hash,
                auth_client.clone(),
                DEFAULT_CALLBACK_PORT,
                None,
            )
            .await?;

            let auth_config = match auth_result {
                AuthCoordinationResult::HandleAuth { auth_url } => {
                    info!("Opening browser for authentication. If it doesn't open automatically, please visit this URL:");
                    info!("{}", auth_url);
                    coordination::handle_auth(auth_client.clone(), &auth_url, DEFAULT_CALLBACK_PORT)
                        .await?
                }
                AuthCoordinationResult::WaitForAuth { lock_file } => {
                    debug!("Another instance is handling authentication. Waiting...");
                    coordination::wait_for_auth(auth_client.clone(), &lock_file).await?
                }
                AuthCoordinationResult::AuthDone { auth_config } => {
                    info!("Using existing authentication");
                    auth_config
                }
            };
            (Some(auth_config), Some(auth_client))
        }
        _ => {
            return Err(format!("Unexpected response: {:?}", req.status()).into());
        }
    };

    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in config.headers {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
            reqwest::header::HeaderValue::from_str(&value)?,
        );
    }

    let base_client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    info!("Connecting to Streamable HTTP endpoint: {}", config.url);

    // Create transport config
    let transport_config = StreamableHttpClientTransportConfig::with_uri(config.url.clone());

    let auth_token = match auth_config {
        Some(auth_config) => {
            let Some(token) = auth_config.access_token else {
                return Err("Access token is empty".into());
            };

            if let (Some(auth_client_ref), Some(expires_at)) =
                (&auth_client, auth_config.expires_at)
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if now >= expires_at {
                    info!("Token appears to be expired, refreshing...");
                    match auth_client_ref.get_auth_config().await {
                        Ok(refreshed_config) => refreshed_config.access_token.unwrap_or(token),
                        Err(e) => {
                            tracing::warn!("Failed to refresh expired token: {}", e);
                            token
                        }
                    }
                } else {
                    token
                }
            } else {
                token
            }
        }
        None => String::new(),
    };
    let authenticated_client = AuthenticatedHttpClient {
        client: base_client,
        auth_token: Arc::new(tokio::sync::RwLock::new(auth_token)),
        auth_client,
    };

    let transport =
        StreamableHttpClientTransport::with_client(authenticated_client, transport_config);

    let client_info = ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::builder().enable_sampling().build(),
        ..Default::default()
    };

    let client = client_info.serve(transport).await?;

    let server_info = client.peer_info();
    info!(
        "Connected to server: {}",
        server_info.unwrap().server_info.name
    );

    let proxy_handler = ProxyHandler::new(client);
    let stdio_transport = stdio();
    let server = proxy_handler.serve(stdio_transport).await?;

    server.waiting().await?;
    Ok(())
}
