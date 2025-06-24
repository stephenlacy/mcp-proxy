use crate::config::{AuthConfig, ConfigError, ConfigManager};
use log::{debug, error};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

struct OidcConfigCache {
    config: Option<serde_json::Value>,
    last_updated: Option<SystemTime>,
    ttl: Duration,
}

// Client registration information
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ClientRegistration {
    client_id: String,
    client_secret: Option<String>,
    registration_access_token: Option<String>,
    registration_client_uri: Option<String>,
    client_id_issued_at: Option<u64>,
    client_secret_expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthTokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Authentication required")]
    AuthRequired,
    #[error("Invalid server URL")]
    InvalidServerUrl,
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClientRegistrationResponse {
    client_id: String,
    client_secret: Option<String>,
    registration_access_token: Option<String>,
    registration_client_uri: Option<String>,
    client_id_issued_at: Option<u64>,
    client_secret_expires_at: Option<u64>,
}

pub struct AuthClient {
    pub server_url: String,
    config_manager: ConfigManager,
    server_url_hash: String,
    http_client: HttpClient,
    auth_state: RwLock<Option<String>>,
    session_id: String,
    redirect_port: u16,
    oidc_config_cache: RwLock<OidcConfigCache>, // Cache for OIDC config
    client_registration: RwLock<Option<ClientRegistration>>, // Dynamic client registration info
}

impl AuthClient {
    pub fn new(server_url: String, redirect_port: u16) -> Result<Self> {
        let url = Url::parse(&server_url)?;
        if !url.scheme().starts_with("http") {
            return Err(AuthError::InvalidServerUrl);
        }

        let server_url_hash = crate::utils::hash_server_url(&server_url);

        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let session_id = Uuid::new_v4().to_string();

        // Initialize config cache with 1 hour TTL
        let oidc_config_cache = RwLock::new(OidcConfigCache {
            config: None,
            last_updated: None,
            ttl: Duration::from_secs(3600), // 1 hour
        });

        Ok(Self {
            server_url,
            config_manager: ConfigManager::new(),
            server_url_hash,
            http_client,
            auth_state: RwLock::new(None),
            session_id,
            redirect_port,
            oidc_config_cache,
            client_registration: RwLock::new(None),
        })
    }

    /// Load client registration from config or register a new client
    async fn ensure_client_registration(&self) -> Result<ClientRegistration> {
        if let Some(registration) = self.client_registration.read().await.clone() {
            return Ok(registration);
        }

        // Try to load from config
        let registration_path = self
            .config_manager
            .get_registration_path(&self.server_url_hash);
        if registration_path.exists() {
            match std::fs::read_to_string(&registration_path) {
                Ok(json) => {
                    match serde_json::from_str::<ClientRegistration>(&json) {
                        Ok(registration) => {
                            // Store in cache
                            *self.client_registration.write().await = Some(registration.clone());
                            return Ok(registration);
                        }
                        Err(e) => {
                            debug!("Failed to parse client registration: {}", e);
                            // Fall through to register a new client
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read client registration: {}", e);
                    // Fall through to register a new client
                }
            }
        }

        // Get OIDC configuration to find registration endpoint
        let oidc_config = self.discover_openid_config().await?;

        // Get registration endpoint
        let registration_endpoint = oidc_config
            .get("registration_endpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AuthError::Other("No registration_endpoint in OIDC configuration".to_string())
            })?;

        // Create registration request
        let redirect_url = self.get_redirect_url();
        let registration_request = serde_json::json!({
            "client_name": "mcp-proxy",
            "application_type": "native",
            "redirect_uris": [redirect_url],
            "token_endpoint_auth_method": "none", // Public client
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid" // Do we need this?
        });

        debug!("Registering client with request: {}", registration_request);

        // Send registration request
        let response = self
            .http_client
            .post(registration_endpoint)
            .header("Content-Type", "application/json")
            .json(&registration_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Failed to register client: {} - {}", status, error_text);
            return Err(AuthError::Other(format!(
                "Failed to register client: {} - {}",
                status, error_text
            )));
        }

        let registration = response.json::<ClientRegistration>().await?;

        // Save to config
        let json = serde_json::to_string_pretty(&registration)?;
        self.config_manager.ensure_config_dir()?;
        std::fs::write(&registration_path, json)?;

        // Store in cache
        {
            let mut reg = self.client_registration.write().await;
            *reg = Some(registration.clone());
        }

        Ok(registration)
    }

    pub fn get_server_url_hash(&self) -> &str {
        &self.server_url_hash
    }

    pub fn get_redirect_url(&self) -> String {
        format!("http://127.0.0.1:{}/oauth/callback", self.redirect_port)
    }

    async fn discover_openid_config(&self) -> Result<serde_json::Value> {
        // Check if we have a cached and valid configuration
        {
            let cache = self.oidc_config_cache.read().await;
            if let (Some(config), Some(last_updated)) = (&cache.config, cache.last_updated) {
                let now = SystemTime::now();
                if now
                    .duration_since(last_updated)
                    .map(|d| d < cache.ttl)
                    .unwrap_or(false)
                {
                    debug!("Using cached OpenID configuration");
                    return Ok(config.clone());
                }
            }
        }

        debug!("Cache miss or expired, fetching new OpenID configuration");

        // Parse the server URL to get the base domain for .well-known discovery
        let parsed_url = Url::parse(&self.server_url)?;

        // Construct base URL with just schema and host
        let base_url = format!(
            "{}://{}",
            parsed_url.scheme(),
            parsed_url
                .host_str()
                .ok_or_else(|| AuthError::InvalidServerUrl)?
        );

        // Add port if specified and not the default for the scheme
        let base_url = match parsed_url.port() {
            Some(port) => {
                let is_default_port = (parsed_url.scheme() == "http" && port == 80)
                    || (parsed_url.scheme() == "https" && port == 443);

                if is_default_port {
                    base_url
                } else {
                    format!("{}:{}", base_url, port)
                }
            }
            None => base_url,
        };

        // Discover OIDC configuration from .well-known endpoint
        let well_known_url = format!("{}/.well-known/oauth-authorization-server", base_url);

        let response = self.http_client.get(&well_known_url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!(
                "Failed to get OpenID configuration: {} - {}",
                status, error_text
            );
            return Err(AuthError::Other(format!(
                "Failed to get OpenID configuration: {} - {}",
                status, error_text
            )));
        }

        let config = response.json::<serde_json::Value>().await?;
        debug!("Successfully retrieved OpenID configuration");

        // Validate that the configuration has required fields
        let required_fields = ["authorization_endpoint", "token_endpoint", "issuer"];
        for field in required_fields {
            if config.get(field).is_none() {
                return Err(AuthError::Other(format!(
                    "OIDC configuration missing required field: {}",
                    field
                )));
            }
        }

        // Update the cache
        {
            let mut cache = self.oidc_config_cache.write().await;
            cache.config = Some(config.clone());
            cache.last_updated = Some(SystemTime::now());
        }

        Ok(config)
    }

    pub async fn initialize_auth(&self) -> Result<String> {
        debug!("Initializing OAuth authorization flow");

        // Random state for CSRF
        let state = Uuid::new_v4().to_string();

        *self.auth_state.write().await = Some(state.clone());

        let redirect_url = self.get_redirect_url();

        let oidc_config = self.discover_openid_config().await?;

        let auth_endpoint = oidc_config
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AuthError::Other("No authorization_endpoint in OIDC configuration".to_string())
            })?;

        debug!("Using authorization endpoint: {}", auth_endpoint);

        let client_registration = self.ensure_client_registration().await?;

        // Get scope from config
        let supported_scopes = oidc_config
            .get("scopes_supported")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|| "openid profile email".to_string());

        debug!("Using scopes: {}", supported_scopes);

        // Build the authorization URL with proper parameters from OIDC configuration
        let auth_url = reqwest::Url::parse(auth_endpoint)?
            .query_pairs_mut()
            .append_pair("redirect_uri", &redirect_url)
            .append_pair("state", &state)
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_registration.client_id)
            .append_pair("scope", &supported_scopes)
            .finish()
            .to_string();

        debug!("Built authorization URL: {}", auth_url);

        Ok(auth_url)
    }

    pub async fn handle_callback(&self, code: &str, state: &str) -> Result<AuthConfig> {
        debug!("Handling OAuth callback with code");

        // Check if the state matches our stored state
        let stored_state = self.auth_state.read().await.clone();
        if stored_state.is_none() || stored_state.unwrap() != state {
            return Err(AuthError::Other(
                "State mismatch, possible CSRF attack".to_string(),
            ));
        }

        let oidc_config = self.discover_openid_config().await?;

        let token_endpoint = oidc_config
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::Other("No token_endpoint in OIDC configuration".into()))?;

        debug!("Using token endpoint: {}", token_endpoint);

        let client_registration = self.ensure_client_registration().await?;

        // Exchange the code for a token
        let redirect_uri = self.get_redirect_url();

        let form_data = [
            ("code", code.to_string()),
            ("grant_type", "authorization_code".to_string()),
            ("client_id", client_registration.client_id.clone()),
            ("redirect_uri", redirect_uri),
        ];

        debug!("Token exchange form data: {:?}", form_data);

        let response = self
            .http_client
            .post(token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form_data)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Failed to get tokens: {} - {}", status, error_text);
            return Err(AuthError::Other(format!(
                "Failed to get tokens: {} - {}",
                status, error_text
            )));
        }

        let token_data: AuthTokenResponse = response.json().await?;
        if token_data.access_token.is_none() {
            return Err(AuthError::Other(
                "No access_token in refresh response".to_string(),
            ));
        }

        let expires_in = token_data.expires_in.unwrap_or(3600); // Default to 1 hour if not provided

        // Calculate expiration timestamp
        let expires_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + expires_in,
        );

        debug!("Successfully obtained tokens");

        // Create auth config
        let auth_config = AuthConfig {
            server_url: self.server_url.clone(),
            access_token: token_data.access_token,
            refresh_token: token_data.refresh_token,
            expires_at,
            auth_state: None,
            session_id: self.session_id.clone(),
        };

        // Save to config
        self.config_manager
            .save_auth_config(&self.server_url_hash, &auth_config)?;
        debug!("Saved auth config");

        Ok(auth_config)
    }

    pub async fn get_auth_config(&self) -> Result<AuthConfig> {
        // Try to load from config file
        match self.config_manager.load_auth_config(&self.server_url_hash) {
            Ok(config) => {
                debug!("Loaded auth config from file");

                // Check if token is expired
                if let Some(expires_at) = config.expires_at {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if now >= expires_at {
                        debug!("Token is expired, trying to refresh");
                        return self.refresh_token(&config).await;
                    }
                }

                Ok(config)
            }
            Err(ConfigError::NotFound) => {
                debug!("Auth config not found, need to authenticate");
                Err(AuthError::AuthRequired)
            }
            Err(e) => {
                error!("Failed to load auth config: {}", e);
                Err(e.into())
            }
        }
    }

    pub async fn refresh_token(&self, config: &AuthConfig) -> Result<AuthConfig> {
        let refresh_token = match &config.refresh_token {
            Some(token) => token.clone(),
            None => return Err(AuthError::Other("No refresh token found".to_string())),
        };

        // Discover OIDC configuration
        let oidc_config = self.discover_openid_config().await?;

        // Extract the token endpoint
        let token_endpoint = oidc_config
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AuthError::Other("No token_endpoint in OIDC configuration".to_string())
            })?;

        debug!("Using token endpoint for refresh: {}", token_endpoint);

        // Get our registered client
        let client_registration = self.ensure_client_registration().await?;
        debug!(
            "Using registered client ID for refresh: {}",
            client_registration.client_id
        );

        // Call token endpoint with refresh_token grant type
        let response = self
            .http_client
            .post(token_endpoint)
            .form(&[
                ("refresh_token", refresh_token.clone()),
                ("grant_type", "refresh_token".to_string()),
                ("client_id", client_registration.client_id.clone()),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("Failed to refresh token: {} - {}", status, error_text);

            // If we get a 401 or 400, the refresh token is invalid/expired, need to re-auth
            if status.as_u16() == 401 || status.as_u16() == 400 {
                return Err(AuthError::AuthRequired);
            }

            return Err(AuthError::Other(format!(
                "Failed to refresh token: {} - {}",
                status, error_text
            )));
        }

        let token_data: AuthTokenResponse = response.json().await?;
        if token_data.access_token.is_none() {
            return Err(AuthError::Other(
                "No access_token in refresh response".to_string(),
            ));
        }

        let expires_in = token_data.expires_in.unwrap_or(3600); // Default to 1 hour if not provided

        // Calculate expiration timestamp
        let expires_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + expires_in,
        );

        debug!("Successfully refreshed token");

        // Create new auth config
        let new_config = AuthConfig {
            server_url: self.server_url.clone(),
            access_token: token_data.access_token,
            refresh_token: token_data.refresh_token,
            expires_at,
            auth_state: None,
            session_id: self.session_id.clone(),
        };

        // Save to config
        self.config_manager
            .save_auth_config(&self.server_url_hash, &new_config)?;
        debug!("Saved refreshed auth config");

        Ok(new_config)
    }
}
