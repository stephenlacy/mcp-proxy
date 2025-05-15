use http::{header::AUTHORIZATION, HeaderName, HeaderValue};
use log::debug;
use reqwest::Client as HttpClient;

/**
 * Create a local server that proxies requests to a remote server over SSE.
 */
use rmcp::{
    model::{ClientCapabilities, ClientInfo},
    transport::{
        sse::{ReqwestSseClient, SseTransport},
        stdio,
    },
    ServiceExt,
};
use std::{collections::HashMap, error::Error as StdError, str::FromStr, sync::Arc};
use tracing::info;

use crate::{
    auth::AuthClient,
    coordination::{self, AuthCoordinationResult},
    proxy_handler::ProxyHandler,
    utils::DEFAULT_CALLBACK_PORT,
};

/// Configuration for the SSE client
pub struct SseClientConfig {
    pub url: String,
    pub headers: HashMap<String, String>,
}

/// Run the SSE client
///
/// This function connects to a remote SSE server and exposes it as a stdio server.
pub async fn run_sse_client(config: SseClientConfig) -> Result<(), Box<dyn StdError>> {
    info!("Running SSE client with URL: {}", config.url);

    let http_client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let req = http_client.get(&config.url).send().await?;
    let auth_config = match req.status() {
        reqwest::StatusCode::OK => {
            info!("No authentication required");
            None
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            info!("Authentication required");

            let auth_client = Arc::new(AuthClient::new(config.url.clone(), DEFAULT_CALLBACK_PORT)?);
            let server_url_hash = auth_client.get_server_url_hash().to_string();
            // Coordinate auth with other processes
            let auth_result = coordination::coordinate_auth(
                &server_url_hash,
                auth_client.clone(),
                DEFAULT_CALLBACK_PORT,
                None,
            )
            .await?;

            // Get auth config
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
            Some(auth_config)
        }
        _ => {
            return Err(format!("Unexpected response: {:?}", req.status()).into());
        }
    };

    // Create the header map
    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in config.headers {
        headers.insert(HeaderName::from_str(&key)?, value.parse()?);
    }

    if let Some(auth_config) = auth_config {
        if auth_config.access_token.is_none() {
            return Err("Access token is empty".into());
        }
        // Add the authentication headers
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Bearer {}",
                auth_config.access_token.as_ref().unwrap()
            ))?,
        );
    }

    // Create the reqwest client to be by the SSE client.
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let sse_client = ReqwestSseClient::new_with_client(&config.url, client).await?;

    // Create SSE transport
    let transport = SseTransport::start_with_client(sse_client).await?;

    // Create client info with full capabilities to ensure we can use all the server's features
    let client_info = ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::builder()
            .enable_experimental()
            .enable_roots()
            .enable_roots_list_changed()
            .enable_sampling()
            .build(),
        ..Default::default()
    };

    // Create client service with transport
    let client = client_info.serve(transport).await?;

    // Get server info
    let server_info = client.peer_info();
    info!("Connected to server: {}", server_info.server_info.name);

    // Create proxy handler
    let proxy_handler = ProxyHandler::new(client);

    // Create stdio transport
    let stdio_transport = stdio();

    // Create server with proxy handler and stdio transport
    let server = proxy_handler.serve(stdio_transport).await?;

    // Wait for completion
    server.waiting().await?;

    Ok(())
}
