use http::HeaderName;
/**
 * Create a local server that proxies requests to a remote server over SSE.
 */
use rmcp::{
    model::{ClientCapabilities, ClientInfo},
    transport::{sse::SseTransport, stdio},
    ServiceExt,
};
use std::{collections::HashMap, error::Error as StdError, str::FromStr};
use tracing::info;

use crate::proxy_handler::ProxyHandler;

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

    // Create the header map
    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in config.headers {
        headers.insert(HeaderName::from_str(&key)?, value.parse()?);
    }

    // Create the reqwest client to be by the SSE client.
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    // Create SSE transport
    let transport = SseTransport::start_with_client(&config.url, client).await?;

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
