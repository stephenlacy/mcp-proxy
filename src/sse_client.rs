use log::debug;
use reqwest::Client as HttpClient;

use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures::StreamExt;
/**
 * Create a local server that proxies requests to a remote server over SSE.
 */
use rmcp::{
    model::{ClientCapabilities, ClientInfo},
    transport::{async_rw::AsyncRwTransport, stdio},
    ServiceExt,
};
use serde_json::Value;
use std::{collections::HashMap, error::Error as StdError, sync::Arc};
use tokio::io::AsyncWrite;
use tokio_util::io::StreamReader;
use tracing::{error, info, warn};

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

/// SSE Writer implementation for outgoing messages
/// TODO: remove in the next major version since SSE is deprecated
struct SseWriter {
    client: HttpClient,
    message_url: String,
}

impl AsyncWrite for SseWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if let Ok(json_str) = std::str::from_utf8(buf) {
            let lines: Vec<&str> = json_str.lines().collect();
            for line in lines {
                if !line.trim().is_empty() {
                    if let Ok(json_value) = serde_json::from_str::<Value>(line) {
                        let client = self.client.clone();
                        let url = self.message_url.clone();

                        tokio::spawn(async move {
                            match client.post(&url).json(&json_value).send().await {
                                Ok(response) => {
                                    if !response.status().is_success() {
                                        warn!(
                                            "Message POST failed with status: {}",
                                            response.status()
                                        );
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to send message: {}", e);
                                }
                            }
                        });
                    }
                }
            }
        }

        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
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

    // Create the header map for authenticated requests
    let mut headers = reqwest::header::HeaderMap::new();
    for (key, value) in config.headers {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
            reqwest::header::HeaderValue::from_str(&value)?,
        );
    }

    if let Some(auth_config) = auth_config {
        if auth_config.access_token.is_none() {
            return Err("Access token is empty".into());
        }
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", auth_config.access_token.as_ref().unwrap()).parse()?,
        );
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    // Parse URL to get base URL and endpoints
    let base_url = config.url.trim_end_matches("/sse");
    let sse_url = format!("{}/sse", base_url);
    let message_url = format!("{}/message", base_url);

    info!("Connecting to SSE endpoint: {}", sse_url);
    info!("Message endpoint: {}", message_url);

    // Create SSE stream
    let response = client
        .get(&sse_url)
        .header("Accept", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("SSE connection failed with status: {}", response.status()).into());
    }

    let event_stream = response.bytes_stream().eventsource();

    // Convert SSE events to bytes stream for JSON-RPC
    let sse_stream = event_stream.map(|event_result| {
        match event_result {
            Ok(event) => {
                // Convert SSE event data to JSON-RPC line
                let mut data = event.data.into_bytes();
                data.push(b'\n');
                Ok(Bytes::from(data))
            }
            Err(e) => {
                error!("SSE error: {}", e);
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    });

    // Create reader from SSE stream
    let reader = StreamReader::new(sse_stream);

    // Create writer for outgoing messages
    let writer = SseWriter {
        client: client.clone(),
        message_url,
    };

    // Create transport using AsyncRwTransport
    let transport = AsyncRwTransport::new(reader, writer);

    let client_info = ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::builder().enable_sampling().build(),
        ..Default::default()
    };

    // Create client service
    let client = client_info.serve(transport).await?;

    // Get server info
    let server_info = client.peer_info();
    info!(
        "Connected to server: {}",
        server_info.unwrap().server_info.name
    );

    // Create proxy handler
    let proxy_handler = ProxyHandler::new(client);

    // Create stdio transport and serve
    let stdio_transport = stdio();
    let server = proxy_handler.serve(stdio_transport).await?;

    // Wait for completion
    server.waiting().await?;

    Ok(())
}

