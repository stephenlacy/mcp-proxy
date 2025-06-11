use crate::proxy_handler::ProxyHandler;
/**
 * Create a local SSE server that proxies requests to a stdio MCP server.
 */
use rmcp::{
    model::{ClientCapabilities, ClientInfo},
    transport::{
        child_process::TokioChildProcess,
        sse_server::{SseServer, SseServerConfig},
    },
    ServiceExt,
};
use std::{collections::HashMap, error::Error as StdError, net::SocketAddr, time::Duration};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Settings for the SSE server
pub struct SseServerSettings {
    pub bind_addr: SocketAddr,
    pub keep_alive: Option<Duration>,
}

/// StdioServerParameters holds parameters for the stdio client.
pub struct StdioServerParameters {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
}

/// Run the SSE server with a stdio client
///
/// This function connects to a stdio server and exposes it as an SSE server.
pub async fn run_sse_server(
    stdio_params: StdioServerParameters,
    sse_settings: SseServerSettings,
) -> Result<(), Box<dyn StdError>> {
    info!(
        "Running SSE server on {:?} with command: {}",
        sse_settings.bind_addr, stdio_params.command,
    );

    // Configure SSE server
    let config = SseServerConfig {
        bind: sse_settings.bind_addr,
        sse_path: "/sse".to_string(),
        post_path: "/message".to_string(),
        ct: CancellationToken::new(),
        sse_keep_alive: sse_settings.keep_alive,
    };

    let mut command = Command::new(&stdio_params.command);
    command.args(&stdio_params.args);

    for (key, value) in &stdio_params.env {
        command.env(key, value);
    }

    // Create child process
    let tokio_process = TokioChildProcess::new(&mut command)?;

    let client_info = ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::builder()
            // Use minimal capabilities to avoid validation errors
            .enable_sampling()
            .build(),
        ..Default::default()
    };

    // Create client service
    let client = client_info.serve(tokio_process).await?;

    // Get server info
    let server_info = client.peer_info();
    info!("Connected to server: {}", server_info.server_info.name);

    // Create proxy handler
    let proxy_handler = ProxyHandler::new(client);

    // Start the SSE server
    let sse_server = SseServer::serve_with_config(config.clone()).await?;

    // Register the proxy handler with the SSE server
    let ct = sse_server.with_service(move || proxy_handler.clone());

    // Wait for Ctrl+C to shut down
    tokio::signal::ctrl_c().await?;
    ct.cancel();

    Ok(())
}
