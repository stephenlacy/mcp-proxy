use axum::{routing::get, Router};
use rmcp::{
    model::{ClientCapabilities, ClientInfo},
    transport::{
        child_process::TokioChildProcess,
        streamable_http_server::{
            session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
        },
    },
    ServiceExt,
};
use std::{
    collections::HashMap, error::Error as StdError, net::SocketAddr, sync::Arc, time::Duration,
};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::proxy_handler::ProxyHandler;

/// Parameters for stdio server connection
#[derive(Debug, Clone)]
pub struct StdioServerParameters {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
}

/// Settings for Streamable HTTP server
#[derive(Debug, Clone)]
pub struct StreamableHttpServerSettings {
    pub bind_addr: SocketAddr,
    pub keep_alive: Option<Duration>,
}

/// This function starts a server that accepts Streamable HTTP connections and proxies them to a stdio-based MCP server process.
pub async fn run_streamable_http_server(
    stdio_params: StdioServerParameters,
    settings: StreamableHttpServerSettings,
) -> Result<(), Box<dyn StdError>> {
    info!(
        "Starting Streamable HTTP server on {} proxying to command: {} {:?}",
        settings.bind_addr, stdio_params.command, stdio_params.args
    );

    let session_manager = Arc::new(LocalSessionManager::default());
    let shutdown_token = CancellationToken::new();

    let service_factory = {
        let shutdown_token = shutdown_token.clone();
        move || {
            let stdio_params = stdio_params.clone();
            let result: Result<ProxyHandler, std::io::Error> = (|| {
                // Create child process command
                let mut command = Command::new(&stdio_params.command);
                command.args(&stdio_params.args);

                for (key, value) in &stdio_params.env {
                    command.env(key, value);
                }

                // Create child process
                let tokio_process = TokioChildProcess::new(command)?;

                let client_info = ClientInfo {
                    protocol_version: Default::default(),
                    capabilities: ClientCapabilities::builder().enable_sampling().build(),
                    ..Default::default()
                };

                // Create client connection to the stdio process
                let client = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let client = client_info
                            .serve(tokio_process)
                            .await
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                        // Set up shutdown handling for this client
                        let shutdown_token = shutdown_token.clone();
                        tokio::spawn(async move {
                            shutdown_token.cancelled().await;
                            // Client will be dropped and cleaned up automatically
                        });

                        Ok::<_, std::io::Error>(client)
                    })
                })?;

                Ok(ProxyHandler::new(client))
            })();

            result
        }
    };

    let server_config = StreamableHttpServerConfig {
        sse_keep_alive: settings.keep_alive,
        stateful_mode: true,
    };

    let streamable_service =
        StreamableHttpService::new(service_factory, session_manager, server_config);

    let app = Router::new()
        .route(
            "/health",
            get(|| async { "MCP Streamable HTTP Proxy Server" }),
        )
        .fallback_service(streamable_service);

    let listener = tokio::net::TcpListener::bind(&settings.bind_addr).await?;
    let actual_addr = listener.local_addr()?;

    info!("Streamable HTTP server listening on http://{}", actual_addr);

    let serve_future =
        axum::serve(listener, app).with_graceful_shutdown(shutdown_signal(shutdown_token.clone()));

    tokio::select! {
        result = serve_future => {
            if let Err(e) = result {
                warn!("Server error: {}", e);
            }
        }
        _ = shutdown_token.cancelled() => {
            info!("Shutdown token cancelled");
        }
    }

    info!("Starting graceful shutdown...");

    shutdown_token.cancel();

    tokio::time::sleep(Duration::from_millis(100)).await;

    info!("Shutdown complete");
    Ok(())
}

async fn shutdown_signal(shutdown_token: CancellationToken) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating shutdown...");
        },
        _ = terminate => {
            info!("Received terminate signal, initiating shutdown...");
        },
    }

    // Signal shutdown to all components
    shutdown_token.cancel();
}
