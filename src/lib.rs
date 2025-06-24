mod auth;
pub mod config;
mod coordination;
/**
 * MCP Proxy Library
 *
 * A Rust implementation of the MCP proxy that provides:
 * 1. SSE client that connects to a remote SSE server and exposes it as a stdio server
 * 2. Stdio client that connects to a local stdio server and exposes it as an SSE server
 * 3. Streamable HTTP client that connects to a remote Streamable HTTP server and exposes it as a stdio server
 * 4. Stdio client that connects to a local stdio server and exposes it as a Streamable HTTP server
 */
pub mod proxy_handler;
pub mod sse_client;
pub mod sse_server;
pub mod streamable_http_client;
pub mod streamable_http_server;
mod utils;

// Export main functions
pub use self::sse_client::run_sse_client;
pub use self::sse_server::run_sse_server;
pub use self::streamable_http_client::run_streamable_http_client;
pub use self::streamable_http_server::run_streamable_http_server;
