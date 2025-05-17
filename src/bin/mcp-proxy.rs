/**
 * The entry point for the mcp-proxy application.
 * It sets up logging and runs the main function.
 */
use clap::{ArgAction, Parser};
use rmcp_proxy::{
    config::get_config_dir,
    run_sse_client, run_sse_server,
    sse_client::SseClientConfig,
    sse_server::{SseServerSettings, StdioServerParameters},
};
use std::{collections::HashMap, env, error::Error, net::SocketAddr, process, time::Duration};
use tracing::{debug, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// MCP Proxy CLI arguments
#[derive(Parser)]
#[command(
    name = "mcp-proxy",
    about = "Start the MCP proxy in one of two possible modes: as an SSE or stdio client.",
    long_about = None,
    after_help = "Examples:\n  \
        Connect to a remote SSE server:\n  \
        mcp-proxy http://localhost:8080/sse\n\n  \
        Expose a local stdio server as an SSE server:\n  \
        mcp-proxy your-command --sse-port 8080 -e KEY VALUE -e ANOTHER_KEY ANOTHER_VALUE\n  \
        mcp-proxy --sse-port 8080 -- your-command --arg1 value1 --arg2 value2\n  \
        mcp-proxy --sse-port 8080 -- python mcp_server.py\n  \
        mcp-proxy --sse-port 8080 --sse-host 0.0.0.0 -- npx -y @modelcontextprotocol/server-everything
",
)]
struct Cli {
    /// Command or URL to connect to. When a URL, will run an SSE client,
    /// otherwise will run the given command and connect as a stdio client.
    #[arg(env = "SSE_URL")]
    command_or_url: Option<String>,

    /// Headers to pass to the SSE server. Can be used multiple times.
    #[arg(short = 'H', long = "headers", value_names = ["KEY", "VALUE"], number_of_values = 2)]
    headers: Vec<String>,

    /// Any extra arguments to the command to spawn the server
    #[arg(last = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Environment variables used when spawning the server. Can be used multiple times.
    #[arg(short = 'e', long = "env", value_names = ["KEY", "VALUE"], number_of_values = 2)]
    env_vars: Vec<String>,

    /// Pass through all environment variables when spawning the server.
    #[arg(long = "pass-environment", action = ArgAction::SetTrue)]
    pass_environment: bool,

    /// Port to expose an SSE server on. Default is a random port
    #[arg(long = "sse-port", default_value = "0")]
    sse_port: u16,

    /// Host to expose an SSE server on. Default is 127.0.0.1
    #[arg(long = "sse-host", default_value = "127.0.0.1")]
    sse_host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut cli = Cli::parse();

    // Check if we have a command or URL, or use the first of the pased args
    let command_or_url = match cli.command_or_url {
        Some(value) => value,
        None => match cli.args.len() {
            0 => {
                eprintln!("Error: command or URL is required");
                std::process::exit(1);
            }
            _ => cli.args.remove(0),
        },
    };

    // Check if it's a URL (SSE client mode) or a command (stdio client mode)
    if command_or_url.starts_with("http://") || command_or_url.starts_with("https://") {
        // Start a client connected to the SSE server, and expose as a stdio server
        debug!("Starting SSE client and stdio server");

        // Convert headers from Vec<String> to HashMap<String, String>
        let mut headers = HashMap::new();
        for i in (0..cli.headers.len()).step_by(2) {
            if i + 1 < cli.headers.len() {
                headers.insert(cli.headers[i].clone(), cli.headers[i + 1].clone());
            }
        }

        // Create SSE client config
        let config = SseClientConfig {
            url: command_or_url,
            headers,
        };

        // Run SSE client
        run_sse_client(config).await?;
    } else if command_or_url == "reset" {
        let config_dir = get_config_dir();

        println!("Deleting auth config at {:?}", config_dir);
        if let Err(e) = std::fs::remove_dir_all(&config_dir) {
            if e.kind() == std::io::ErrorKind::NotFound {
                println!("Auth config not found at {:?}", config_dir);
                return Ok(());
            }
            // Handle the error without using ?
            error!("Failed to delete auth config: {}", e);
            process::exit(1);
        }
        debug!("Auth config deleted");
    } else {
        // Start a client connected to the given command, and expose as an SSE server
        debug!("Starting stdio client and SSE server");

        // The environment variables passed to the server process
        let mut env_map = HashMap::new();

        // Pass through current environment variables if configured
        if cli.pass_environment {
            for (key, value) in env::vars() {
                env_map.insert(key, value);
            }
        }

        // Pass in and override any environment variables with those passed on the command line
        for i in (0..cli.env_vars.len()).step_by(2) {
            if i + 1 < cli.env_vars.len() {
                env_map.insert(cli.env_vars[i].clone(), cli.env_vars[i + 1].clone());
            }
        }

        // Create stdio parameters
        let stdio_params = StdioServerParameters {
            command: command_or_url,
            args: cli.args,
            env: env_map,
        };

        // Create SSE server settings
        let sse_settings = SseServerSettings {
            bind_addr: format!("{}:{}", cli.sse_host, cli.sse_port).parse::<SocketAddr>()?,
            keep_alive: Some(Duration::from_secs(15)),
        };

        // Run SSE server
        run_sse_server(stdio_params, sse_settings).await?;
    }

    Ok(())
}
