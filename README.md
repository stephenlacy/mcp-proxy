# mcp-proxy
> A Rust bidirectional MCP proxy supporting SSE and Streamable HTTP transports with OAuth.

## Features
- **Multiple transports**: SSE and Streamable HTTP
- **OAuth authentication**: Full OAuth flow with automatic token refresh
- **Bidirectional proxy**: Connect remote servers to local clients or expose local servers remotely
- **Fast and lightweight**: Built in rust for performance

## Usage

### Installing

```bash
# from crates.io
cargo install rmcp-proxy
# from github
cargo install --git https://github.com/stephenlacy/mcp-proxy
```

### Building

```bash
cargo build --release
```

### Running

The proxy can operate in two modes:

#### 1. Remote Client Mode

Connect to a remote MCP server and expose it as a local stdio server. Supports both SSE and Streamable HTTP transports with automatic detection.

**Transport Detection**:
- URLs containing `/sse` → Uses SSE transport
- All other URLs → Uses Streamable HTTP transport
- Override with `--transport` flag

##### Basic Examples

```bash
# Streamable HTTP
mcp-proxy http://localhost:9090/mcp/instances_abc123

# SSE transport
mcp-proxy http://localhost:8080/sse
mcp-proxy --transport sse http://localhost:8080/events

# Specific
mcp-proxy --transport streamable-http http://localhost:9090/api
```

##### Using with Claude or Cursor

```json
{
  "mcpServers": {
    "my-remote-server": {
      "command": "mcp-proxy",
      "args": ["http://example.com/mcp/instances_abc123"]
    },
    "sse-server": {
      "command": "mcp-proxy", 
      "args": ["--transport", "sse", "http://example.com/sse"]
    }
  }
}
```

#### 2. Local Server Mode

Connect to a local MCP server via stdio and expose it as a remote server. Supports both SSE and Streamable HTTP endpoints.

```bash
# Expose as SSE server
mcp-proxy --port 8080 -- your-command --arg1 value1 --arg2 value2
mcp-proxy --port 8080 python mcp_server.py
mcp-proxy --port 8080 -- npx -y @modelcontextprotocol/server-everything

# Or http+streamable
mcp-proxy --port 9090 --transport streamable-http -- python mcp_server.py

mcp-proxy --port 8080 -e KEY VALUE -e ANOTHER_KEY ANOTHER_VALUE -- your-command
```

### Authentication Management

#### Clearing Auth Cache

If you encounter authentication issues, clear the auth cache:

```bash
# Clear all auth data
mcp-proxy reset

# Or manually delete the directory
rm -rf ~/.mcp-auth
```

### Command Line Options

```bash
# Transport selection
--transport <TRANSPORT>    # sse, streamable-http, or auto (default: auto)

# Server mode options
--port <PORT>             # Port for local server mode (default: random)
--host <HOST>             # Host to bind to (default: 127.0.0.1)

# Environment variables (server mode)
-e, --env <KEY> <VALUE>   # Set environment variable
--pass-environment        # Pass through all environment variables

# Headers (client mode) 
-H, --headers <KEY> <VALUE>  # Add custom headers

# Reset auth
mcp-proxy reset           # Clear all stored auth data
```

### Logging
> The upstream rmcp crate dumps noisy logs unfortunately

Control log verbosity with the `RUST_LOG` environment variable:

```bash
# Minimal logging
RUST_LOG=error mcp-proxy http://example.com/mcp
RUST_LOG=debug mcp-proxy http://example.com/mcp
RUST_LOG=info mcp-proxy http://example.com/mcp
```

### Library Usage

```rust
use rmcp_proxy::{
    sse_client::run_sse_client,
    streamable_http_client::run_streamable_http_client,
    StreamableHttpClientConfig, SseClientConfig
};

// Streamable HTTP client
let config = StreamableHttpClientConfig {
    url: "http://example.com/mcp/instances_abc123".to_string(),
    headers: HashMap::new(),
};
run_streamable_http_client(config).await?;

// SSE client  
let config = SseClientConfig {
    url: "http://example.com/sse".to_string(),
    headers: HashMap::new(),
};
run_sse_client(config).await?;
```


## License

MIT
