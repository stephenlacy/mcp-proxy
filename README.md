# mcp-proxy
> A Rust bidirectional MCP proxy between stdio and SSE. Based initially on [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy)

## Features
- Connect to a remote server over SSE and expose it as a stdio server
- Connect to a local server using stdio and expose it as an SSE server
- Fast startup with minimal memory usage

## Usage

### Installing

```bash
# from crates.io
cargo install rmcp-proxy

cargo install --git https://github.com/stephenlacy/mcp-proxy
```

### Building

```bash
cargo build --release
```

### Running

The proxy can operate in two modes:

#### 1. SSE Client Mode

Connect to a remote MCP server over SSE and expose it as a stdio server.

This allows a local client such as Claude or Cursor connect to a remote server running on SSE.

##### Example

```bash
mcp-proxy http://localhost:8080/sse
mcp-proxy --headers Authorization 'Bearer YOUR_TOKEN' http://localhost:8080/sse
```

##### Using with Claude or Cursor

```json
{
  "mcpServers": {
    "mcp-proxy": {
      "command": "mcp-proxy",
      "args": ["http://example.com/sse"]
    }
  }
}
```

#### 2. Stdio Client Mode

Connect to a local command using stdio and expose it as an SSE server.

This allows remote SSE connections to a local stdio server.

```bash
mcp-proxy --sse-port 8080 -- your-command --arg1 value1 --arg2 value2
mcp-proxy --sse-port 8080 -e KEY VALUE -e ANOTHER_KEY ANOTHER_VALUE -- your-command --arg1 value1 --arg2 value2
mcp-proxy --sse-port 8080 python mcp_server.py
mcp-proxy --sse-port 8080 -- npx -y @modelcontextprotocol/server-everything
```


#### Using as a library

```rust
use rmcp::{
    ServiceExt,
    model::{ClientCapabilities, ClientInfo},
    transport::{sse::SseTransport, stdio},
};

use rmcp_proxy::proxy_handler::ProxyHandler;

// Create SSE transport
let transport = SseTransport::start(&config.url).await?;

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

```


## License

MIT
