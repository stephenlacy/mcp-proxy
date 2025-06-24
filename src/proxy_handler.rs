/**
 * Create a local SSE server that proxies requests to a stdio MCP server.
 */
use rmcp::{
    model::{
        CallToolRequestParam, CallToolResult, ClientInfo, Content, Implementation, ListToolsResult,
        PaginatedRequestParam, ServerInfo,
    },
    service::{NotificationContext, RequestContext, RunningService},
    Error, RoleClient, RoleServer, ServerHandler,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

/// A proxy handler that forwards requests to a client based on the server's capabilities
#[derive(Clone)]
pub struct ProxyHandler {
    client: Arc<Mutex<RunningService<RoleClient, ClientInfo>>>,
    // Store the server's capabilities to avoid locking the client on every get_info call
    cached_info: Arc<ServerInfo>,
}

impl ServerHandler for ProxyHandler {
    fn get_info(&self) -> ServerInfo {
        // Return the cached server info with capabilities
        self.cached_info.as_ref().clone()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, Error> {
        let client = self.client.clone();
        let guard = client.lock().await;

        match guard.list_tools(request).await {
            Ok(result) => {
                debug!(
                    "Proxying list_tools response with {} tools",
                    result.tools.len()
                );
                Ok(result)
            }
            Err(err) => {
                tracing::error!("Error listing tools: {:?}", err);
                // Return empty list instead of error
                Ok(ListToolsResult::default())
            }
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, Error> {
        let client = self.client.clone();
        let guard = client.lock().await;

        match guard.call_tool(request.clone()).await {
            Ok(result) => {
                debug!("Tool call succeeded");
                Ok(result)
            }
            Err(err) => {
                tracing::error!("Error calling tool: {:?}", err);
                // Return an error result instead of propagating the error
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: {}",
                    err
                ))]))
            }
        }
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Check if the server has resources capability and forward the request
        match self.cached_info.capabilities.resources {
            Some(_) => {
                // Forward request to client
                match guard.list_resources(request).await {
                    Ok(result) => {
                        debug!("Proxying list_resources response");
                        Ok(result)
                    }
                    Err(err) => {
                        tracing::error!("Error listing resources: {:?}", err);
                        // Return empty list instead of error
                        Ok(rmcp::model::ListResourcesResult::default())
                    }
                }
            }
            None => {
                // Server doesn't support resources, return empty list
                tracing::error!("Server doesn't support resources capability");
                Ok(rmcp::model::ListResourcesResult::default())
            }
        }
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Check if the server has resources capability and forward the request
        match self.cached_info.capabilities.resources {
            Some(_) => {
                // Forward request to client
                match guard
                    .read_resource(rmcp::model::ReadResourceRequestParam {
                        uri: request.uri.clone(),
                    })
                    .await
                {
                    Ok(result) => {
                        debug!("Proxying read_resource response for {}", request.uri);
                        Ok(result)
                    }
                    Err(err) => {
                        tracing::error!("Error reading resource: {:?}", err);
                        Err(Error::internal_error(
                            format!("Error reading resource: {}", err),
                            None,
                        ))
                    }
                }
            }
            None => {
                // Server doesn't support resources, return error
                tracing::error!("Server doesn't support resources capability");
                Err(Error::internal_error(
                    "Server doesn't support resources capability".to_string(),
                    None,
                ))
            }
        }
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Check if the server has resources capability and forward the request
        match self.cached_info.capabilities.resources {
            Some(_) => {
                // Forward request to client
                match guard.list_resource_templates(request).await {
                    Ok(result) => {
                        debug!("Proxying list_resource_templates response");
                        Ok(result)
                    }
                    Err(err) => {
                        tracing::error!("Error listing resource templates: {:?}", err);
                        // Return empty list instead of error
                        Ok(rmcp::model::ListResourceTemplatesResult::default())
                    }
                }
            }
            None => {
                // Server doesn't support resources, return empty list
                tracing::error!("Server doesn't support resources capability");
                Ok(rmcp::model::ListResourceTemplatesResult::default())
            }
        }
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Check if the server has prompts capability and forward the request
        match self.cached_info.capabilities.prompts {
            Some(_) => {
                // Forward request to client
                match guard.list_prompts(request).await {
                    Ok(result) => {
                        debug!("Proxying list_prompts response");
                        Ok(result)
                    }
                    Err(err) => {
                        tracing::error!("Error listing prompts: {:?}", err);
                        // Return empty list instead of error
                        Ok(rmcp::model::ListPromptsResult::default())
                    }
                }
            }
            None => {
                // Server doesn't support prompts, return empty list
                tracing::error!("Server doesn't support prompts capability");
                Ok(rmcp::model::ListPromptsResult::default())
            }
        }
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::GetPromptResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Check if the server has prompts capability and forward the request
        match self.cached_info.capabilities.prompts {
            Some(_) => {
                // Forward request to client
                match guard.get_prompt(request).await {
                    Ok(result) => {
                        debug!("Proxying get_prompt response");
                        Ok(result)
                    }
                    Err(err) => {
                        tracing::error!("Error getting prompt: {:?}", err);
                        Err(Error::internal_error(
                            format!("Error getting prompt: {}", err),
                            None,
                        ))
                    }
                }
            }
            None => {
                // Server doesn't support prompts, return error
                tracing::error!("Server doesn't support prompts capability");
                Err(Error::internal_error(
                    "Server doesn't support prompts capability".to_string(),
                    None,
                ))
            }
        }
    }

    async fn complete(
        &self,
        request: rmcp::model::CompleteRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CompleteResult, Error> {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;

        // Forward request to client
        match guard.complete(request).await {
            Ok(result) => {
                debug!("Proxying complete response");
                Ok(result)
            }
            Err(err) => {
                tracing::error!("Error completing: {:?}", err);
                Err(Error::internal_error(
                    format!("Error completing: {}", err),
                    None,
                ))
            }
        }
    }

    async fn on_progress(&self, notification: rmcp::model::ProgressNotificationParam, _context: NotificationContext<RoleServer>) {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;
        match guard.notify_progress(notification).await {
            Ok(_) => {
                debug!("Proxying progress notification");
            }
            Err(err) => {
                tracing::error!("Error notifying progress: {:?}", err);
            }
        }
    }

    async fn on_cancelled(&self, notification: rmcp::model::CancelledNotificationParam, _context: NotificationContext<RoleServer>) {
        // Get a lock on the client
        let client = self.client.clone();
        let guard = client.lock().await;
        match guard.notify_cancelled(notification).await {
            Ok(_) => {
                debug!("Proxying cancelled notification");
            }
            Err(err) => {
                tracing::error!("Error notifying cancelled: {:?}", err);
            }
        }
    }
}

impl ProxyHandler {
    pub fn new(client: RunningService<RoleClient, ClientInfo>) -> Self {
        let peer_info = client.peer_info();

        // Create a ServerInfo object that forwards the server's capabilities
        let peer_info_data = peer_info.unwrap();
        let cached_info = ServerInfo {
            protocol_version: peer_info_data.protocol_version.clone(),
            server_info: Implementation {
                name: peer_info_data.server_info.name.clone(),
                version: peer_info_data.server_info.version.clone(),
            },
            instructions: peer_info_data.instructions.clone(),
            capabilities: peer_info_data.capabilities.clone(),
        };

        Self {
            client: Arc::new(Mutex::new(client)),
            cached_info: Arc::new(cached_info),
        }
    }
}
