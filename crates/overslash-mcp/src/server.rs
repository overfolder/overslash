use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::{ClientError, Cred, OverslashClient};
use crate::config::McpConfig;

#[derive(Clone)]
pub struct OverslashMcp {
    client: OverslashClient,
    // Populated by `#[tool_router]` and consumed by `#[tool_handler]`; the
    // field is read through generated code, not directly.
    #[allow(dead_code)]
    tool_router: ToolRouter<OverslashMcp>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchArgs {
    /// Free-text query. Matches against service names, action names,
    /// descriptions, and template keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExecuteArgs {
    /// Service instance name or template key.
    pub service: String,
    /// Action key (e.g. `create_pull_request`) or HTTP verb for raw mode.
    pub action: String,
    /// Action parameters / request body.
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct AuthArgs {
    /// Sub-action (`create_service_from_template`, `status`, `list_secrets`,
    /// `request_secret`, `rotate_secret`, `create_subagent`, `whoami`, ...).
    /// See SPEC §10.
    pub action: String,
    /// Sub-action parameters.
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ApproveArgs {
    /// Approval ID returned by a prior `pending_approval` execute result.
    pub approval_id: String,
    /// One of `allow_once`, `allow_remember`, `bubble`, `reject`.
    pub resolution: String,
    /// Permission keys to remember (only used with `allow_remember`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember_keys: Option<Vec<String>>,
    /// Optional TTL in seconds for the remembered rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[tool_router]
impl OverslashMcp {
    pub fn new(cfg: McpConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: OverslashClient::new(&cfg)?,
            tool_router: Self::tool_router(),
        })
    }

    #[tool(
        description = "Discover Overslash services and actions available to the agent. Returns connected service instances and instantiable templates."
    )]
    async fn overslash_search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = match args.query {
            Some(q) if !q.is_empty() => {
                format!("/v1/services?query={}", urlencode(&q))
            }
            _ => "/v1/services".to_string(),
        };
        let v = self
            .client
            .get(Cred::Agent, &path)
            .await
            .map_err(into_mcp)?;
        Ok(json_result(v))
    }

    #[tool(
        description = "Execute an Overslash action. Returns the action result, or `pending_approval` with an approval_id if the user must approve. In that case call `overslash_approve` then re-call this tool."
    )]
    async fn overslash_execute(
        &self,
        Parameters(args): Parameters<ExecuteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let body = json!({
            "service": args.service,
            "action": args.action,
            "params": args.params,
        });
        let v = self
            .client
            .post(Cred::Agent, "/v1/actions/execute", &body)
            .await
            .map_err(into_mcp)?;
        Ok(json_result(v))
    }

    #[tool(
        description = "Auth and identity sub-actions: whoami, list_secrets, request_secret, create_subagent, create_service_from_template, service_status. See Overslash SPEC §10."
    )]
    async fn overslash_auth(
        &self,
        Parameters(args): Parameters<AuthArgs>,
    ) -> Result<CallToolResult, McpError> {
        let route = auth_route(&args)?;
        let v = match route.method {
            HttpMethod::Get => self.client.get(route.cred, &route.path).await,
            HttpMethod::Post => {
                self.client
                    .post(route.cred, &route.path, &args.params)
                    .await
            }
        };
        Ok(json_result(v.map_err(into_mcp)?))
    }

    #[tool(
        description = "Resolve a pending approval inline using the user's credential. Use after `overslash_execute` returns `pending_approval`."
    )]
    async fn overslash_approve(
        &self,
        Parameters(args): Parameters<ApproveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let body = json!({
            "resolution": args.resolution,
            "remember_keys": args.remember_keys,
            "ttl": args.ttl,
        });
        let path = format!("/v1/approvals/{}/resolve", urlencode(&args.approval_id));
        let v = self
            .client
            .post(Cred::User, &path, &body)
            .await
            .map_err(into_mcp)?;
        Ok(json_result(v))
    }
}

#[tool_handler]
impl ServerHandler for OverslashMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Overslash MCP server. Use `overslash_search` to discover services, \
             `overslash_execute` to run actions, `overslash_auth` for credential / \
             identity ops, and `overslash_approve` to resolve approvals inline."
                    .to_string(),
            )
    }
}

fn json_result(v: Value) -> CallToolResult {
    let text = serde_json::to_string(&v).unwrap_or_else(|_| "null".into());
    CallToolResult::success(vec![Content::text(text)])
}

fn into_mcp(e: ClientError) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthRoute {
    pub method: HttpMethod,
    pub path: String,
    pub cred: Cred,
}

/// Pure routing decision for `overslash_auth`. Kept separate so the dispatch
/// table is unit-testable without an HTTP server.
pub fn auth_route(args: &AuthArgs) -> Result<AuthRoute, McpError> {
    let (method, path, cred) = match args.action.as_str() {
        "whoami" => (HttpMethod::Get, "/auth/me".to_string(), Cred::Agent),
        "list_secrets" => (HttpMethod::Get, "/v1/secrets".to_string(), Cred::Agent),
        "request_secret" => (
            HttpMethod::Post,
            "/v1/secrets/requests".to_string(),
            Cred::Agent,
        ),
        "create_subagent" => (HttpMethod::Post, "/v1/identities".to_string(), Cred::Agent),
        "create_service_from_template" => {
            (HttpMethod::Post, "/v1/services".to_string(), Cred::Agent)
        }
        "service_status" => {
            let name = args
                .params
                .get("service")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    McpError::invalid_params("service_status requires `service`", None)
                })?;
            (
                HttpMethod::Get,
                format!("/v1/services/{}/status", urlencode(name)),
                Cred::Agent,
            )
        }
        other => {
            return Err(McpError::invalid_params(
                format!(
                    "unknown action `{other}` — supported: whoami, list_secrets, \
                     request_secret, create_subagent, create_service_from_template, \
                     service_status"
                ),
                None,
            ));
        }
    };
    Ok(AuthRoute { method, path, cred })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(action: &str, params: Value) -> AuthArgs {
        AuthArgs {
            action: action.into(),
            params,
        }
    }

    #[test]
    fn whoami_uses_auth_me() {
        let r = auth_route(&args("whoami", json!({}))).unwrap();
        assert_eq!(r.method, HttpMethod::Get);
        assert_eq!(r.path, "/auth/me");
    }

    #[test]
    fn list_secrets_is_get() {
        let r = auth_route(&args("list_secrets", json!({}))).unwrap();
        assert_eq!(r.method, HttpMethod::Get);
        assert_eq!(r.path, "/v1/secrets");
    }

    #[test]
    fn request_secret_is_post_to_requests() {
        let r = auth_route(&args("request_secret", json!({"name": "gh"}))).unwrap();
        assert_eq!(r.method, HttpMethod::Post);
        assert_eq!(r.path, "/v1/secrets/requests");
    }

    #[test]
    fn create_subagent_is_post_to_identities() {
        let r = auth_route(&args("create_subagent", json!({"name": "x"}))).unwrap();
        assert_eq!(r.method, HttpMethod::Post);
        assert_eq!(r.path, "/v1/identities");
    }

    #[test]
    fn create_service_from_template_is_post_to_services() {
        let r = auth_route(&args(
            "create_service_from_template",
            json!({"template": "github"}),
        ))
        .unwrap();
        assert_eq!(r.method, HttpMethod::Post);
        assert_eq!(r.path, "/v1/services");
    }

    #[test]
    fn service_status_interpolates_name() {
        let r = auth_route(&args("service_status", json!({"service": "github"}))).unwrap();
        assert_eq!(r.method, HttpMethod::Get);
        assert_eq!(r.path, "/v1/services/github/status");
    }

    #[test]
    fn service_status_url_encodes_dangerous_chars() {
        let r = auth_route(&args("service_status", json!({"service": "../admin"}))).unwrap();
        assert_eq!(r.path, "/v1/services/..%2Fadmin/status");
    }

    #[test]
    fn service_status_without_name_fails() {
        let err = auth_route(&args("service_status", json!({}))).unwrap_err();
        assert!(err.to_string().contains("service_status"));
    }

    #[test]
    fn unknown_action_lists_supported() {
        let err = auth_route(&args("flarp", json!({}))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("flarp"));
        assert!(msg.contains("whoami"));
    }
}
