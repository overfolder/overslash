//! Dynamic Client Registration (RFC 7591) — `POST /oauth/register`.

use super::*;

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct RegisterRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    token_endpoint_auth_method: Option<String>,
    // All other RFC 7591 fields are accepted but ignored for v1.
    #[serde(flatten)]
    _extra: std::collections::HashMap<String, Value>,
}

pub(super) async fn register(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ctx: Option<Extension<RequestOrgContext>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Lock the client to the subdomain org it registered on: a corp-subdomain
    // registration stamps that org (so the client can't be replayed on another
    // org's subdomain, and shows up in that org's admin MCP-Clients list); a
    // root registration stays NULL = multi-org. Missing extension (older test
    // harnesses) is treated as Root. See mcp-enrollment-org-scoping.md.
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    let client_org_id = match &ctx {
        RequestOrgContext::Org { org_id, .. } => Some(*org_id),
        RequestOrgContext::Root => None,
    };
    if req.redirect_uris.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        );
    }
    for uri in &req.redirect_uris {
        if uri.contains(char::is_whitespace) || uri.is_empty() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri must be a non-empty URL with no whitespace",
            );
        }
    }
    if let Some(method) = req.token_endpoint_auth_method.as_deref()
        && method != "none"
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "only public clients are supported (token_endpoint_auth_method=none)",
        );
    }

    let client_id = oauth_as::generate_client_id();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());
    // Behind a reverse proxy, use X-Forwarded-For; direct calls don't
    // expose the socket addr here (we intentionally keep ConnectInfo out
    // of the handler signature so the route works in tests that don't
    // attach ConnectInfo).
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let row = match oauth_mcp_client::create(
        state.db(&ext),
        &oauth_mcp_client::CreateOauthMcpClient {
            client_id: &client_id,
            client_name: req.client_name.as_deref(),
            redirect_uris: &req.redirect_uris,
            software_id: req.software_id.as_deref(),
            software_version: req.software_version.as_deref(),
            created_ip: ip.as_deref(),
            created_user_agent: ua.as_deref(),
            org_id: client_org_id,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("DCR insert failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to register client",
            );
        }
    };

    // RFC 7591 metadata fields are optional. Claude Code's DCR client (Zod
    // schema) rejects explicit `null`s — omit unset fields entirely rather
    // than serialising Option<String>::None into `null`.
    let mut body = serde_json::Map::new();
    body.insert("client_id".into(), json!(row.client_id));
    body.insert("redirect_uris".into(), json!(row.redirect_uris));
    body.insert("token_endpoint_auth_method".into(), json!("none"));
    body.insert(
        "grant_types".into(),
        json!(["authorization_code", "refresh_token"]),
    );
    body.insert("response_types".into(), json!(["code"]));
    if let Some(v) = row.client_name.as_deref() {
        body.insert("client_name".into(), json!(v));
    }
    if let Some(v) = row.software_id.as_deref() {
        body.insert("software_id".into(), json!(v));
    }
    if let Some(v) = row.software_version.as_deref() {
        body.insert("software_version".into(), json!(v));
    }

    (StatusCode::CREATED, Json(Value::Object(body))).into_response()
}
