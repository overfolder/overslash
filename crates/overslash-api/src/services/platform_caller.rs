use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::registry::ServiceRegistry;
use overslash_db::scopes::OrgScope;

use crate::AppState;
use crate::config::Config;
use crate::error::AppError;

pub struct PlatformCallContext {
    pub org_id: Uuid,
    /// `None` when the caller is using an org-level API key (no identity
    /// binding). Kernels that need an identity (user-tier writes) must
    /// reject with `BadRequest` rather than fall back to a synthetic id —
    /// otherwise nil-uuid ends up on FK columns and surfaces as 500.
    pub identity_id: Option<Uuid>,
    pub access_level: AccessLevel,
    pub db: PgPool,
    pub registry: Arc<ServiceRegistry>,
    /// App config — OAuth-bearing kernels (`platform_connections`) read
    /// `public_url` and encryption keys here; URL-minting kernels read
    /// signing keys and `oversla.sh` settings. Cheap `Clone` per dispatch.
    pub config: Config,
    /// Shared HTTP client for outbound calls (e.g. the URL shortener,
    /// upstream OAuth providers).
    pub http_client: reqwest::Client,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait PlatformHandler: Send + Sync {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>>;
}

pub type PlatformRegistry = HashMap<String, Box<dyn PlatformHandler + Send + Sync>>;

/// Look up and dispatch a platform-runtime handler. Shared by the direct
/// `/v1/actions/call` dispatch path and the approval-replay path at
/// `POST /v1/approvals/{id}/call`. Returns the raw `Value` the handler
/// produced — caller wraps it into the appropriate response envelope
/// (`CallResponse::Called` inline, or an `ActionResult` for an execution row).
///
/// `ceiling_user_id` is recomputed by the caller from the requester's
/// identity (typically `group_ceiling::resolve_ceiling_user_id`). At replay
/// time this means the access level reflects current state — if the requester
/// has been demoted since the approval was created, the new ceiling applies.
#[allow(clippy::too_many_arguments)]
pub async fn invoke(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    identity_id: Uuid,
    ceiling_user_id: Uuid,
    action_key: &str,
    params: HashMap<String, Value>,
) -> Result<Value, AppError> {
    let handler = state.platform_registry.get(action_key).ok_or_else(|| {
        AppError::Internal(format!("platform handler '{action_key}' not registered"))
    })?;

    let access_level = {
        let ceiling = scope.get_ceiling_for_user(ceiling_user_id).await?;
        ceiling
            .grants
            .iter()
            .filter(|g| g.template_key == "overslash")
            .filter_map(|g| AccessLevel::parse(&g.access_level))
            .max()
            .unwrap_or(AccessLevel::Read)
    };

    let ctx = PlatformCallContext {
        org_id: scope.org_id(),
        identity_id: Some(identity_id),
        access_level,
        db: state.db_pool(ext),
        registry: Arc::clone(&state.registry),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };

    handler.call(ctx, params).await
}
