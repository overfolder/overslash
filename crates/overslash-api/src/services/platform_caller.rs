use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_core::registry::ServiceRegistry;

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
