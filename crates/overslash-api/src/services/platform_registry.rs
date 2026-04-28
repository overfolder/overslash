use std::collections::HashMap;

use serde_json::Value;

use super::platform_caller::{BoxFuture, PlatformCallContext, PlatformHandler, PlatformRegistry};
use super::platform_templates::{
    kernel_create_template, kernel_get_template, kernel_list_templates,
};
use crate::error::AppError;

struct PingHandler;

impl PlatformHandler for PingHandler {
    fn call(
        &self,
        _ctx: PlatformCallContext,
        _params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async { Ok(serde_json::json!({"runtime": "platform", "ok": true})) })
    }
}

struct ListTemplatesHandler;

impl PlatformHandler for ListTemplatesHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        _params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(kernel_list_templates(ctx))
    }
}

struct GetTemplateHandler;

impl PlatformHandler for GetTemplateHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let key = params
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("'key' param is required".into()))?
                .to_string();
            kernel_get_template(ctx, key).await
        })
    }
}

struct CreateTemplateHandler;

impl PlatformHandler for CreateTemplateHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let openapi = params
                .get("openapi")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("'openapi' param is required".into()))?
                .to_string();
            let user_level = params
                .get("user_level")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            kernel_create_template(ctx, openapi, user_level).await
        })
    }
}

pub fn build_registry() -> PlatformRegistry {
    let mut m: PlatformRegistry = HashMap::new();
    m.insert("ping".into(), Box::new(PingHandler));
    m.insert("list_templates".into(), Box::new(ListTemplatesHandler));
    m.insert("get_template".into(), Box::new(GetTemplateHandler));
    m.insert("create_template".into(), Box::new(CreateTemplateHandler));
    m
}
