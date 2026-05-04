use std::collections::HashMap;
use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;

use overslash_core::openapi::import::{ImportOptions, ImportWarning};

use super::platform_caller::{BoxFuture, PlatformCallContext, PlatformHandler, PlatformRegistry};
use super::platform_templates::{
    DraftDetail, kernel_create_template, kernel_delete_template, kernel_get_template,
    kernel_import_template, kernel_list_templates,
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

struct ImportTemplateHandler;

impl PlatformHandler for ImportTemplateHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let openapi = params
                .get("openapi")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "'openapi' param is required (raw OpenAPI YAML/JSON)".into(),
                    )
                })?
                .to_string();
            let user_level = params
                .get("user_level")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let include_operations: Option<HashSet<String>> = params
                .get("include_operations")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                });
            let key = params
                .get("key")
                .and_then(Value::as_str)
                .map(str::to_string);
            let display_name = params
                .get("display_name")
                .and_then(Value::as_str)
                .map(str::to_string);
            let draft_id = params
                .get("draft_id")
                .and_then(Value::as_str)
                .map(|s| {
                    Uuid::parse_str(s)
                        .map_err(|_| AppError::BadRequest(format!("invalid draft_id: {s:?}")))
                })
                .transpose()?;

            let opts = ImportOptions {
                include_operations,
                key,
                display_name,
            };

            let out: DraftDetail = kernel_import_template(
                ctx,
                openapi.into_bytes(),
                None, // no content-type hint over MCP — body-only
                opts,
                user_level,
                draft_id,
                Vec::<ImportWarning>::new(),
            )
            .await?;
            Ok(serde_json::to_value(out).unwrap_or(Value::Null))
        })
    }
}

struct DeleteTemplateHandler;

impl PlatformHandler for DeleteTemplateHandler {
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
            kernel_delete_template(ctx, key).await
        })
    }
}

pub fn build_registry() -> PlatformRegistry {
    let mut m: PlatformRegistry = HashMap::new();
    m.insert("ping".into(), Box::new(PingHandler));
    m.insert("list_templates".into(), Box::new(ListTemplatesHandler));
    m.insert("get_template".into(), Box::new(GetTemplateHandler));
    m.insert("create_template".into(), Box::new(CreateTemplateHandler));
    m.insert("import_template".into(), Box::new(ImportTemplateHandler));
    m.insert("delete_template".into(), Box::new(DeleteTemplateHandler));
    m
}
