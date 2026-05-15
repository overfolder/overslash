use std::collections::HashMap;
use std::collections::HashSet;

use serde_json::Value;
use uuid::Uuid;

use overslash_core::openapi::import::{ImportOptions, ImportWarning};

use super::platform_caller::{BoxFuture, PlatformCallContext, PlatformHandler, PlatformRegistry};
use super::platform_connections::dispatch_create_connection;
use super::platform_secrets::{RequestSecretInput, kernel_request_secret};
use super::platform_services::{
    CreateServiceInput, GetServiceInput, UpdateServiceInput, kernel_create_service,
    kernel_get_service, kernel_list_services, kernel_update_service,
};
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

// ── Service kernels ──────────────────────────────────────────────────────

struct ListServicesHandler;

impl PlatformHandler for ListServicesHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        _params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let summaries = kernel_list_services(ctx, false).await?;
            Ok(serde_json::to_value(summaries).unwrap_or(Value::Null))
        })
    }
}

struct GetServiceHandler;

impl PlatformHandler for GetServiceHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let input = params_to_get_input(params)?;
            let detail = kernel_get_service(ctx, input).await?;
            Ok(serde_json::to_value(detail).unwrap_or(Value::Null))
        })
    }
}

struct CreateServiceHandler;

impl PlatformHandler for CreateServiceHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let input: CreateServiceInput = params_to_struct(params)?;
            if input.template_key.is_empty() {
                return Err(AppError::BadRequest("'template_key' is required".into()));
            }
            let detail = kernel_create_service(ctx, input).await?;
            Ok(serde_json::to_value(detail).unwrap_or(Value::Null))
        })
    }
}

struct CreateConnectionHandler;

impl PlatformHandler for CreateConnectionHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(dispatch_create_connection(ctx, params))
    }
}

struct UpdateServiceHandler;

impl PlatformHandler for UpdateServiceHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let id_str = params
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::BadRequest("'id' param is required".into()))?;
            let id = Uuid::parse_str(id_str)
                .map_err(|_| AppError::BadRequest(format!("invalid uuid '{id_str}'")))?;
            let mut params = params;
            params.remove("id");
            let input: UpdateServiceInput = params_to_struct(params)?;
            let detail = kernel_update_service(ctx, id, input).await?;
            Ok(serde_json::to_value(detail).unwrap_or(Value::Null))
        })
    }
}

// ── Secret-request kernel ────────────────────────────────────────────────

struct RequestSecretHandler;

impl PlatformHandler for RequestSecretHandler {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>> {
        Box::pin(async move {
            let input: RequestSecretInput = params_to_struct(params)?;
            kernel_request_secret(ctx, input).await
        })
    }
}

fn params_to_struct<T: serde::de::DeserializeOwned + Default>(
    params: HashMap<String, Value>,
) -> Result<T, AppError> {
    if params.is_empty() {
        return Ok(T::default());
    }
    let value = Value::Object(params.into_iter().collect());
    serde_json::from_value(value).map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))
}

fn params_to_get_input(params: HashMap<String, Value>) -> Result<GetServiceInput, AppError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::BadRequest("'name' param is required".into()))?
        .to_string();
    let include_inactive = params
        .get("include_inactive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(GetServiceInput {
        name,
        include_inactive,
    })
}

pub fn build_registry() -> PlatformRegistry {
    let mut m: PlatformRegistry = HashMap::new();
    m.insert("ping".into(), Box::new(PingHandler));
    m.insert("list_templates".into(), Box::new(ListTemplatesHandler));
    m.insert("get_template".into(), Box::new(GetTemplateHandler));
    m.insert("create_template".into(), Box::new(CreateTemplateHandler));
    m.insert("import_template".into(), Box::new(ImportTemplateHandler));
    m.insert("delete_template".into(), Box::new(DeleteTemplateHandler));
    m.insert("list_services".into(), Box::new(ListServicesHandler));
    m.insert("get_service".into(), Box::new(GetServiceHandler));
    m.insert("create_service".into(), Box::new(CreateServiceHandler));
    m.insert("update_service".into(), Box::new(UpdateServiceHandler));
    m.insert(
        "create_connection".into(),
        Box::new(CreateConnectionHandler),
    );
    m.insert("request_secret".into(), Box::new(RequestSecretHandler));
    m
}
