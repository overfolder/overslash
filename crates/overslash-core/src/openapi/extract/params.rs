//! Parameter-level helpers: `parameters[]` and `requestBody` → `ActionParam`.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::types::{ActionParam, ParamLocation, ParamResolver, RequestBodySpec};

use super::{parse_aliases, parse_instance_config, parse_sql_policy};

// ── parameters → HashMap<String, ActionParam> ────────────────────────

pub(super) fn collect_parameters(arr: &[Value], out: &mut HashMap<String, ActionParam>) {
    for p in arr {
        let Some(obj) = p.as_object() else { continue };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        let required = obj
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let schema = obj.get("schema").and_then(Value::as_object);
        let (param_type, enum_values, default) = schema_fields(schema);

        let resolve = obj.get("x-overslash-resolve").and_then(parse_resolver);
        let aliases = parse_aliases(Some(obj), name);

        let location = match obj.get("in").and_then(Value::as_str) {
            Some("query") => ParamLocation::Query,
            Some("path") => ParamLocation::Path,
            Some("header") => ParamLocation::Header,
            _ => ParamLocation::Body,
        };

        let instance_config = parse_instance_config(Some(obj));
        let (sql_field, sql_database) = parse_sql_policy(Some(obj));

        out.insert(
            name.to_string(),
            ActionParam {
                param_type,
                required,
                description,
                enum_values,
                default,
                resolve,
                aliases,
                location,
                instance_config,
                sql_field,
                sql_database,
            },
        );
    }
}

/// Parse an operation's `requestBody` into the spec routing needs. Returns
/// `None` when the operation declares no body, or declares one with no usable
/// media type — routing then sends neither body nor `Content-Type`.
///
/// The media type is taken from the declared `content` key rather than assumed,
/// so a non-JSON body surfaces as itself instead of being silently re-sent as
/// JSON. `application/json` wins when several are offered, since that is the
/// only shape `collect_body_parameters` can extract fields from.
pub(super) fn parse_request_body(body: Option<&Value>) -> Option<RequestBodySpec> {
    let b = body.and_then(Value::as_object)?;
    let content = b.get("content").and_then(Value::as_object)?;

    let content_type = if content.contains_key("application/json") {
        "application/json".to_string()
    } else {
        content.keys().next()?.clone()
    };

    Some(RequestBodySpec {
        content_type,
        required: b.get("required").and_then(Value::as_bool).unwrap_or(false),
    })
}

pub(super) fn collect_body_parameters(
    body: Option<&Value>,
    out: &mut HashMap<String, ActionParam>,
) {
    let Some(b) = body.and_then(Value::as_object) else {
        return;
    };
    let body_required = b.get("required").and_then(Value::as_bool).unwrap_or(false);
    let Some(schema) = b
        .get("content")
        .and_then(Value::as_object)
        .and_then(|c| c.get("application/json"))
        .and_then(Value::as_object)
        .and_then(|j| j.get("schema"))
        .and_then(Value::as_object)
    else {
        return;
    };

    let required_names: Vec<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };

    for (name, prop) in props {
        let pobj = prop.as_object();
        let (param_type, enum_values, default) = schema_fields(pobj);
        let description = pobj
            .and_then(|o| o.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let resolve = pobj
            .and_then(|o| o.get("x-overslash-resolve"))
            .and_then(parse_resolver);
        let aliases = parse_aliases(pobj, name);
        let instance_config = parse_instance_config(pobj);
        let (sql_field, sql_database) = parse_sql_policy(pobj);

        out.insert(
            name.clone(),
            ActionParam {
                param_type,
                required: body_required && required_names.iter().any(|r| r == name),
                description,
                enum_values,
                default,
                resolve,
                aliases,
                location: ParamLocation::Body,
                instance_config,
                sql_field,
                sql_database,
            },
        );
    }
}

fn schema_fields(
    schema: Option<&Map<String, Value>>,
) -> (String, Option<Vec<String>>, Option<Value>) {
    // Empty `param_type` is the "type unspecified" sentinel (no schema, or a
    // schema with no concrete `type` such as anyOf/oneOf) — runtime type
    // checks skip these rather than guess "string".
    let Some(s) = schema else {
        return (String::new(), None, None);
    };
    let param_type = s
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let enum_values = s.get("enum").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    });
    let default = s.get("default").cloned();
    (param_type, enum_values, default)
}

fn parse_resolver(v: &Value) -> Option<ParamResolver> {
    let obj = v.as_object()?;
    let get = obj.get("get").and_then(Value::as_str)?.to_string();
    let pick = obj.get("pick").and_then(Value::as_str)?.to_string();
    Some(ParamResolver { get, pick })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::compile_service;
    use serde_json::json;

    /// The D42/D43 sql annotations parse from body properties (the Metabase
    /// shape) and from `parameters[]` entries alike.
    #[test]
    fn sql_annotations_parse_from_body_and_query_params() {
        let body = json!({
            "required": true,
            "content": { "application/json": { "schema": {
                "type": "object",
                "required": ["database", "query"],
                "properties": {
                    "database": {
                        "type": "integer",
                        "x-overslash-sql-database": ".database | tostring"
                    },
                    "query": {
                        "type": "string",
                        "x-overslash-sql-field": "native.query"
                    },
                    "type": { "type": "string", "default": "native" }
                }
            }}}
        });
        let mut params = HashMap::new();
        collect_body_parameters(Some(&body), &mut params);
        assert_eq!(params["query"].sql_field.as_deref(), Some("native.query"));
        assert!(params["query"].sql_database.is_none());
        assert_eq!(
            params["database"].sql_database.as_deref(),
            Some(".database | tostring")
        );
        assert!(params["database"].sql_field.is_none());
        assert!(params["type"].sql_field.is_none());

        // Query-param shape (GET-with-SQL services).
        let arr = vec![json!({
            "name": "q",
            "in": "query",
            "schema": { "type": "string" },
            "x-overslash-sql-field": "q"
        })];
        let mut params = HashMap::new();
        collect_parameters(&arr, &mut params);
        assert_eq!(params["q"].sql_field.as_deref(), Some("q"));
    }

    // ── collect_parameters / body / schema_fields ────────────────────

    #[test]
    fn parameter_without_name_is_skipped() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [
                    {"in": "query", "schema": {"type": "string"}},
                    {"name": "q", "in": "query", "schema": {"type": "string"}}
                ]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params.len(), 1);
        assert!(svc.actions["x"].params.contains_key("q"));
    }

    #[test]
    fn parameter_without_schema_has_unspecified_type() {
        // No `schema` → no concrete `type`, so `param_type` is the empty
        // "unspecified" sentinel (opts the param out of runtime type checks)
        // rather than a fabricated "string".
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{"name": "q", "in": "query"}]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params["q"].param_type, "");
    }

    #[test]
    fn path_parameters_required_and_typed() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/cal/{id}/events": {
                    "get": {
                        "operationId": "list_events",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "schema": {"type": "string"}},
                            {"name": "q", "in": "query", "required": false,
                             "schema": {"type": "string"}}
                        ]
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["list_events"];
        assert!(a.params["id"].required);
        assert!(!a.params["q"].required);
        assert_eq!(a.params["id"].param_type, "string");
    }

    #[test]
    fn parameter_location_from_in() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/cal/{id}/events": {
                    "post": {
                        "operationId": "create_event",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "schema": {"type": "string"}},
                            {"name": "sendUpdates", "in": "query",
                             "schema": {"type": "string"}},
                            {"name": "Notion-Version", "in": "header",
                             "schema": {"type": "string", "default": "2022-06-28"}}
                        ],
                        "requestBody": {
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "properties": {"summary": {"type": "string"}}
                            }}}
                        }
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["create_event"];
        assert_eq!(a.params["id"].location, ParamLocation::Path);
        assert_eq!(a.params["sendUpdates"].location, ParamLocation::Query);
        assert_eq!(a.params["summary"].location, ParamLocation::Body);
        // `in: header` params land on `Header`, carrying their default so
        // `apply_defaults` can pin a constant version header at call time.
        assert_eq!(a.params["Notion-Version"].location, ParamLocation::Header);
        assert_eq!(
            a.params["Notion-Version"].default,
            Some(serde_json::json!("2022-06-28"))
        );
        // Path template is unaffected by location tracking.
        assert_eq!(a.path, "/cal/{id}/events");
    }

    #[test]
    fn parameter_enum_and_default() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "role", "in": "query",
                    "schema": {
                        "type": "string",
                        "enum": ["reader", "writer"],
                        "default": "reader"
                    }
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let p = &svc.actions["x"].params["role"];
        assert_eq!(
            p.enum_values.as_deref().unwrap(),
            &["reader".to_string(), "writer".to_string()]
        );
        assert_eq!(p.default.as_ref().unwrap(), "reader");
    }

    #[test]
    fn resolver_on_parameter() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/cal/{id}": {"get": {
                "operationId": "get_cal",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"get": "/cal/{id}", "pick": "summary"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let r = svc.actions["get_cal"].params["id"]
            .resolve
            .as_ref()
            .unwrap();
        assert_eq!(r.get, "/cal/{id}");
        assert_eq!(r.pick, "summary");
    }

    #[test]
    fn body_without_required_array_marks_props_optional() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(!svc.actions["x"].params["foo"].required);
    }

    #[test]
    fn body_required_false_makes_all_props_optional() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["foo"],
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(!svc.actions["x"].params["foo"].required);
    }

    #[test]
    fn body_wrong_content_type_ignored() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/xml": {
                        "schema": {
                            "type": "object",
                            "required": ["foo"],
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params.is_empty());

        // The media type is still carried verbatim rather than coerced to
        // JSON, so routing can tell it apart instead of silently re-sending an
        // XML body as `application/json`.
        let rb = svc.actions["x"].request_body.as_ref().unwrap();
        assert_eq!(rb.content_type, "application/xml");
        assert!(!rb.is_json());
    }

    #[test]
    fn request_body_records_json_media_type() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {
                        "schema": {"type": "object", "properties": {"foo": {"type": "string"}}}
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let rb = svc.actions["x"].request_body.as_ref().unwrap();
        assert_eq!(rb.content_type, "application/json");
        assert!(rb.required);
        assert!(rb.is_json());
    }

    #[test]
    fn request_body_absent_when_operation_declares_none() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {"post": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        // No `requestBody` in the contract ⇒ routing sends neither body nor
        // `Content-Type`.
        assert!(svc.actions["x"].request_body.is_none());
    }

    #[test]
    fn request_body_optional_fields_still_declared() {
        // The `POST /email/search` shape: a body whose every field is optional.
        // The spec must still record it, or routing omits the body, omits
        // `Content-Type`, and a strict upstream rejects the call.
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {"type": "object", "properties": {"q": {"type": "string"}}}
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let rb = svc.actions["x"].request_body.as_ref().unwrap();
        assert_eq!(rb.content_type, "application/json");
        assert!(!rb.required);
    }

    #[test]
    fn request_body_prefers_json_when_several_offered() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "content": {
                        "application/xml": {"schema": {"type": "object"}},
                        "application/json": {"schema": {
                            "type": "object", "properties": {"foo": {"type": "string"}}
                        }}
                    }
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        // JSON wins — it is the only shape whose fields we can extract.
        assert_eq!(
            svc.actions["x"].request_body.as_ref().unwrap().content_type,
            "application/json"
        );
        assert!(svc.actions["x"].params.contains_key("foo"));
    }

    #[test]
    fn body_without_properties_is_noop() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {
                        "schema": {"type": "object"}
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params.is_empty());
    }

    #[test]
    fn operation_params_shadow_path_params() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "description": "path-level", "schema": {"type": "string"}
                }],
                "get": {
                    "operationId": "x",
                    "parameters": [{
                        "name": "id", "in": "path", "required": true,
                        "description": "op-level", "schema": {"type": "string"}
                    }]
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params["id"].description, "op-level");
    }

    // ── parse_resolver structural edge cases ──────────────────────────

    #[test]
    fn resolver_drops_entry_missing_get() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"pick": "name"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params["id"].resolve.is_none());
    }

    #[test]
    fn resolver_drops_entry_missing_pick() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"get": "/x/{id}"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params["id"].resolve.is_none());
    }
}
