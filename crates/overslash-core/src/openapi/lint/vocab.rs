//! What is legitimate where: the alias table each position normalizes, and the
//! plain OpenAPI fields it accepts.

use super::super::alias::{
    APIKEY_SEC_ALIASES, Alias, HTTP_SEC_ALIASES, INFO_ALIASES, MCP_TOOL_ALIASES,
    OAUTH2_SEC_ALIASES, OPERATION_ALIASES, PARAMETER_ALIASES, ROOT_ALIASES,
};
use super::super::ext::{Pos, SchemeKind};

/// The alias table [`normalize_aliases`](super::super::normalize_aliases)
/// applies here.
///
/// Borrowed from `alias.rs` rather than restated, so a new alias teaches this
/// module at the same time it teaches the normalizer.
pub(super) fn alias_table(pos: Pos) -> &'static [Alias] {
    match pos {
        Pos::Root => ROOT_ALIASES,
        Pos::Info => INFO_ALIASES,
        Pos::Operation | Pos::PlatformAction => OPERATION_ALIASES,
        Pos::Parameter | Pos::BodyProperty | Pos::McpToolProperty => PARAMETER_ALIASES,
        Pos::McpTool | Pos::McpToolDiscovered => MCP_TOOL_ALIASES,
        Pos::SecurityScheme(SchemeKind::Oauth2) => OAUTH2_SEC_ALIASES,
        Pos::SecurityScheme(SchemeKind::ApiKey) => APIKEY_SEC_ALIASES,
        Pos::SecurityScheme(SchemeKind::Http) => HTTP_SEC_ALIASES,
        _ => &[],
    }
}

/// The non-`x-` keys legitimate at a position: the standard OpenAPI fields for
/// that object plus our own plain ones.
///
/// `None` means open-world — JSON Schema vocabulary, an MCP wire snapshot, or a
/// position we do not interpret — where an unrecognized bare key is not evidence
/// of anything.
pub(super) fn allowed_plain(pos: Pos) -> Option<&'static [&'static str]> {
    Some(match pos {
        Pos::Root => &[
            "openapi",
            "info",
            "servers",
            "paths",
            "components",
            "security",
            "tags",
            "externalDocs",
            "webhooks",
            "jsonSchemaDialect",
        ],
        Pos::Info => &[
            "title",
            "version",
            "summary",
            "description",
            "termsOfService",
            "contact",
            "license",
        ],
        Pos::PathItem => &[
            "$ref",
            "summary",
            "description",
            "servers",
            "parameters",
            "get",
            "put",
            "post",
            "delete",
            "options",
            "head",
            "patch",
            "trace",
        ],
        Pos::Operation => &[
            "tags",
            "summary",
            "description",
            "externalDocs",
            "operationId",
            "parameters",
            "requestBody",
            "responses",
            "callbacks",
            "deprecated",
            "security",
            "servers",
        ],
        Pos::Parameter => &[
            "$ref",
            "name",
            "in",
            "description",
            "required",
            "deprecated",
            "allowEmptyValue",
            "style",
            "explode",
            "allowReserved",
            "schema",
            "content",
        ],
        Pos::Components => &[
            "schemas",
            "responses",
            "parameters",
            "examples",
            "requestBodies",
            "headers",
            "securitySchemes",
            "links",
            "callbacks",
            "pathItems",
        ],
        Pos::SecurityScheme(SchemeKind::Oauth2) => &["type", "description", "flows"],
        Pos::SecurityScheme(SchemeKind::ApiKey) => &["type", "description", "name", "in"],
        Pos::SecurityScheme(SchemeKind::Http) => &["type", "description", "scheme", "bearerFormat"],
        Pos::McpBlock => &[
            "url",
            "auth",
            "autodiscover",
            "tools",
            "discovered_tools",
            // Provenance on a pasted resync snapshot. Nothing reads it off the
            // document — `discovered_at` is a `service_instances` column — but
            // dropping it from a paste would be busywork, so it is inert rather
            // than wrong.
            "discovered_at",
        ],
        Pos::McpAuth => &["kind", "secret_name", "provider", "scopes"],
        Pos::McpTool => &[
            "name",
            "description",
            "disabled",
            "input_schema",
            "output_schema",
            "mcp_tool",
        ],
        Pos::PlatformAction => &["description", "summary", "params", "permission"],
        // Open-world, each for its own reason: body and tool properties are JSON
        // Schema; a discovered-tool snapshot mirrors the MCP wire shape
        // (`annotations`, `title`, `_meta`) and closing it would fire on every
        // field of a faithful paste; a platform-action param is schema-shaped and
        // an author may reasonably write `enum` there; an unrecognized scheme
        // `type` already has its own error to answer for.
        Pos::BodyProperty
        | Pos::McpToolProperty
        | Pos::McpToolDiscovered
        | Pos::PlatformActionParam
        | Pos::SecurityScheme(SchemeKind::Unknown)
        | Pos::Other => return None,
    })
}
