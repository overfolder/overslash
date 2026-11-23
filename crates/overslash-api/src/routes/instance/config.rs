//! `GET /v1/instance/config` — the effective configuration this deployment
//! runs with, read-only.
//!
//! Values come from the process environment at boot; changing one means
//! changing the deployment (Terraform) and redeploying, so nothing here is
//! writable. Secrets are reported only as set or not set — their values never
//! leave the process. Template variables are shown in full: by D44 they are
//! non-secret by construction (any template author can read them back).

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{AppState, extractors::InstanceAdminAuth, services::rate_limit::RateLimitConfig};

#[derive(Serialize)]
pub(super) struct ConfigResponse {
    groups: Vec<Group>,
}

#[derive(Serialize)]
struct Group {
    title: &'static str,
    rows: Vec<Row>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Value {
    /// A plain value, shown verbatim.
    Text { value: String },
    /// A list of values (IdPs, CIDRs), shown as chips.
    List { values: Vec<String> },
    /// A secret: only whether it is configured.
    Secret { set: bool },
    /// Not configured, with an optional note on what happens instead.
    Unset { note: Option<String> },
}

#[derive(Serialize)]
struct Row {
    key: String,
    #[serde(flatten)]
    value: Value,
    /// Short gloss shown after the value (`1 h`, `/ 60 s`, `dev · 04ab626`).
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// `true` when the environment variable is not set and the built-in
    /// default applies.
    is_default: bool,
}

fn text(key: &str, value: impl ToString) -> Row {
    Row {
        key: key.to_string(),
        value: Value::Text {
            value: value.to_string(),
        },
        note: None,
        is_default: false,
    }
}

/// A value backed by one environment variable named `key`.
fn env_text(key: &str, value: impl ToString) -> Row {
    Row {
        is_default: !overslash_env::is_set(key),
        ..text(key, value)
    }
}

fn secret(key: &str, set: bool) -> Row {
    Row {
        key: key.to_string(),
        value: Value::Secret { set },
        note: None,
        is_default: false,
    }
}

fn list_or_unset(key: &str, values: Vec<String>, unset_note: Option<&str>) -> Row {
    let value = if values.is_empty() {
        Value::Unset {
            note: unset_note.map(str::to_string),
        }
    } else {
        Value::List { values }
    };
    Row {
        key: key.to_string(),
        value,
        note: None,
        is_default: false,
    }
}

fn with_note(mut row: Row, note: impl Into<String>) -> Row {
    row.note = Some(note.into());
    row
}

fn rate(key: &str, limit: Option<RateLimitConfig>) -> Row {
    match limit {
        Some(l) => with_note(
            env_text(key, l.max_requests),
            format!("/ {} s", l.window_seconds),
        ),
        None => Row {
            key: key.to_string(),
            value: Value::Unset {
                note: Some("Turned off".into()),
            },
            note: None,
            is_default: false,
        },
    }
}

fn duration_gloss(secs: i64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{} h", s / 3600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// Prefix of the template-variable environment names (`template_vars.rs`).
const TEMPLATE_VAR_PREFIX: &str = "OVERSLASH_TEMPLATE_VAR_";

pub(super) async fn get_config(
    _admin: InstanceAdminAuth,
    State(state): State<AppState>,
) -> Json<ConfigResponse> {
    let c = &state.config;
    let info = overslash_core::build_info::build_info();
    let proxies = c.trusted_proxies.view();
    let ssrf: Vec<String> = crate::services::ssrf_guard::operator_allowed_ranges()
        .iter()
        .map(|r| r.to_string())
        .collect();

    let build = vec![
        with_note(
            text("Version", format!("v{}", info.version)),
            info.commit_short(),
        ),
        env_text("OVERSLASH_ENV", c.deployment_env.as_str()),
    ];

    let billing = vec![
        env_text("ALLOW_ORG_CREATION", c.allow_org_creation),
        env_text("CLOUD_BILLING", c.cloud_billing),
        env_text("TRIAL_DEFAULT_DURATION_DAYS", c.trial_default_duration_days),
        secret("STRIPE_SECRET_KEY", c.stripe_secret_key.is_some()),
        secret("STRIPE_WEBHOOK_SECRET", c.stripe_webhook_secret.is_some()),
    ];

    let mut security = vec![
        with_note(
            env_text("ADMIN_STEP_UP_MAX_AGE_SECS", c.admin_step_up_max_age_secs),
            duration_gloss(c.admin_step_up_max_age_secs),
        ),
        list_or_unset("OVERSLASH_SSRF_ALLOWED_CIDRS", ssrf, None),
        env_text("OVERSLASH_TRUSTED_PROXY_HOPS", proxies.hops),
        list_or_unset("OVERSLASH_TRUSTED_PROXIES", proxies.cidrs, None),
        secret("OVERSLASH_TRUSTED_PROXY_SECRET", proxies.secret_set),
    ];
    if let Some(h) = proxies.client_ip_header {
        security.push(text("OVERSLASH_TRUSTED_CLIENT_IP_HEADER", h));
    }

    let limits = &c.ingress_rate_limits;
    let rate_limits = vec![
        with_note(
            env_text("DEFAULT_RATE_LIMIT", c.default_rate_limit),
            format!("/ {} s", c.default_rate_window_secs),
        ),
        rate("MCP_RATE_LIMIT", limits.mcp_client),
        rate("OAUTH_RATE_LIMIT", limits.oauth_ip),
        rate("OAUTH_REGISTER_RATE_LIMIT", limits.oauth_register_ip),
    ];

    let mut sign_in = vec![
        list_or_unset(
            "Root identity providers",
            crate::services::admin_step_up::root_idps(&state),
            Some("None · magic link only"),
        ),
        env_text("MAGIC_LINK_ENABLED", c.magic_link_enabled),
        env_text("DEV_AUTH", c.dev_auth_enabled),
    ];
    if let Some(org) = &c.single_org_mode {
        sign_in.push(text("SINGLE_ORG_MODE", org));
    }

    let template_vars: Vec<Row> = overslash_core::template_vars::Vars::from_env()
        .iter()
        .map(|(k, v)| text(&format!("{TEMPLATE_VAR_PREFIX}{k}"), v))
        .collect();
    let template_vars = if template_vars.is_empty() {
        vec![Row {
            key: format!("{TEMPLATE_VAR_PREFIX}*"),
            value: Value::Unset {
                note: Some("None set · templates use their defaults".into()),
            },
            note: None,
            is_default: false,
        }]
    } else {
        template_vars
    };

    Json(ConfigResponse {
        groups: vec![
            Group {
                title: "Build",
                rows: build,
            },
            Group {
                title: "Orgs & billing",
                rows: billing,
            },
            Group {
                title: "Security",
                rows: security,
            },
            Group {
                title: "Rate limits",
                rows: rate_limits,
            },
            Group {
                title: "Sign-in",
                rows: sign_in,
            },
            Group {
                title: "Template variables",
                rows: template_vars,
            },
        ],
    })
}
