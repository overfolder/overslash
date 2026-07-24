use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::CredentialTemplate;

/// Risk level of a service action: read, write, or delete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    #[default]
    Read,
    Write,
    Delete,
}

impl Risk {
    /// Returns `true` for write and delete operations.
    pub fn is_mutating(self) -> bool {
        !matches!(self, Risk::Read)
    }

    /// Monotonic severity ordering: `read < write < delete`. Used by the
    /// layered-template fold to clamp risk **upward only** (a mask may add
    /// approvals, never remove them).
    pub fn severity(self) -> u8 {
        match self {
            Risk::Read => 0,
            Risk::Write => 1,
            Risk::Delete => 2,
        }
    }

    /// Infer risk from an HTTP method.
    pub fn from_http_method(method: &str) -> Risk {
        match method.to_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Risk::Read,
            "DELETE" => Risk::Delete,
            _ => Risk::Write,
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Risk::Read => write!(f, "read"),
            Risk::Write => write!(f, "write"),
            Risk::Delete => write!(f, "delete"),
        }
    }
}

/// Execution runtime for a service definition.
///
/// - `Http` (default): actions are OpenAPI operations invoked by the HTTP executor.
/// - `Mcp`: actions are tools on an external MCP server (Streamable HTTP, JSON-RPC 2.0).
/// - `Platform`: actions are dispatched in-process to registered Rust handlers.
///   Used by the `overslash` meta-service so agents can manage templates, secrets,
///   etc. through the same Mode-C permission/approval graph as external services.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    #[default]
    Http,
    Mcp,
    Platform,
}

impl Runtime {
    pub fn is_default(&self) -> bool {
        matches!(self, Runtime::Http)
    }
}

fn default_true() -> bool {
    true
}

/// A service definition — describes an external API, its auth methods, and available actions.
/// Also referred to as a "service template" (the blueprint from which service instances are created).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub key: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Catalog visibility (`x-overslash-hidden`). Hidden templates are
    /// omitted from agent-facing list/search surfaces (MCP discovery,
    /// `/v1/search`, embeddings) but stay reachable by key and instantiable;
    /// dashboard surfaces show them flagged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    /// Credential slots this template needs, declared once
    /// (`components.x-overslash-secrets`) and referenced by the auth entries'
    /// templates. One slot is one vault secret the operator binds; a slot may
    /// feed several injections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretSlot>,
    /// Non-secret per-instance inputs a credential template may read alongside
    /// its secrets (`components.x-overslash-config`). Declared here, stored in
    /// the instance's `config` jsonb next to the instance-config *param* pins,
    /// and never vaulted — see [`ConfigVar`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config: Vec<ConfigVar>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
    /// Execution runtime. Defaults to `Http` for backwards compat with every
    /// existing template. MCP templates set this to `Mcp` and populate `mcp`.
    #[serde(default, skip_serializing_if = "Runtime::is_default")]
    pub runtime: Runtime,
    /// MCP-specific config. Present iff `runtime == Mcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSpec>,
    /// Defaults an org layer supplies for the per-instance override surface
    /// (endpoint URL + `instance_config` pins). Only ever set by the fold —
    /// a shipped template expresses its defaults through `servers:` and param
    /// `default:` instead, so the compile path always leaves this `None`.
    ///
    /// An instance that sets the corresponding field still wins; see
    /// [`crate::service_layer::InstanceDefaults`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_defaults: Option<crate::service_layer::InstanceDefaults>,
}

/// MCP external-server configuration. Lives inside a `ServiceDefinition` when
/// `runtime == Mcp`. All per-tool shape lives on `ServiceAction` (one action
/// per tool) — this struct only carries transport + auth + discovery config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSpec {
    /// Streamable HTTP endpoint (MCP 2025-06-18). JSON-RPC 2.0 POST target.
    /// `None` means the template has no default URL; the service instance must
    /// supply one via its `url` field at creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How to authenticate to the MCP server.
    pub auth: McpAuth,
    /// When `true` (default), saving the template triggers `tools/list` and
    /// caches the result; the compile step merges discovered tools with any
    /// authored `tools:` overrides. When `false`, the tool set is pinned to
    /// what the YAML declares and every tool must carry `input_schema`.
    #[serde(default = "default_true")]
    pub autodiscover: bool,
}

/// How Overslash authenticates outbound to an MCP server.
///
/// The tagged-enum shape is forward-compatible: adding future variants
/// (`header`, `headers`, `oauth`) is a pure addition that does not break
/// existing serialized templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum McpAuth {
    /// No auth — public or internal MCP servers.
    None,
    /// `Authorization: Bearer <secret>`. The secret is resolved at call time
    /// from the Overslash vault by name (org or user scope, versioned).
    /// `secret_name: None` means the template has no default; the service
    /// instance must supply one via its `secret_name` field at creation time.
    Bearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_name: Option<String>,
    },
    /// `Authorization: Bearer <token>`, where the token is a live OAuth access
    /// token resolved at call time from the caller's connection for `provider`
    /// (refreshed via the standard grant, using the org/BYOC OAuth client).
    /// Mirrors HTTP-runtime `ServiceAuth::OAuth` but for MCP servers that sit
    /// behind OAuth (e.g. HubSpot's remote MCP). `scopes` is the superset the
    /// service may request at connect time.
    #[serde(rename = "oauth")]
    OAuth {
        provider: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
    },
}

impl ServiceDefinition {
    /// The config key whose per-instance value names the account this instance
    /// speaks for, if the template declares one (`identity: true` on a
    /// `components.x-overslash-config` entry).
    ///
    /// Discovery reads the instance's `config` at this key and surfaces it as
    /// `account_email`, which is what lets several secret-based instances of
    /// one template be told apart. Deterministic when a template mistakenly
    /// marks more than one: keys are sorted at parse time, so the first wins.
    pub fn identity_config_key(&self) -> Option<&str> {
        self.config
            .iter()
            .find(|c| c.identity)
            .map(|c| c.key.as_str())
    }

    /// The credential slots one secret-backed auth entry reads, paired with
    /// their declarations — the single place the implicit-slot rule lives.
    ///
    /// A slot declared under `components.x-overslash-secrets` uses that
    /// declaration. A slot with no declaration is the scheme's implicit
    /// self-named slot and inherits the scheme's own label, description,
    /// default secret name, source and optionality. That is how a
    /// single-secret template declares no secrets block at all — and why a
    /// definition rebuilt without one (parts-based CRUD) still resolves.
    ///
    /// Returns empty for OAuth entries, which carry no vault secret.
    pub fn slots_for(&self, auth: &ServiceAuth) -> Vec<SecretSlot> {
        let ServiceAuth::Secret {
            scheme,
            label,
            description,
            default_secret_name,
            slots,
            secret_source,
            optional,
            ..
        } = auth
        else {
            return Vec::new();
        };

        // A definition from before credential slots existed carries no
        // `slots`; its one secret is the scheme's own.
        let keys: Vec<&String> = if slots.is_empty() {
            vec![scheme]
        } else {
            slots.iter().collect()
        };

        keys.into_iter()
            .map(|key| match self.secrets.iter().find(|s| &s.key == key) {
                Some(declared) => declared.clone(),
                None => SecretSlot {
                    key: key.clone(),
                    label: label.clone(),
                    description: description.clone(),
                    default_secret_name: default_secret_name.clone(),
                    source: *secret_source,
                    optional: *optional,
                },
            })
            .collect()
    }

    /// The non-secret config vars one auth entry's template reads, paired with
    /// their declarations.
    ///
    /// Unlike [`Self::slots_for`] there is no implicit-var rule: a config key
    /// only exists because `components.x-overslash-config` declares it, which
    /// is what extraction checks. A key with no declaration here can only come
    /// from stored data that has drifted from its template, and is dropped
    /// rather than invented — resolution then treats the scheme as unresolved
    /// instead of rendering a credential from a value nobody declared.
    pub fn config_for(&self, auth: &ServiceAuth) -> Vec<ConfigVar> {
        let ServiceAuth::Secret { config_keys, .. } = auth else {
            return Vec::new();
        };
        config_keys
            .iter()
            .filter_map(|key| self.config.iter().find(|c| &c.key == key).cloned())
            .collect()
    }

    /// Every credential slot the template needs, deduped, in `auth` order.
    /// The set the dashboard renders and an instance binds.
    pub fn all_slots(&self) -> Vec<SecretSlot> {
        let mut out: Vec<SecretSlot> = Vec::new();
        for auth in &self.auth {
            for slot in self.slots_for(auth) {
                if !out.iter().any(|s| s.key == slot.key) {
                    out.push(slot);
                }
            }
        }
        out
    }
}

/// Alias: a service template is the same as a service definition.
pub type ServiceTemplate = ServiceDefinition;

/// Which tier a template belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateTier {
    Global,
    Org,
    User,
}

/// Auth method supported by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServiceAuth {
    #[serde(rename = "oauth")]
    OAuth {
        provider: String,
        /// Superset of OAuth scopes this service may request. The caller
        /// (dashboard/API) picks which subset to actually request at connect
        /// time; the provider's granted scopes land on `connections.scopes`.
        #[serde(default)]
        scopes: Vec<String>,
        token_injection: TokenInjection,
    },
    /// A static, vault-stored credential injected into the outbound request.
    /// Not necessarily an API key: `services/email.yaml`'s `mailbox` scheme
    /// composes an IMAP username and password. Compiled from an OpenAPI
    /// `apiKey` or `http`-bearer security scheme.
    ///
    /// Serializes as `"secret"`; still accepts the legacy `"api_key"`
    /// discriminant on the wire.
    #[serde(rename = "secret", alias = "api_key")]
    Secret {
        /// The securitySchemes key this was compiled from (`gateway`,
        /// `mailbox`, …). Names the injection — the header or query parameter
        /// this entry fills — and keys nothing in the vault by itself; the
        /// secrets come from `slots`.
        #[serde(default)]
        scheme: String,
        /// Short human-readable display name for the credential slot, from
        /// `x-overslash-label` (alias `label`) — e.g. "Overfwd API Token".
        /// The dashboard uses it as the row label; absent falls back to the
        /// scheme key.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        label: String,
        /// The standard OpenAPI securityScheme `description`, verbatim.
        /// Help text for the credential's row in the dashboard.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        description: String,
        default_secret_name: String,
        injection: TokenInjection,
        /// How to build the value from `slots`. `None` injects the single
        /// slot's secret verbatim — the common case.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template: Option<CredentialTemplate>,
        /// Slot keys the template reads, computed once at extraction by
        /// [`crate::credential_template::referenced_slots`] so nothing on the
        /// request path parses jq to decide what to decrypt. Exactly one entry
        /// (the implicit slot named after `scheme`) when there is no template.
        #[serde(default)]
        slots: Vec<String>,
        /// Non-secret config keys the template reads, split out from `slots` at
        /// extraction by the same static analysis and against the same
        /// `components.x-overslash-config` declarations. Empty for every
        /// template that composes secrets alone. Kept separate from `slots`
        /// because the two resolve from different stores — a slot names a vault
        /// secret, a config key names a plain value on the instance.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        config_keys: Vec<String>,
        /// Fallback policy when the instance has no explicit per-slot
        /// binding in `credentials[slot]`. `Instance` (default): fall back
        /// to the instance's legacy scalar `secret_name`; unbound means the
        /// credential is missing. `Org`: fall back to the fixed
        /// `default_secret_name` in the org vault — a sensible org-wide
        /// default for a shared credential (e.g. an overfwd gateway key)
        /// that any instance may still override per deployment.
        #[serde(default)]
        secret_source: SecretSource,
        /// When true, this credential is injected only if its secret is
        /// configured; a missing secret is skipped rather than failing the
        /// request. Meaningful for an `Org`-source static credential the
        /// deployment may not need — e.g. an overfwd gateway key when the
        /// gateway runs with `OVERFWD_REQUIRE_API_KEY=false`. Default `false`:
        /// a missing required secret still surfaces as an error at send time.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        optional: bool,
    },
}

/// Which secret a compiled credential injection falls back to at execution
/// time when the instance has no explicit `credentials[scheme]` binding.
/// See [`ServiceAuth::Secret`]'s `secret_source`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSource {
    /// The instance's legacy scalar `secret_name` (per-instance credential,
    /// no org-wide default name).
    #[default]
    Instance,
    /// The scheme's fixed `default_secret_name`, from the org vault.
    Org,
}

/// A credential slot: one vault secret the operator binds per instance.
///
/// Declared once under `components.x-overslash-secrets` and referenced by
/// name from a [`CredentialTemplate`], so several injections can read the same
/// secret and one injection can compose several.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretSlot {
    /// Key the template references (`mailbox_user`) and the instance binds in
    /// its `credentials` map.
    pub key: String,
    /// Short display name for the dashboard row ("Mailbox username").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Help text under the row.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Org-vault secret name used when `source: org` and the instance binds
    /// nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_secret_name: String,
    #[serde(default)]
    pub source: SecretSource,
    /// When true a missing secret skips the injection instead of failing the
    /// request.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

/// A non-secret template input: one plain value the operator sets per service
/// instance, which a [`CredentialTemplate`] may read alongside its secrets.
///
/// The reason this is not a [`SecretSlot`] with a flag: a slot's value is
/// encrypted, versioned, write-only in the dashboard and costs a vault entry.
/// A mailbox *username* is none of those things — it is the public half of a
/// login, and `services/email.yaml` only stored it in the vault because a
/// credential template had no other input. A config var is stored in the
/// instance's `config` jsonb, the same place an `x-overslash-instance-config`
/// param pin lives, and shares its namespace: one key means one field on the
/// instance form, whether a param or a credential reads it. That sharing is
/// what gives config vars an org-layer default for free — a layer's
/// `instance_defaults.config` presets them exactly as it presets a param pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVar {
    /// Key the credential template references (`.mailbox_user`) and the
    /// instance sets in its `config` map.
    pub key: String,
    /// Short display name for the instance form ("Mailbox username").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Help text under the field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// When true, a scheme reading this var does not resolve until the value is
    /// set — the same treatment an unbound secret slot gets, because a jq
    /// template silently absorbs a missing value (`"user" + null` is `"user"`)
    /// and would otherwise send a truncated credential.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    /// When true, this var's value names *which account* the instance speaks
    /// for, and discovery surfaces it as the row's `account_email`.
    ///
    /// OAuth instances get that identity for free from
    /// `connections.account_email`. Secret-based ones have nowhere to put it:
    /// the display name belongs to the template, so three mailboxes on the
    /// same template render three identical rows and an agent has no way to
    /// tell which is which except by calling all of them. Marking the config
    /// var that already holds the address closes that gap without a new
    /// column.
    ///
    /// At most one var per template should set this; the first by key order
    /// wins if several do.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub identity: bool,
}

/// Where a credential's value goes in the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInjection {
    #[serde(rename = "as")]
    pub inject_as: String, // "header" or "query"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    /// OAuth only: the literal that precedes the live token ("Bearer ").
    /// Secret-backed credentials express any prefix in their
    /// [`CredentialTemplate`] instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// One scoped param: which argument supplies the value, and the **label** that
/// value is filed under in the derived permission key
/// (`{service}:{action}:{label}={value}`).
///
/// The label defaults to the param name and only differs when several params
/// mean the same thing to a human granting access: `to`, `cc`, and `bcc` are
/// all *recipients*, so all three are authored as `<param>:recipient` and one
/// `email:send:recipient=jane@example.com` grant covers an address wherever it
/// appears — and the same address on two headers collapses to one key, hence
/// one approval.
///
/// Serializes as `{param, label}` — API responses hand clients the resolved
/// pair so no consumer has to re-implement the `param:label` grammar. Only
/// the template document carries the compact authored form (see
/// [`ScopeParams`]'s `Serialize`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeParamRef {
    /// The action param whose value is scoped.
    pub param: String,
    /// The permission-key namespace the value is filed under.
    pub label: String,
}

impl ScopeParamRef {
    /// Parse the wire form: `"to"` (label = param) or `"to:recipient"`.
    /// Both sides must be bare identifiers — the key grammar is `:`-delimited,
    /// so a label containing `:` or `=` would produce a key no one can parse
    /// back.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (param, label) = match s.split_once(':') {
            Some((p, l)) => (p, l),
            None => (s, s),
        };
        for (side, v) in [("param", param), ("label", label)] {
            if !is_scope_ident(v) {
                return Err(format!(
                    "scope_param entry {s:?}: {side} {v:?} must be an identifier \
                     ([A-Za-z_][A-Za-z0-9_]*)"
                ));
            }
        }
        Ok(Self {
            param: param.to_string(),
            label: label.to_string(),
        })
    }

    /// The wire form — `param` when the label is implicit, else `param:label`.
    pub fn to_wire(&self) -> String {
        if self.param == self.label {
            self.param.clone()
        } else {
            format!("{}:{}", self.param, self.label)
        }
    }
}

/// Is `s` a bare identifier? Used for both sides of a `param:label` entry and,
/// in `permissions`, to recognize a `label=` prefix on a derived key.
pub fn is_scope_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Which params provide the `{arg}` segment of an action's permission keys.
///
/// Empty means the action is unscoped and its arg is `*`. One entry is the
/// common case (`scope_param: repo`); several entries fan the keys out over
/// the union of their values, which is what lets a send be gated on every
/// recipient rather than just the ones in `to`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeParams(Vec<ScopeParamRef>);

impl ScopeParams {
    pub fn refs(&self) -> &[ScopeParamRef] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse from the authored form: one string, or a list of them.
    pub fn parse_list<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        entries
            .into_iter()
            .map(ScopeParamRef::parse)
            .collect::<Result<Vec<_>, _>>()
            .map(ScopeParams)
    }
}

impl FromIterator<ScopeParamRef> for ScopeParams {
    fn from_iter<I: IntoIterator<Item = ScopeParamRef>>(iter: I) -> Self {
        ScopeParams(iter.into_iter().collect())
    }
}

impl From<&str> for ScopeParams {
    /// One param under its own name — the `scope_param: repo` shape, for call
    /// sites holding a param name rather than authored text (tests, in-code
    /// service definitions).
    ///
    /// Deliberately **not** a second parser: the `param:label` grammar lives
    /// only in [`ScopeParamRef::parse`], so text that might carry a label must
    /// go through [`ScopeParams::parse_list`], which rejects the shapes this
    /// would otherwise accept silently.
    fn from(param: &str) -> Self {
        ScopeParams(vec![ScopeParamRef {
            param: param.to_string(),
            label: param.to_string(),
        }])
    }
}

impl Serialize for ScopeParams {
    /// Round-trips the authored shape: a lone entry serializes as a bare
    /// string (so every template that predates lists stays byte-identical),
    /// several as a sequence.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [one] => serializer.serialize_str(&one.to_wire()),
            many => serializer.collect_seq(many.iter().map(ScopeParamRef::to_wire)),
        }
    }
}

impl<'de> Deserialize<'de> for ScopeParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        let raw = Raw::deserialize(deserializer)?;
        let entries = match &raw {
            Raw::One(s) => std::slice::from_ref(s),
            Raw::Many(v) => v.as_slice(),
        };
        ScopeParams::parse_list(entries.iter().map(String::as_str))
            .map_err(serde::de::Error::custom)
    }
}

/// An action within a service (maps to an HTTP request template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    /// What the *agent* reads when choosing this action, and the text the
    /// keyword/embedding index scores against. For an HTTP operation this is
    /// the OpenAPI `description`, falling back to `summary` when only the
    /// short form is authored.
    ///
    /// This is the only string about an action that ever reaches the model —
    /// parameter descriptions, defaults, and response schemas do not — so it
    /// carries the whole contract, examples included, and is free to be long.
    pub description: String,
    /// The short, interpolatable human label: the OpenAPI `summary`, e.g.
    /// `"Search folder '{folder}' for {criteria}"`. `{param}` placeholders are
    /// substituted with the caller's actual arguments to title the approval
    /// screen and the audit row.
    ///
    /// Separate from [`description`](Self::description) because the two jobs
    /// pull in opposite directions: the agent needs the long form, while an
    /// approval prompt a human must read in one glance needs a single line.
    /// `None` falls back to `description`, which is how every action that
    /// authors only one of the two behaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub risk: Risk,
    /// Response type hint: "json" (default) or "binary" (for file downloads).
    /// When "binary", callers should use `prefer_stream: true` to avoid buffering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, ActionParam>,
    /// Which params provide the `{arg}` segment in permission keys, and under
    /// which label. Empty (`scope_param` absent) means the arg defaults to `*`.
    #[serde(default, skip_serializing_if = "ScopeParams::is_empty")]
    pub scope_param: ScopeParams,
    /// OAuth scopes this specific action needs. Checked against the
    /// connection's granted scopes at execution time (SPEC §9 "Per-action
    /// scopes"). Empty means no gating — fall back to the service-level
    /// scope set granted at connect time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Platform-runtime only. When set, overrides the action key used for
    /// permission key derivation, letting multiple actions share a single
    /// permission anchor. E.g. `list_templates` and `get_template` both
    /// set `permission: manage_templates_own` so one `overslash:manage_templates_own:*`
    /// grant covers both without granting the broad action-key wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// Labeled jq filters to extract human-readable fields from the resolved
    /// request (method / url / params / body / resolved) at approval-create
    /// and audit write time. See SPEC §N "Detail disclosure".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<DisclosureField>,
    /// Dotted paths into the resolved request to replace with `"[REDACTED]"`
    /// in the persisted raw payload (`approvals.action_detail` + audit
    /// `detail.request`). Does not affect the disclose jq input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<String>,
    /// MCP tool name (present iff the owning service's `runtime == Mcp`).
    /// The map key in `ServiceDefinition.actions` equals this tool name for
    /// MCP actions, but we store it explicitly so renames are cheap later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    /// MCP 2025-06-18 `outputSchema` — carried so agents can consume typed
    /// structured results without a second round-trip to describe the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Admin-controlled visibility toggle. When `true`, the action is hidden
    /// from the agent-visible action list and `/v1/actions/execute` rejects
    /// invocation. Applies equally to Http and Mcp actions, though v1 only
    /// surfaces it in the MCP discovery-override flow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The operation's declared `requestBody`, parsed at template-load time.
    /// `None` means the operation takes no body at all (e.g. a POST whose only
    /// inputs are path params) — routing then sends neither a body nor a
    /// `Content-Type`.
    ///
    /// Presence here is a static fact about the contract, *not* a function of
    /// which arguments a caller happened to supply: an operation whose body
    /// fields are all optional (`POST /email/search`) must still send `{}` with
    /// the declared media type, or a strict upstream extractor rejects the call
    /// before it ever looks at the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBodySpec>,
}

impl ServiceAction {
    /// The template to interpolate for human-facing surfaces (approval title,
    /// audit description). Prefers the short [`summary`](Self::summary) and
    /// falls back to [`description`](Self::description) when the action
    /// authors only the long form.
    pub fn label_template(&self) -> &str {
        self.summary.as_deref().unwrap_or(&self.description)
    }
}

/// An operation's declared `requestBody`, reduced to what routing needs: which
/// media type to send it as, and whether the upstream demands it.
///
/// `Content-Type` is deliberately modelled here rather than as a header param:
/// it is derived from the payload, not chosen by the caller. Caller/template
/// -chosen headers keep their own channel (`ParamLocation::Header` and
/// `securitySchemes` injection), so the two mechanisms never contend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBodySpec {
    /// The media type key declared under `requestBody.content`, sent verbatim
    /// as the `Content-Type` header (e.g. `application/json`).
    pub content_type: String,
    /// The `requestBody.required` flag. Informational for routing — a body is
    /// sent whenever one is declared — but retained so validation can tell an
    /// omitted-but-required body from an omitted-and-optional one.
    #[serde(default)]
    pub required: bool,
}

impl RequestBodySpec {
    /// Whether this body is carried as JSON — `application/json` or a
    /// structured suffix like `application/vnd.api+json`. Parameters are only
    /// extracted (and bodies only serialised) for JSON media types today.
    pub fn is_json(&self) -> bool {
        let base = self
            .content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        base == "application/json" || (base.starts_with("application/") && base.ends_with("+json"))
    }
}

/// One entry in `ServiceAction::disclose`. The `filter` is a jq expression
/// applied to a `{method, url, params, body, resolved}` projection of the
/// resolved request (`resolved` carries the display names produced by
/// `resolve` declarations, so filters can prefer
/// `.resolved.fileId // .params.fileId`). `max_chars` optionally clamps long
/// string outputs (e.g. email bodies); results longer than the clamp are
/// still carried but marked `truncated` for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureField {
    pub label: String,
    pub filter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<usize>,
    /// When true, this field is rendered as a prominent "hero" value on the
    /// approval detail screen rather than collapsed into the parameter table.
    /// Multiple fields may be primary — they render in declaration order.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub primary: bool,
}

/// Describes how to resolve an opaque ID into a human-readable display name.
///
/// The resolver makes a GET request to the same service host (reusing existing auth)
/// and extracts a value from the JSON response using a dot-path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamResolver {
    /// GET endpoint path with `{param}` placeholders, e.g. `/calendar/v3/calendars/{calendarId}`.
    pub get: String,
    /// Dot-separated path into the JSON response, e.g. `summary` or `owner.login`.
    pub pick: String,
}

/// Where a parameter is sent on the wire, mirroring the OpenAPI `in:` field.
///
/// Routing consults `Query` and `Header`: on non-GET methods, query-located
/// params go to the URL query string, header-located params become request
/// headers, and everything else becomes the JSON body. A `Header` param with a
/// `default` (e.g. `Notion-Version: 2022-06-28`) is how a template pins a
/// constant version/accept header on every call — `apply_defaults` fills it in
/// when the caller omits it. `Path` is informational — path interpolation
/// matches `{name}` placeholders in the path template and never reads this field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamLocation {
    #[default]
    Body,
    Query,
    Path,
    Header,
}

impl ParamLocation {
    pub fn is_default(&self) -> bool {
        matches!(self, ParamLocation::Body)
    }
}

/// A parameter for a service action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParam {
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Optional resolver to convert an opaque ID into a human-readable name for descriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve: Option<ParamResolver>,
    /// Alternate caller-facing names for this parameter. A call that supplies
    /// one of these keys instead of the canonical name has it rewritten to the
    /// canonical name before validation (see
    /// `crate::openapi::validate_input::apply_aliases`), so a well-known
    /// synonym (`to` for `recipient`, `body` for `text`) is accepted rather
    /// than rejected as an unknown argument. Authored via the
    /// `x-overslash-aliases` (or unprefixed `aliases`) parameter extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Where this parameter is sent (body/query/path). Omitted when `body` (the default).
    #[serde(default, skip_serializing_if = "ParamLocation::is_default")]
    pub location: ParamLocation,
    /// Whether an org can pin this parameter per service instance.
    ///
    /// Some parameters are properties of a *deployment*, not of a call: which
    /// IMAP host a mailbox gateway should dial, which region an API lives in.
    /// The caller has no business supplying them on every request and an agent
    /// has no way to know them. Marking the param `x-overslash-instance-config`
    /// (or unprefixed `instance-config`) lets the dashboard render a field on
    /// the service-instance form and store the value in
    /// `service_instances.config`, which is then merged *under* the caller's
    /// args at execution time — an explicit arg still wins.
    ///
    /// Only non-secret values belong here; it is stored as plain jsonb. A
    /// secret goes in the vault and is bound via `credentials`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub instance_config: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ScopeParams ──────────────────────────────────────────────────────

    /// A template that scopes on one param must round-trip as the bare string
    /// it was authored as — otherwise adopting the list syntax would rewrite
    /// every shipped YAML on the next normalize-and-persist.
    #[test]
    fn scope_params_round_trip_a_single_bare_param() {
        let sp: ScopeParams = serde_json::from_value(serde_json::json!("repo")).unwrap();
        assert_eq!(
            sp.refs(),
            [ScopeParamRef {
                param: "repo".into(),
                label: "repo".into()
            }]
        );
        assert_eq!(
            serde_json::to_value(&sp).unwrap(),
            serde_json::json!("repo")
        );
    }

    #[test]
    fn scope_params_round_trip_a_labelled_list() {
        let authored = serde_json::json!(["to:recipient", "cc:recipient", "bcc:recipient"]);
        let sp: ScopeParams = serde_json::from_value(authored.clone()).unwrap();
        assert_eq!(
            sp.refs()
                .iter()
                .map(|r| (r.param.as_str(), r.label.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("to", "recipient"),
                ("cc", "recipient"),
                ("bcc", "recipient")
            ]
        );
        assert_eq!(serde_json::to_value(&sp).unwrap(), authored);
    }

    /// An implicit label is not written back out: `to` in, `to` out, never
    /// `to:to`.
    #[test]
    fn scope_params_omit_an_implicit_label() {
        let sp: ScopeParams = serde_json::from_value(serde_json::json!(["to", "cc"])).unwrap();
        assert_eq!(
            serde_json::to_value(&sp).unwrap(),
            serde_json::json!(["to", "cc"])
        );
    }

    #[test]
    fn scope_params_reject_malformed_entries() {
        for bad in [
            serde_json::json!("a:b:c"),
            serde_json::json!(":x"),
            serde_json::json!("to:"),
            serde_json::json!("to recipient"),
            serde_json::json!(["ok", 3]),
            serde_json::json!({ "to": "recipient" }),
        ] {
            assert!(
                serde_json::from_value::<ScopeParams>(bad.clone()).is_err(),
                "{bad} should not parse as a scope_param"
            );
        }
    }

    /// The `Secret` variant used to be `ApiKey`, serialized as `"api_key"`.
    /// The `serde(alias)` keeps templates and clients written against the old
    /// discriminant parsing; nothing else pins it, so removing the alias must
    /// break this test rather than silently break those callers.
    #[test]
    fn secret_auth_accepts_legacy_api_key_discriminant() {
        let legacy = serde_json::json!({
            "type": "api_key",
            "scheme": "mailbox",
            "default_secret_name": "mailbox_credential",
            "injection": { "as": "header", "header_name": "X-Mailbox-Auth" },
        });

        let parsed: ServiceAuth = serde_json::from_value(legacy).unwrap();
        let ServiceAuth::Secret {
            scheme,
            default_secret_name,
            ..
        } = &parsed
        else {
            panic!("legacy api_key must deserialize into ServiceAuth::Secret");
        };
        assert_eq!(scheme, "mailbox");
        assert_eq!(default_secret_name, "mailbox_credential");

        // Round-trips out under the new name, never the legacy one.
        let out = serde_json::to_value(&parsed).unwrap();
        assert_eq!(out["type"], "secret");

        // And the new discriminant parses too.
        assert!(matches!(
            serde_json::from_value::<ServiceAuth>(out).unwrap(),
            ServiceAuth::Secret { .. }
        ));
    }

    #[test]
    fn risk_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&Risk::Read).unwrap(), r#""read""#);
        assert_eq!(serde_json::to_string(&Risk::Write).unwrap(), r#""write""#);
        assert_eq!(serde_json::to_string(&Risk::Delete).unwrap(), r#""delete""#);

        assert_eq!(
            serde_json::from_str::<Risk>(r#""read""#).unwrap(),
            Risk::Read
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""write""#).unwrap(),
            Risk::Write
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""delete""#).unwrap(),
            Risk::Delete
        );
    }

    #[test]
    fn risk_default_is_read() {
        assert_eq!(Risk::default(), Risk::Read);
    }

    #[test]
    fn risk_is_mutating() {
        assert!(!Risk::Read.is_mutating());
        assert!(Risk::Write.is_mutating());
        assert!(Risk::Delete.is_mutating());
    }

    #[test]
    fn risk_from_http_method() {
        assert_eq!(Risk::from_http_method("GET"), Risk::Read);
        assert_eq!(Risk::from_http_method("HEAD"), Risk::Read);
        assert_eq!(Risk::from_http_method("OPTIONS"), Risk::Read);
        assert_eq!(Risk::from_http_method("POST"), Risk::Write);
        assert_eq!(Risk::from_http_method("PUT"), Risk::Write);
        assert_eq!(Risk::from_http_method("PATCH"), Risk::Write);
        assert_eq!(Risk::from_http_method("DELETE"), Risk::Delete);
        // case-insensitive
        assert_eq!(Risk::from_http_method("get"), Risk::Read);
        assert_eq!(Risk::from_http_method("delete"), Risk::Delete);
    }

    #[test]
    fn risk_display() {
        assert_eq!(Risk::Read.to_string(), "read");
        assert_eq!(Risk::Write.to_string(), "write");
        assert_eq!(Risk::Delete.to_string(), "delete");
    }

    // ── ParamLocation ─────────────────────────────────────────────────

    #[test]
    fn param_location_serde_roundtrip() {
        assert_eq!(
            serde_json::to_string(&ParamLocation::Body).unwrap(),
            r#""body""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Query).unwrap(),
            r#""query""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Path).unwrap(),
            r#""path""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Header).unwrap(),
            r#""header""#
        );

        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""body""#).unwrap(),
            ParamLocation::Body
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""query""#).unwrap(),
            ParamLocation::Query
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""path""#).unwrap(),
            ParamLocation::Path
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""header""#).unwrap(),
            ParamLocation::Header
        );
    }

    #[test]
    fn param_location_default_is_body() {
        assert_eq!(ParamLocation::default(), ParamLocation::Body);
        assert!(ParamLocation::Body.is_default());
        assert!(!ParamLocation::Query.is_default());
        assert!(!ParamLocation::Path.is_default());
        assert!(!ParamLocation::Header.is_default());
    }

    #[test]
    fn action_param_omits_default_location() {
        let p = ActionParam {
            param_type: "string".into(),
            required: false,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
            aliases: Vec::new(),
            location: ParamLocation::Body,
            instance_config: false,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("location").is_none());
        // Same omit-when-default contract as `location`: a param nobody pinned
        // must not grow an `instance_config: false` key in every serialized
        // template.
        assert!(json.get("instance_config").is_none());

        let q = ActionParam {
            location: ParamLocation::Query,
            ..p
        };
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["location"], "query");

        // Older serialized params without a `location` key deserialize as body.
        let legacy: ActionParam = serde_json::from_str(r#"{"type": "string"}"#).unwrap();
        assert_eq!(legacy.location, ParamLocation::Body);
    }

    // ── Runtime types ─────────────────────────────────────────────────

    #[test]
    fn runtime_default_is_http() {
        assert_eq!(Runtime::default(), Runtime::Http);
        assert!(Runtime::Http.is_default());
        assert!(!Runtime::Mcp.is_default());
        assert!(!Runtime::Platform.is_default());
    }

    #[test]
    fn runtime_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&Runtime::Http).unwrap(), r#""http""#);
        assert_eq!(serde_json::to_string(&Runtime::Mcp).unwrap(), r#""mcp""#);
        assert_eq!(
            serde_json::to_string(&Runtime::Platform).unwrap(),
            r#""platform""#
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""http""#).unwrap(),
            Runtime::Http
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""mcp""#).unwrap(),
            Runtime::Mcp
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""platform""#).unwrap(),
            Runtime::Platform
        );
    }

    // ── MCP types ────────────────────────────────────────────────────

    #[test]
    fn mcp_auth_none_serde() {
        let j = serde_json::to_value(McpAuth::None).unwrap();
        assert_eq!(j, serde_json::json!({ "kind": "none" }));
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, McpAuth::None);
    }

    #[test]
    fn mcp_auth_bearer_serde() {
        let a = McpAuth::Bearer {
            secret_name: Some("linear_token".into()),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(
            j,
            serde_json::json!({ "kind": "bearer", "secret_name": "linear_token" })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_bearer_without_secret_name_serde() {
        let a = McpAuth::Bearer { secret_name: None };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j, serde_json::json!({ "kind": "bearer" }));
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_oauth_serde() {
        let a = McpAuth::OAuth {
            provider: "hubspot".into(),
            scopes: vec!["crm.objects.contacts.read".into()],
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(
            j,
            serde_json::json!({
                "kind": "oauth",
                "provider": "hubspot",
                "scopes": ["crm.objects.contacts.read"]
            })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_oauth_without_scopes_serde() {
        let a = McpAuth::OAuth {
            provider: "hubspot".into(),
            scopes: vec![],
        };
        let j = serde_json::to_value(&a).unwrap();
        // Empty scopes are elided; still round-trips.
        assert_eq!(
            j,
            serde_json::json!({ "kind": "oauth", "provider": "hubspot" })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_unknown_kind_rejected() {
        // Forward-compat spec: new variants in the enum are additions; *unknown*
        // variants must fail deserialization cleanly so callers know to upgrade.
        let v = serde_json::json!({ "kind": "quantum", "secret_name": "x" });
        assert!(serde_json::from_value::<McpAuth>(v).is_err());
    }

    #[test]
    fn mcp_spec_autodiscover_defaults_true() {
        // Omitting autodiscover should default to true.
        let v = serde_json::json!({
            "url": "https://mcp.example.com/mcp",
            "auth": { "kind": "none" }
        });
        let spec: McpSpec = serde_json::from_value(v).unwrap();
        assert!(spec.autodiscover);
        assert_eq!(spec.url.as_deref(), Some("https://mcp.example.com/mcp"));
        assert_eq!(spec.auth, McpAuth::None);
    }

    #[test]
    fn service_definition_http_defaults_keep_mcp_absent() {
        // Existing Http templates must serialize without runtime/mcp keys.
        let svc = ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "slack".into(),
            display_name: "Slack".into(),
            description: None,
            hosts: vec!["slack.com".into()],
            category: None,
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        };
        let j = serde_json::to_value(&svc).unwrap();
        assert!(
            j.get("runtime").is_none(),
            "runtime must be elided when Http"
        );
        assert!(j.get("mcp").is_none(), "mcp must be elided when absent");
    }

    #[test]
    fn service_definition_mcp_roundtrip() {
        let mut actions = HashMap::new();
        actions.insert(
            "search_issues".into(),
            ServiceAction {
                method: "".into(),
                path: "".into(),
                description: "Search issues".into(),
                summary: None,
                risk: Risk::Read,
                response_type: None,
                params: HashMap::new(),
                scope_param: "team".into(),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: Some("search_issues".into()),
                output_schema: Some(serde_json::json!({ "type": "object" })),
                disabled: false,
                request_body: None,
            },
        );
        let svc = ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: Some("Development".into()),
            hidden: false,
            auth: vec![],
            actions,
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.linear.app/mcp".into()),
                auth: McpAuth::Bearer {
                    secret_name: Some("linear_api_token".into()),
                },
                autodiscover: true,
            }),
            instance_defaults: None,
        };
        let j = serde_json::to_value(&svc).unwrap();
        assert_eq!(j["runtime"], "mcp");
        assert_eq!(j["mcp"]["url"], "https://mcp.linear.app/mcp");
        assert_eq!(j["mcp"]["auth"]["kind"], "bearer");
        let back: ServiceDefinition = serde_json::from_value(j).unwrap();
        assert_eq!(back.runtime, Runtime::Mcp);
        let mcp = back.mcp.expect("mcp present");
        assert!(mcp.autodiscover);
        assert_eq!(
            mcp.auth,
            McpAuth::Bearer {
                secret_name: Some("linear_api_token".into())
            }
        );
        let a = &back.actions["search_issues"];
        assert_eq!(a.mcp_tool.as_deref(), Some("search_issues"));
        assert!(!a.disabled);
        assert!(a.output_schema.is_some());
    }

    #[test]
    fn service_action_disabled_elided_when_false() {
        let a = ServiceAction {
            method: "GET".into(),
            path: "/foo".into(),
            description: "x".into(),
            summary: None,
            risk: Risk::Read,
            response_type: None,
            params: HashMap::new(),
            scope_param: Default::default(),
            required_scopes: vec![],
            permission: None,
            disclose: vec![],
            redact: vec![],
            mcp_tool: None,
            output_schema: None,
            disabled: false,
            request_body: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("disabled").is_none());
        assert!(j.get("mcp_tool").is_none());
        assert!(j.get("output_schema").is_none());
    }
}
