//! The `x-overslash-*` extension vocabulary, and the only way to read one.
//!
//! Every extension key has a canonical spelling ([`Ext::key`]) and a set of
//! document positions whose extractor actually reads it ([`READS`]). Those two
//! facts used to live only in the extractors themselves, as ~30 inline
//! `obj.get("x-overslash-…")` calls, which made "is this key read here?"
//! answerable only by grepping. [`lint`](super::lint) needs that question
//! answered mechanically, so this module owns it.
//!
//! ## Why the accessor exists
//!
//! A position table maintained *next to* the readers is a second source of
//! truth, and it drifts silently in the dangerous direction: the table claims a
//! key is read somewhere it isn't, so the lint blesses exactly the no-op it was
//! built to catch. Routing every read through [`get`] closes that off — the
//! `debug_assert!` fires in the new key's own unit test if its `READS` entry is
//! missing, rather than emitting a spurious warning on a correct template
//! months later. `no_extension_getter_bypasses_this_module` holds the line.
//!
//! Two real instances of that drift were found while writing this, both now
//! encoded below: `x-overslash-template` / `-secret_source` / `-optional` are
//! normalized onto `type: http` security schemes but read only on `apiKey`, and
//! `x-overslash-disclose` / `-redact` / `-timeout_ms` are normalized onto
//! platform actions that never read them.
//!
//! `READS` is the **reader** map, deliberately not the **normalizer** map in
//! [`alias`](super::alias). Where the two disagree, the disagreement is a bug in
//! the template, and the lint is what says so.

use serde_json::{Map, Value};

/// The canonical `x-overslash-*` prefix. An unprefixed alias is rewritten to
/// this form by [`normalize_aliases`](super::normalize_aliases) before anything
/// here runs.
pub(super) const PREFIX: &str = "x-overslash-";

/// One `x-overslash-*` extension key.
///
/// Names that appear in design docs but have no reader are deliberately absent
/// — `transform`, `fixed-params`, `map`, `arg_map`, `body-path`, `sql`,
/// `default-scopes`. So are the HTTP header names that share the prefix
/// (`x-overslash-as`, `-transport`, `-signature`, `-idp-variant`): they are
/// request metadata, never document keys, and writing one into a template is a
/// mistake the lint should name.
///
/// `prefix` and `encode` are also absent. D35 replaced them with
/// [`Ext::Template`], and `extract_api_key` still rejects them by name with a
/// message quoting the jq replacement — a better error than the lint's, so the
/// lint steps aside for them (see `lint::LEGACY_SUPPRESSED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext {
    // Document root
    Runtime,
    Mcp,
    PlatformActions,
    // info
    Key,
    Category,
    Hidden,
    Icon,
    DefaultTimeoutMs,
    // Operations, MCP tools, platform actions
    Risk,
    ScopeParam,
    Disclose,
    Redact,
    TimeoutMs,
    WaitMode,
    HandoffAfterMs,
    Download,
    Upload,
    Pagination,
    // Parameters, body properties, tool properties, platform-action params
    Resolve,
    Aliases,
    InstanceConfig,
    SqlField,
    SqlDatabase,
    // components
    Secrets,
    Config,
    // components.securitySchemes.*
    Provider,
    TokenInjection,
    DefaultSecretName,
    Template,
    SecretSource,
    Optional,
    Label,
}

impl Ext {
    /// The canonical, prefixed spelling as it appears in a document.
    pub fn key(self) -> &'static str {
        match self {
            Ext::Runtime => "x-overslash-runtime",
            Ext::Mcp => "x-overslash-mcp",
            Ext::PlatformActions => "x-overslash-platform_actions",
            Ext::Key => "x-overslash-key",
            Ext::Category => "x-overslash-category",
            Ext::Hidden => "x-overslash-hidden",
            Ext::Icon => "x-overslash-icon",
            Ext::DefaultTimeoutMs => "x-overslash-default_timeout_ms",
            Ext::Risk => "x-overslash-risk",
            Ext::ScopeParam => "x-overslash-scope_param",
            Ext::Disclose => "x-overslash-disclose",
            Ext::Redact => "x-overslash-redact",
            Ext::TimeoutMs => "x-overslash-timeout_ms",
            Ext::WaitMode => "x-overslash-wait-mode",
            Ext::HandoffAfterMs => "x-overslash-handoff_after_ms",
            Ext::Download => "x-overslash-download",
            Ext::Upload => "x-overslash-upload",
            Ext::Pagination => "x-overslash-pagination",
            Ext::Resolve => "x-overslash-resolve",
            Ext::Aliases => "x-overslash-aliases",
            Ext::InstanceConfig => "x-overslash-instance-config",
            Ext::SqlField => "x-overslash-sql-field",
            Ext::SqlDatabase => "x-overslash-sql-database",
            Ext::Secrets => "x-overslash-secrets",
            Ext::Config => "x-overslash-config",
            Ext::Provider => "x-overslash-provider",
            Ext::TokenInjection => "x-overslash-token_injection",
            Ext::DefaultSecretName => "x-overslash-default_secret_name",
            Ext::Template => "x-overslash-template",
            Ext::SecretSource => "x-overslash-secret_source",
            Ext::Optional => "x-overslash-optional",
            Ext::Label => "x-overslash-label",
        }
    }

    /// Resolve a canonical key back to its variant. `None` means the document
    /// wrote an `x-overslash-*` key nothing in the gateway has ever read.
    pub(super) fn from_key(key: &str) -> Option<Self> {
        ALL.iter().copied().find(|e| e.key() == key)
    }

    /// Every position whose extractor reads this key, for the lint's
    /// "reads at" message.
    pub(super) fn positions(self) -> &'static [Pos] {
        READS
            .iter()
            .find(|(e, _)| *e == self)
            .map(|(_, p)| *p)
            .unwrap_or(&[])
    }
}

/// Every variant, so the lint can resolve and suggest names without a second
/// list to keep in step.
pub(super) const ALL: &[Ext] = &[
    Ext::Runtime,
    Ext::Mcp,
    Ext::PlatformActions,
    Ext::Key,
    Ext::Category,
    Ext::Hidden,
    Ext::Icon,
    Ext::DefaultTimeoutMs,
    Ext::Risk,
    Ext::ScopeParam,
    Ext::Disclose,
    Ext::Redact,
    Ext::TimeoutMs,
    Ext::WaitMode,
    Ext::HandoffAfterMs,
    Ext::Download,
    Ext::Upload,
    Ext::Pagination,
    Ext::Resolve,
    Ext::Aliases,
    Ext::InstanceConfig,
    Ext::SqlField,
    Ext::SqlDatabase,
    Ext::Secrets,
    Ext::Config,
    Ext::Provider,
    Ext::TokenInjection,
    Ext::DefaultSecretName,
    Ext::Template,
    Ext::SecretSource,
    Ext::Optional,
    Ext::Label,
];

/// A security scheme's `type`, which decides which extensions apply. Kept
/// separate from [`Pos`] rather than flattened into three variants so the
/// scheme-dispatch in `extract::auth` and the position map read alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeKind {
    Oauth2,
    ApiKey,
    Http,
    /// A `type` the compiler rejects. No extension applies, and the lint stays
    /// open-world here rather than piling warnings on top of the real error.
    Unknown,
}

impl SchemeKind {
    /// Classify a security scheme object by its `type`. Mirrors the dispatch in
    /// `extract::auth::extract_auth`.
    pub(super) fn of(scheme: &Map<String, Value>) -> Self {
        match scheme.get("type").and_then(Value::as_str) {
            Some("oauth2") => SchemeKind::Oauth2,
            Some("apiKey") => SchemeKind::ApiKey,
            Some("http") => SchemeKind::Http,
            _ => SchemeKind::Unknown,
        }
    }
}

/// A position in a template document that the compiler interprets.
///
/// `Other` is everything else — a `components.schemas` subtree, a `responses`
/// entry, a nested schema property. No extension is read there, which is
/// precisely why an `x-overslash-*` key landing in one is worth reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pos {
    Root,
    Info,
    PathItem,
    Operation,
    /// A `parameters[]` entry, at path-item or operation level.
    Parameter,
    /// `requestBody.content.*.schema.properties.*`.
    BodyProperty,
    Components,
    SecurityScheme(SchemeKind),
    McpBlock,
    McpAuth,
    /// An authored `x-overslash-mcp.tools[]` entry.
    McpTool,
    /// An `x-overslash-mcp.discovered_tools[]` entry — a pasted `tools/list`
    /// snapshot. Same extensions as [`Pos::McpTool`], but open-world for plain
    /// keys because it mirrors the MCP wire shape.
    McpToolDiscovered,
    /// A tool's `input_schema.properties.*`.
    McpToolProperty,
    PlatformAction,
    PlatformActionParam,
    Other,
}

impl Pos {
    /// Human phrasing for a lint message, reading as "… is not read on an
    /// operation" / "… is read on an MCP tool".
    pub(super) fn describe(self) -> &'static str {
        match self {
            Pos::Root => "the document root",
            Pos::Info => "`info`",
            Pos::PathItem => "a path item",
            Pos::Operation => "an operation",
            Pos::Parameter => "a `parameters[]` entry",
            Pos::BodyProperty => "a request-body schema property",
            Pos::Components => "`components`",
            Pos::SecurityScheme(SchemeKind::Oauth2) => "an `oauth2` security scheme",
            Pos::SecurityScheme(SchemeKind::ApiKey) => "an `apiKey` security scheme",
            Pos::SecurityScheme(SchemeKind::Http) => "an `http` security scheme",
            Pos::SecurityScheme(SchemeKind::Unknown) => "a security scheme",
            Pos::McpBlock => "the `x-overslash-mcp` block",
            Pos::McpAuth => "`x-overslash-mcp.auth`",
            Pos::McpTool | Pos::McpToolDiscovered => "an MCP tool",
            Pos::McpToolProperty => "an MCP tool input-schema property",
            Pos::PlatformAction => "a platform action",
            Pos::PlatformActionParam => "a platform-action param",
            Pos::Other => "this position",
        }
    }
}

/// Which positions read each extension — the authoritative answer to "position
/// matters, not just spelling".
///
/// Each entry cites the reader it records. A variant absent from this table is
/// read nowhere, and [`get`] will refuse it in debug builds.
pub(super) const READS: &[(Ext, &[Pos])] = &[
    // compile.rs:165, mcp.rs:22, compile.rs:142
    (Ext::Runtime, &[Pos::Root]),
    (Ext::Mcp, &[Pos::Root]),
    (Ext::PlatformActions, &[Pos::Root]),
    // compile.rs:46,63,67,86
    (Ext::Key, &[Pos::Info]),
    (Ext::Category, &[Pos::Info]),
    (Ext::Hidden, &[Pos::Info]),
    // compile.rs:94
    (Ext::Icon, &[Pos::Info]),
    (Ext::DefaultTimeoutMs, &[Pos::Info]),
    // actions.rs:85,184 · mcp.rs:268
    (
        Ext::Risk,
        &[
            Pos::Operation,
            Pos::McpTool,
            Pos::McpToolDiscovered,
            Pos::PlatformAction,
        ],
    ),
    // actions.rs:105,211 · mcp.rs:292
    (
        Ext::ScopeParam,
        &[
            Pos::Operation,
            Pos::McpTool,
            Pos::McpToolDiscovered,
            Pos::PlatformAction,
        ],
    ),
    // actions.rs:132 · mcp.rs:317. NOT on a platform action: `extract_platform_
    // action` never reads it, though OPERATION_ALIASES normalizes it there.
    (
        Ext::Disclose,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    // actions.rs:133 · mcp.rs:318. Same platform-action caveat.
    (
        Ext::Redact,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    // actions.rs:135 · mcp.rs:321. Same platform-action caveat.
    (
        Ext::TimeoutMs,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    // actions.rs · mcp.rs. The D62/D68 execution mode as a template *default*,
    // read wherever an action is authored. NOT on a platform action:
    // `validate_resolved` refuses every deferred mode on `runtime: platform`,
    // so the key would normalize there (OPERATION_ALIASES) and then decide
    // nothing — the same asymmetry `disclose` / `redact` / `timeout_ms` carry
    // one entry up, and for a sharper reason: here the reader exists but its
    // answer is discarded downstream, which is exactly the no-op the lint is
    // for.
    (
        Ext::WaitMode,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    (
        Ext::HandoffAfterMs,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    // mcp.rs:319. MCP-only by design: an HTTP action that returns bytes already
    // is its own download, since `deliver: "url"` mints a token from the
    // resolved request (see the comment at actions.rs:160).
    (Ext::Download, &[Pos::McpTool, Pos::McpToolDiscovered]),
    // mcp.rs. Same positions as Download, for a sharper reason: the block names
    // a *route on the MCP origin*, which exists only because an MCP instance
    // URL does. `McpToolDiscovered` is required even though a discovered entry
    // never authors one — `lower_mcp_tool` is shared with
    // `overlay_discovered_tools`, so the read genuinely happens at that
    // position after the merge, and omitting it fires the `debug_assert!` in
    // `get` from the overlay path.
    (Ext::Upload, &[Pos::McpTool, Pos::McpToolDiscovered]),
    // actions.rs · mcp.rs. Wherever an action is authored, minus the platform
    // runtime: a platform action answers from this process, so there is no
    // upstream page to be on. `NextStyle::Link` is refused at `Pos::McpTool`
    // for a narrower reason — an MCP tool result carries no response headers,
    // so a Link-styled continuation there would parse and then find nothing.
    (
        Ext::Pagination,
        &[Pos::Operation, Pos::McpTool, Pos::McpToolDiscovered],
    ),
    // params.rs:31,129 · mcp.rs:436. NOT on a platform-action param:
    // `parse_platform_params` reads the other four and no resolver.
    (
        Ext::Resolve,
        &[Pos::Parameter, Pos::BodyProperty, Pos::McpToolProperty],
    ),
    // params.rs:32,131 · mcp.rs:430 · actions.rs:250
    (
        Ext::Aliases,
        &[
            Pos::Parameter,
            Pos::BodyProperty,
            Pos::McpToolProperty,
            Pos::PlatformActionParam,
        ],
    ),
    // params.rs:41,132 · mcp.rs:431 · actions.rs:251
    (
        Ext::InstanceConfig,
        &[
            Pos::Parameter,
            Pos::BodyProperty,
            Pos::McpToolProperty,
            Pos::PlatformActionParam,
        ],
    ),
    // params.rs:42,133 · mcp.rs:432 · actions.rs:252
    (
        Ext::SqlField,
        &[
            Pos::Parameter,
            Pos::BodyProperty,
            Pos::McpToolProperty,
            Pos::PlatformActionParam,
        ],
    ),
    (
        Ext::SqlDatabase,
        &[
            Pos::Parameter,
            Pos::BodyProperty,
            Pos::McpToolProperty,
            Pos::PlatformActionParam,
        ],
    ),
    // auth.rs:286,213
    (Ext::Secrets, &[Pos::Components]),
    (Ext::Config, &[Pos::Components]),
    // schemes.rs:16,42
    (Ext::Provider, &[Pos::SecurityScheme(SchemeKind::Oauth2)]),
    (
        Ext::TokenInjection,
        &[Pos::SecurityScheme(SchemeKind::Oauth2)],
    ),
    // schemes.rs:68,190 — the two keys `extract_http_auth` shares with apiKey.
    (
        Ext::DefaultSecretName,
        &[
            Pos::SecurityScheme(SchemeKind::ApiKey),
            Pos::SecurityScheme(SchemeKind::Http),
        ],
    ),
    // schemes.rs:148,197
    (
        Ext::Label,
        &[
            Pos::SecurityScheme(SchemeKind::ApiKey),
            Pos::SecurityScheme(SchemeKind::Http),
        ],
    ),
    // schemes.rs:95,102,114 — apiKey only. On an `http` scheme the template is
    // generated (schemes.rs:213), `secret_source` is hardcoded `Instance` and
    // `optional` hardcoded `false`, so all three normalize cleanly and then do
    // nothing. APIKEY_SEC_ALIASES/HTTP_SEC_ALIASES are split so the normalizer
    // no longer rewrites them onto an `http` scheme either.
    (Ext::Template, &[Pos::SecurityScheme(SchemeKind::ApiKey)]),
    (
        Ext::SecretSource,
        &[Pos::SecurityScheme(SchemeKind::ApiKey)],
    ),
    (Ext::Optional, &[Pos::SecurityScheme(SchemeKind::ApiKey)]),
];

/// Whether `ext` is read at `pos`.
pub(super) fn reads_at(ext: Ext, pos: Pos) -> bool {
    READS
        .iter()
        .any(|(e, positions)| *e == ext && positions.contains(&pos))
}

/// Read `ext` off an object standing at `pos`.
///
/// The `debug_assert!` is the drift guard described in the module docs: a reader
/// that forgets its [`READS`] entry fails in its own tests instead of teaching
/// the lint to warn about a correctly-authored template.
pub(super) fn get(obj: &Map<String, Value>, pos: Pos, ext: Ext) -> Option<&Value> {
    debug_assert!(
        reads_at(ext, pos),
        "{ext:?} is read at {pos:?} but ext::READS does not record it; add the position",
    );
    obj.get(ext.key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_is_in_all() {
        // `ALL` drives name resolution and did-you-mean suggestions, so a
        // variant missing from it is invisible to the lint.
        assert_eq!(ALL.len(), 32, "ALL has drifted from the enum");
        let mut keys: Vec<&str> = ALL.iter().map(|e| e.key()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "two variants share a key");
    }

    #[test]
    fn every_key_carries_the_prefix() {
        for e in ALL {
            assert!(e.key().starts_with(PREFIX), "{e:?} is not prefixed");
        }
    }

    #[test]
    fn from_key_round_trips() {
        for e in ALL {
            assert_eq!(Ext::from_key(e.key()), Some(*e));
        }
        assert_eq!(Ext::from_key("x-overslash-transform"), None);
        assert_eq!(Ext::from_key("x-overslash-prefix"), None);
        assert_eq!(
            Ext::from_key("risk"),
            None,
            "aliases are not canonical keys"
        );
    }

    #[test]
    fn every_variant_is_read_somewhere() {
        // A variant with no position is a key the gateway never reads, which
        // makes it a lint finding rather than a vocabulary entry.
        for e in ALL {
            assert!(
                !e.positions().is_empty(),
                "{e:?} is in the vocabulary but READS gives it no position",
            );
        }
    }

    #[test]
    fn position_asymmetries_are_recorded() {
        // These four are the whole point of a position-aware table: each one
        // normalizes at a position that then ignores it.
        assert!(!reads_at(Ext::Download, Pos::Operation));
        assert!(reads_at(Ext::Download, Pos::McpTool));
        // Upload rides the same MCP-only positions as Download: the route it
        // names only exists because an MCP instance URL does.
        assert!(!reads_at(Ext::Upload, Pos::Operation));
        assert!(reads_at(Ext::Upload, Pos::McpTool));
        assert!(!reads_at(
            Ext::Template,
            Pos::SecurityScheme(SchemeKind::Http)
        ));
        assert!(reads_at(
            Ext::Template,
            Pos::SecurityScheme(SchemeKind::ApiKey)
        ));
        assert!(!reads_at(Ext::Disclose, Pos::PlatformAction));
        assert!(!reads_at(Ext::WaitMode, Pos::PlatformAction));
        assert!(!reads_at(Ext::HandoffAfterMs, Pos::PlatformAction));
        assert!(reads_at(Ext::WaitMode, Pos::Operation));
        assert!(!reads_at(Ext::Resolve, Pos::PlatformActionParam));
        assert!(reads_at(Ext::Aliases, Pos::PlatformActionParam));
    }

    #[test]
    fn nothing_is_read_at_other() {
        // `Pos::Other` is what the walk degrades to, so the lint's "stray key"
        // rule is just `reads_at(_, Other) == false` for everything.
        for e in ALL {
            assert!(
                !reads_at(*e, Pos::Other),
                "{e:?} claims to be read at Other"
            );
        }
    }

    #[test]
    fn scheme_kind_classifies_by_type() {
        let of = |t: &str| {
            let v = serde_json::json!({"type": t});
            SchemeKind::of(v.as_object().unwrap())
        };
        assert_eq!(of("oauth2"), SchemeKind::Oauth2);
        assert_eq!(of("apiKey"), SchemeKind::ApiKey);
        assert_eq!(of("http"), SchemeKind::Http);
        assert_eq!(of("openIdConnect"), SchemeKind::Unknown);
        // A scheme with no `type` at all: the compiler errors on it, and the
        // lint must not pile on.
        assert_eq!(SchemeKind::of(&Map::new()), SchemeKind::Unknown);
    }

    #[test]
    #[should_panic(expected = "ext::READS does not record it")]
    fn get_at_an_unrecorded_position_panics_in_debug() {
        // The drift guard itself. A reader added without its READS entry fails
        // here rather than mislabelling a correct template later.
        let obj = serde_json::json!({"x-overslash-download": {}});
        let _ = get(obj.as_object().unwrap(), Pos::Operation, Ext::Download);
    }
}
