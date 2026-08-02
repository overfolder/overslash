use serde::{Deserialize, Serialize};

use crate::types::CredentialTemplate;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
