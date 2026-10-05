//! The org-vault half of the read rule: where an org secret may go.
//!
//! The vault rule ([`readable_instance_binding`](super::readable_instance_binding))
//! lets a user-level instance read the org vault. But an org secret (an
//! overfwd gateway key, an OAuth app's client secret) is meant for the host
//! the *org* chose for it, and a user-level instance's destination is the
//! owner's to choose: its `url` (D115 makes every endpoint overridable), a
//! user-tier template's `servers`, a user layer's `instance_defaults.url`.
//! Reading the org vault from such an instance would hand the org's secret to
//! a host of the owner's choosing.
//!
//! So a user-level instance reads the org vault only when its request lands
//! on the base the org-or-global tier of its template declares, and only for
//! the slots *that* tier sources from the org — with *that* tier's default
//! name. An org-level instance is unaffected: only an admin configures it.

use std::collections::BTreeMap;

use overslash_core::registry::ServiceRegistry;
use overslash_core::types::{SecretSource, ServiceDefinition};
use overslash_db::repos::service_instance::ServiceInstanceRow;
use sqlx::PgPool;

use crate::error::AppError;

/// Which org-vault reads a request through one instance may make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgVaultGate {
    /// An org-level instance: everything the vault rule allows.
    Open,
    /// A user-level instance whose request lands where the org/global tier
    /// of its template points: that tier's org-source slots, slot key →
    /// the tier's own `default_secret_name`.
    Slots(BTreeMap<String, String>),
    /// The owner chose the destination; no org secret goes there.
    Closed,
}

impl OrgVaultGate {
    /// The gate for a request through `instance` that lands on `lands` — the
    /// base the executor will dial, derived by the caller from the instance
    /// and its owner's template. `base_of` is that same derivation, applied
    /// here to the org/global tier with no instance, so the two can't
    /// disagree about what "the template's own base" means.
    pub async fn for_instance(
        db: &PgPool,
        registry: &ServiceRegistry,
        instance: &ServiceInstanceRow,
        lands: Option<&str>,
        base_of: impl Fn(Option<&ServiceInstanceRow>, &ServiceDefinition) -> Option<String>,
    ) -> Result<Self, AppError> {
        if instance.owner_identity_id.is_none() {
            return Ok(Self::Open);
        }
        // The template as the org sees it: org tier → global, never a user
        // layer. A key only a user tier defines has no org-sanctioned host.
        let trusted = match crate::services::template_resolve::resolve_definition(
            db,
            registry,
            instance.org_id,
            None,
            &instance.template_key,
        )
        .await
        {
            Ok(def) => def,
            Err(AppError::NotFound(_)) => return Ok(Self::Closed),
            Err(e) => return Err(e),
        };
        if lands.is_none() || lands != base_of(None, &trusted).as_deref() {
            return Ok(Self::Closed);
        }
        Ok(Self::Slots(
            trusted
                .secrets
                .iter()
                .filter(|s| s.source == SecretSource::Org)
                .map(|s| (s.key.clone(), s.default_secret_name.clone()))
                .collect(),
        ))
    }

    /// May a binding on `slot` (`None`: a binding not tied to an org-source
    /// slot, such as an MCP bearer or a legacy scalar) name the org vault?
    pub fn admits(&self, slot: Option<&str>) -> bool {
        match self {
            Self::Open => true,
            Self::Slots(slots) => slot.is_some_and(|k| slots.contains_key(k)),
            Self::Closed => false,
        }
    }

    /// The org-vault name an *unbound* org-source `slot` falls back to —
    /// the org/global tier's default, not the owner's template's — or `None`
    /// when the gate refuses it. `own_default` is the name an org-level
    /// instance (gate `Open`) uses.
    pub fn org_default<'a>(&'a self, slot: &str, own_default: &'a str) -> Option<&'a str> {
        match self {
            Self::Open => Some(own_default),
            Self::Slots(slots) => slots.get(slot).map(String::as_str),
            Self::Closed => None,
        }
    }
}
