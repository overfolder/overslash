//! The layered-template **fold walker** — the one place that resolves a
//! template key to its effective [`ServiceDefinition`].
//!
//! `resolve(layer) = apply(layer.delta, resolve(layer.extends))`. This module
//! owns the recursive, I/O-bearing half (fetch base rows / the global registry,
//! detect cycles); the pure algebra lives in
//! [`overslash_core::service_layer`]. It unifies what used to be two duplicate
//! `resolve_template_definition` functions (routes + platform kernels) so
//! discovery, instantiation, and **execution** all read the same effective
//! surface — a masked-out action then vanishes everywhere for free.
//!
//! ## Lookup rules
//!
//! - **Top layer:** the requested key resolves user → org → global (today's
//!   user-shadows-org precedence).
//! - **Base of a derived layer** (`resolve_base`): decoupled key vs extends —
//!   - `extends == layer.key` (shadow-with-delta) → resolve **strictly above**
//!     the layer's own tier (a user layer folds over the org/global of the same
//!     key; an org layer folds over the global) so it never re-selects itself.
//!   - `extends != layer.key` (distinct catalog entry) → standard user → org →
//!     global precedence for `extends`.
//! - Cycles (`A → B → A` via same-tier extends) are rejected by tracking
//!   visited row ids.
//!
//! Resolution is **on-demand** (no persistent resolved-template cache in v1),
//! so a change to any base propagates to descendants immediately and resolution
//! warnings recompute on every read.

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use overslash_core::openapi;
use overslash_core::registry::ServiceRegistry;
use overslash_core::service_layer::{Delta, apply_delta};
use overslash_core::template_validation::ValidationIssue;
use overslash_core::types::ServiceDefinition;
use overslash_db::repos::service_template::{self, ServiceTemplateRow};

use crate::error::AppError;

/// The effective template plus the non-blocking resolution warnings computed
/// during the fold (`shadowed_extension`, `dead_*`, `unreviewed_new_actions`).
pub struct Resolved {
    pub definition: ServiceDefinition,
    pub warnings: Vec<ValidationIssue>,
}

/// Resolve a template key to its effective definition + resolution report.
///
/// `identity_id` selects the user tier for the top-level lookup and for
/// distinct-key base lookups; pass `None` for org-scoped (identity-less) callers.
pub async fn resolve(
    db: &PgPool,
    registry: &ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<Resolved, AppError> {
    let mut warnings = Vec::new();
    let mut visited: HashSet<Uuid> = HashSet::new();
    // Deltas, collected top layer first. Folded base-first (reverse) at the end.
    let mut deltas: Vec<Delta> = Vec::new();

    // Locate the top layer for the requested key.
    let mut cur = lookup_layer(db, org_id, identity_id, key).await?;

    let base_def: ServiceDefinition = loop {
        let Some(row) = cur else {
            // Reachable only on the first iteration (the top-level lookup found
            // no row at any tier) → the requested key is a global template.
            // Every derived-base miss is handled inline by the `Some(ext)` arm.
            break registry
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("template '{key}' not found")))?;
        };

        if !visited.insert(row.id) {
            return Err(AppError::Internal(format!(
                "template inheritance cycle detected while resolving '{key}'"
            )));
        }

        match &row.extends {
            None => {
                // Standalone layer — the base case. The shape CHECK guarantees
                // `openapi` is present whenever `extends IS NULL`.
                let doc = row.openapi.as_ref().ok_or_else(|| {
                    AppError::Internal(format!(
                        "standalone template '{}' has no openapi document",
                        row.key
                    ))
                })?;
                // Expand `${VAR}` here rather than at persist time: the stored
                // document keeps its references, so the same row resolves to
                // this deployment's hosts instead of whichever deployment the
                // author happened to be on.
                let mut doc = doc.clone();
                overslash_core::template_vars::expand(&mut doc, registry.vars()).map_err(
                    |errs| {
                        AppError::Internal(format!(
                            "stored openapi for '{}' has unresolved template variables: {errs:?}",
                            row.key
                        ))
                    },
                )?;
                let (def, _w) = openapi::compile_service(&doc).map_err(|errs| {
                    AppError::Internal(format!(
                        "stored openapi for '{}' failed to compile: {errs:?}",
                        row.key
                    ))
                })?;
                break def;
            }
            Some(ext) => {
                let delta: Delta = serde_json::from_value(row.delta.clone().unwrap_or_default())
                    .map_err(|e| {
                        AppError::Internal(format!(
                            "stored delta for '{}' is malformed: {e}",
                            row.key
                        ))
                    })?;
                let ext_key = ext.clone();
                let row_key = row.key.clone();
                let row_is_user = row.owner_identity_id.is_some();
                deltas.push(delta);
                match resolve_base(db, org_id, identity_id, row_is_user, &row_key, &ext_key).await?
                {
                    Some(base_row) => cur = Some(base_row),
                    None => {
                        // Base is a global registry template named `ext_key`.
                        break registry.get(&ext_key).cloned().ok_or_else(|| {
                            AppError::NotFound(format!(
                                "base template '{ext_key}' (extended by '{row_key}') not found"
                            ))
                        })?;
                    }
                }
            }
        }
    };

    // Fold: apply each delta onto the previous layer's output, base-first.
    let mut def = base_def;
    for delta in deltas.iter().rev() {
        let (next, mut w) = apply_delta(delta, &def);
        def = next;
        warnings.append(&mut w);
    }
    // The effective template surfaces under the requested key (a distinct-key
    // derived layer under its own key; a same-key layer keeps shadowing).
    def.key = key.to_string();

    Ok(Resolved {
        definition: def,
        warnings,
    })
}

/// Resolve a stored row to its effective definition + warnings. Handy for
/// list/detail handlers that already hold the row: a standalone row compiles
/// directly, a derived row folds over its base. Resolves in the row's own tier
/// (`owner_identity_id` selects user vs org).
pub async fn resolve_row(
    db: &PgPool,
    registry: &ServiceRegistry,
    row: &ServiceTemplateRow,
) -> Result<Resolved, AppError> {
    resolve(db, registry, row.org_id, row.owner_identity_id, &row.key).await
}

/// Convenience wrapper for the many call sites that only need the definition.
pub async fn resolve_definition(
    db: &PgPool,
    registry: &ServiceRegistry,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<ServiceDefinition, AppError> {
    Ok(resolve(db, registry, org_id, identity_id, key)
        .await?
        .definition)
}

/// Top-level layer lookup: user tier (if identity) → org tier → None (global).
async fn lookup_layer(
    db: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    key: &str,
) -> Result<Option<ServiceTemplateRow>, AppError> {
    if let Some(id) = identity_id
        && let Some(row) = service_template::get_by_key(db, org_id, Some(id), key).await?
    {
        return Ok(Some(row));
    }
    Ok(service_template::get_by_key(db, org_id, None, key).await?)
}

/// Resolve the base row a derived layer `extends`. `None` means "the base is a
/// global registry template named `ext_key`" (the terminal case).
async fn resolve_base(
    db: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    layer_is_user: bool,
    layer_key: &str,
    ext_key: &str,
) -> Result<Option<ServiceTemplateRow>, AppError> {
    if ext_key == layer_key {
        // Shadow-with-delta: resolve strictly ABOVE the layer's own tier so it
        // never re-selects itself.
        if layer_is_user
            && let Some(org_row) = service_template::get_by_key(db, org_id, None, ext_key).await?
        {
            return Ok(Some(org_row));
        }
        // An org-tier layer (or a user layer with no org row) folds over global.
        Ok(None)
    } else {
        // Distinct key: standard user → org → global precedence.
        if let Some(id) = identity_id
            && let Some(user_row) =
                service_template::get_by_key(db, org_id, Some(id), ext_key).await?
        {
            return Ok(Some(user_row));
        }
        if let Some(org_row) = service_template::get_by_key(db, org_id, None, ext_key).await? {
            return Ok(Some(org_row));
        }
        Ok(None)
    }
}

/// The DB row id that a layer's `extends` **actually** resolves to (its direct
/// base), or `None` if it resolves to a global registry template or the layer
/// is standalone. Lets the delete guard identify *real* dependents precisely —
/// rows that merely share the `extends` key but resolve to a different base
/// (another user's same-keyed template, or a global) are not dependents. Uses
/// the same lookup rule as the fold, so it can't diverge from resolution.
pub async fn base_row_id_for(
    db: &PgPool,
    layer: &ServiceTemplateRow,
) -> Result<Option<Uuid>, AppError> {
    let Some(ext) = layer.extends.as_deref() else {
        return Ok(None);
    };
    let base = resolve_base(
        db,
        layer.org_id,
        layer.owner_identity_id,
        layer.owner_identity_id.is_some(),
        &layer.key,
        ext,
    )
    .await?;
    Ok(base.map(|r| r.id))
}
