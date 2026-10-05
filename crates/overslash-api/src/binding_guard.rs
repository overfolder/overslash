//! Guard: credential-bearing rows are reached through their binding policy.
//!
//! A stored reference to an owned resource — a secret path, a pinned
//! connection, a pinned BYOC client, an instance's template — has one
//! binding-policy module that owns both the write check and the read check
//! (`secret_paths`, `platform_services::connection_binding`, `byoc_binding`,
//! `platform_services::instance_template`). D119 and D120 were both the same
//! bug: some path read the reference with an org-wide getter and trusted it.
//!
//! The org-wide getters are named for what they are (`*_any_owner`), and this
//! test fails when one is called from a file the allowlist does not name —
//! so a new path either goes through the policy, or states in review why it
//! may look past the owner. The same goes for reading secret values, for the
//! vault rule without the org-vault gate, and for resolving an instance's
//! template as anyone but its owner.
//!
//! Modelled on `overslash-env`'s `guard` and the extension-vocabulary lint:
//! a line scan, test modules cut off at the first `#[cfg(test)]`.

use std::path::{Path, PathBuf};

/// Calls that look past ownership. Each needle is matched as a substring of a
/// non-test line.
const GUARDED: &[&str] = &[
    ".get_connection_any_owner(",
    ".get_connections_by_ids_any_owner(",
    ".list_all_connections_any_owner(",
    ".get_byoc_credential_any_owner(",
    ".list_byoc_credentials_any_owner(",
    ".get_current_secret_value(",
    ".get_secret_value_at_version(",
    // The vault rule alone, without the org-vault gate
    // (`readable_slot_binding` applies both).
    "readable_instance_binding(",
];

/// `(needle, file relative to src/, why this file may call it)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    // ── The policy modules themselves ──────────────────────────────────
    (
        ".get_connection_any_owner(",
        "services/platform_services/connection_binding.rs",
        "the connection-pin policy: write check and call-time read",
    ),
    (
        ".get_connections_by_ids_any_owner(",
        "services/platform_services/connection_binding.rs",
        "usable_pins: the view-side read, filtered by owner",
    ),
    (
        ".get_byoc_credential_any_owner(",
        "services/byoc_binding.rs",
        "the BYOC-pin policy",
    ),
    (
        "readable_instance_binding(",
        "services/secret_paths/mod.rs",
        "the secret-path policy; readable_slot_binding wraps it with the gate",
    ),
    // ── Owner- or admin-checked inline, next to the call ──────────────
    (
        ".list_all_connections_any_owner(",
        "routes/connections/crud.rs",
        "admin-only \"all users' connections\" view",
    ),
    (
        ".get_connection_any_owner(",
        "routes/connections/crud.rs",
        "GET /connections/{id} admin branch; upgrade-scopes checks caller or ceiling",
    ),
    (
        ".get_connection_any_owner(",
        "routes/connections/callback.rs",
        "upgrade target must match the flow identity and provider",
    ),
    (
        ".get_connection_any_owner(",
        "services/platform_connections/create.rs",
        "login_hint only from the flow identity's own connection",
    ),
    (
        ".get_byoc_credential_any_owner(",
        "routes/byoc_credentials.rs",
        "BYOC CRUD: self or org admin",
    ),
    (
        ".list_byoc_credentials_any_owner(",
        "routes/byoc_credentials.rs",
        "BYOC list: filtered to self unless org admin",
    ),
    (
        ".list_byoc_credentials_any_owner(",
        "routes/oauth_providers.rs",
        "provider list: filtered to the caller's own BYOC",
    ),
    // ── Secret values: the paths come from the read rule ──────────────
    (
        ".get_current_secret_value(",
        "routes/actions/auth_resolve.rs",
        "org-source default candidates, gated by OrgVaultGate",
    ),
    (
        ".get_current_secret_value(",
        "services/action_caller.rs",
        "send time: paths the server qualified under the read rule",
    ),
    (
        ".get_current_secret_value(",
        "services/mcp_auth.rs",
        "MCP bearer: path qualified by resolve_effective_mcp under the read rule",
    ),
    (
        ".get_current_secret_value(",
        "services/client_credentials.rs",
        "OAuth app credentials: org vault only",
    ),
    (
        ".get_current_secret_value(",
        "routes/org_oauth_credentials.rs",
        "admin-only org OAuth app settings: org vault only",
    ),
    (
        ".get_current_secret_value(",
        "routes/oauth_providers.rs",
        "whether org OAuth app credentials exist: org vault only",
    ),
    (
        ".get_secret_value_at_version(",
        "routes/secrets.rs",
        "reveal/restore behind select_namespace: own vault, else admin",
    ),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(path relative to src/, non-test source)` for every file under src/.
fn sources() -> Vec<(String, String)> {
    let root = src_dir();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    files
        .into_iter()
        // A `tests.rs` sibling module is test code end to end.
        .filter(|p| p.file_name().is_some_and(|n| n != "tests.rs"))
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&p).unwrap();
            let live = match src.find("#[cfg(test)]") {
                Some(i) => src[..i].to_string(),
                None => src,
            };
            (rel, live)
        })
        .collect()
}

fn allowed(needle: &str, file: &str) -> bool {
    ALLOWED.iter().any(|(n, f, _)| *n == needle && *f == file)
}

#[test]
fn no_owner_blind_getter_outside_its_policy() {
    let mut offenders = Vec::new();
    for (file, src) in sources() {
        if file == "binding_guard.rs" {
            continue;
        }
        for (i, line) in src.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in GUARDED {
                if line.contains(needle) && !allowed(needle, &file) {
                    offenders.push(format!("{file}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these calls look past who owns a credential. Go through the binding \
         policy (`connection_binding::{{pinned_connection, usable_pins}}`, \
         `byoc_binding::usable_byoc_pin`, `secret_paths::readable_slot_binding`), \
         or — if the call checks ownership itself — add it to `ALLOWED` with the \
         reason:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_allowlist_points_at_real_call_sites() {
    let sources = sources();
    let stale: Vec<_> = ALLOWED
        .iter()
        .filter(|(needle, file, _)| {
            !sources
                .iter()
                .any(|(f, src)| f == file && src.contains(needle))
        })
        .map(|(needle, file, _)| format!("{file} no longer calls {needle}"))
        .collect();
    assert!(
        stale.is_empty(),
        "stale allowlist entries:\n{}",
        stale.join("\n")
    );
}

/// An instance's template is its owner's (`instance_template`). Passing an
/// instance row's `template_key` to `resolve_template_definition` directly
/// means choosing whose tiers to resolve in — the call-time bug where the
/// caller's same-key user template shadowed the owner's.
#[test]
fn instance_templates_resolve_through_instance_template() {
    let mut offenders = Vec::new();
    for (file, src) in sources() {
        if file == "services/platform_services/templates.rs" || file == "binding_guard.rs" {
            continue;
        }
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("resolve_template_definition(") || line.contains("fn ") {
                continue;
            }
            // The call's arguments: up to the closing paren, a few lines on.
            let call: String = lines[i..lines.len().min(i + 8)].join("\n");
            let call = &call[..call.find(')').map_or(call.len(), |j| j + 1)];
            // `input.template_key` is a create request naming a template, not
            // an instance's reference to one.
            if call.contains(".template_key") && !call.contains("input.template_key") {
                offenders.push(format!("{file}:{}", i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "resolve an instance's template with `platform_services::instance_template`:\n{}",
        offenders.join("\n")
    );
}

/// A new org-wide getter on `OrgScope` that returns credential-bearing rows
/// must say so in its name, so the guard above can see it.
#[test]
fn org_scope_credential_getters_name_their_reach() {
    let scopes = Path::new(env!("CARGO_MANIFEST_DIR")).join("../overslash-db/src/scopes");
    let mut offenders = Vec::new();
    for name in ["org_connections.rs", "org_byoc.rs"] {
        let src = std::fs::read_to_string(scopes.join(name)).unwrap();
        let src = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(rest) = line.trim_start().strip_prefix("pub async fn ") else {
                continue;
            };
            let fn_name = &rest[..rest.find(['(', '<']).unwrap_or(rest.len())];
            // Signature through the opening brace.
            let sig: String = lines[i..lines.len().min(i + 8)].join(" ");
            let sig = &sig[..sig.find('{').unwrap_or(sig.len())];
            let returns_rows = sig.contains("ConnectionRow>") || sig.contains("ByocCredentialRow>");
            let reads = fn_name.starts_with("get_") || fn_name.starts_with("list_");
            // Owner-filtered by a parameter, or the create path's echo.
            let owner_scoped = sig.contains("identity_id: Uuid");
            if returns_rows && reads && !owner_scoped && !fn_name.ends_with("_any_owner") {
                offenders.push(format!("{name}: {fn_name}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "OrgScope getters returning another owner's credential rows must end in \
         `_any_owner` (and be added to binding_guard's GUARDED list):\n{}",
        offenders.join("\n")
    );
}
