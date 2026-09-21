//! Instance-name collisions, and saying which row is holding the name.
//!
//! Split out of [`super::kernels`] because create and rename need the same
//! two answers — "was that a name collision?" and "what do I tell the
//! caller?" — and they had drifted: create caught *any* constraint violation
//! and called it "already exists", rename caught nothing and surfaced a
//! taken name as a 500.

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::error::AppError;

/// The two partial unique indexes that spell "this name is taken".
///
/// Matched by name rather than by `constraint().is_some()`, which used to
/// report *any* constraint violation — a bad `connection_id` foreign key, a
/// status check — as "service 'x' already exists". A caller acting on that
/// message renames and tries again, which cannot work, and the real cause
/// never reaches them.
pub(super) const INSTANCE_NAME_INDEXES: [&str; 2] = [
    "idx_service_instances_org_name",
    "idx_service_instances_user_name",
];

pub(super) fn is_instance_name_collision(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db
        .constraint()
        .is_some_and(|c| INSTANCE_NAME_INDEXES.contains(&c)))
}

/// Turn a name collision into a 409 that says which row is holding the name.
///
/// The lookup matters most in the case that reads as a bug: neither unique
/// index has a status predicate, so an **archived** instance keeps its name,
/// while the default `GET /v1/services` hides archived rows. Without this the
/// operator is told a name is taken by something they cannot see, and since
/// `name` defaults to the template key, archiving one `holded` makes every
/// later `create_service` for that template fail with no visible cause.
pub(super) async fn instance_name_conflict(
    scope: &OrgScope,
    owner_identity_id: Option<Uuid>,
    name: &str,
) -> AppError {
    let existing = scope
        .get_service_instance_by_name(owner_identity_id, name)
        .await
        .ok()
        .flatten();
    match existing {
        Some(row) if row.status == "archived" => AppError::Conflict(format!(
            "service '{name}' already exists: instance {} is archived and still \
             holds the name (archived instances are hidden from the default \
             service list). Rename or delete it, or choose another `name`.",
            row.id
        )),
        Some(row) => AppError::Conflict(format!(
            "service '{name}' already exists (instance {}, status {}). Choose \
             another `name`.",
            row.id, row.status
        )),
        // Raced, or held by a row this scope cannot see. The bare message is
        // still true and still actionable.
        None => AppError::Conflict(format!("service '{name}' already exists")),
    }
}
