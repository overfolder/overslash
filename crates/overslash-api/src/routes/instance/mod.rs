//! Instance Admin panel API (`/v1/instance/*`): orgs as tenancy and billing
//! units, instance admins, the effective deployment configuration, and the
//! instance audit trail.
//!
//! Every handler takes `InstanceAdminAuth`: session-cookie only, the
//! `is_instance_admin` flag re-read per request, and a fresh sign-in
//! (admin step-up) required on every mutation. Nothing here reads inside an
//! org — no secrets, connections, approvals or member identities.

use axum::{
    Router,
    routing::{delete, get},
};

use crate::AppState;

mod admins;
mod audit;
mod config;
mod orgs;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/instance/orgs", get(orgs::list).post(orgs::create))
        .route("/v1/instance/admins", get(admins::list).post(admins::grant))
        .route("/v1/instance/admins/{user_id}", delete(admins::revoke))
        .route("/v1/instance/users", get(admins::search_users))
        .route("/v1/instance/config", get(config::get_config))
        .route("/v1/instance/audit", get(audit::list))
        .route("/v1/instance/audit/export", get(audit::export))
}
