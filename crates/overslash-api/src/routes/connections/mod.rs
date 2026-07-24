//! Connection endpoints: OAuth-orchestrated creation, white-label token
//! import, the `/connect-authorize` browser gate, the OAuth callback, and
//! connection CRUD.

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::oauth_connection_flow;
use overslash_db::scopes::{OrgScope, UserScope};

use super::connect_gate::{
    ConnectGateOutcome, SessionError, admin_consent_html, evaluate_connect_gate, gone_html,
    mismatch_html, read_session,
};
use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, ReqExt, WriteAcl},
    services::{
        client_credentials, oauth,
        platform_caller::PlatformCallContext,
        platform_connections::{
            CreateConnectionInput, CreateConnectionResponse, RequestMeta, kernel_create_connection,
            kernel_create_connection_for_identity, merge_scopes,
        },
    },
};
use overslash_core::crypto;

mod callback;
mod crud;
mod gate;
mod initiate;

use callback::oauth_callback;
use crud::{
    delete_connection, get_connection, list_connections, set_connection_default,
    set_connection_keep, upgrade_connection_scopes,
};
use gate::{connect_authorize, connect_authorize_confirm};
use initiate::{import_connection, initiate_connection};

// Shared with the service-deletion cascade in `routes::services`.
pub(crate) use crud::fire_connection_deleted;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/connections",
            post(initiate_connection).get(list_connections),
        )
        .route("/v1/connections/import", post(import_connection))
        .route(
            "/v1/connections/{id}",
            get(get_connection).delete(delete_connection),
        )
        .route(
            "/v1/connections/{id}/set_default",
            post(set_connection_default),
        )
        .route("/v1/connections/{id}/keep", post(set_connection_keep))
        .route(
            "/v1/connections/{id}/upgrade_scopes",
            post(upgrade_connection_scopes),
        )
        .route("/v1/oauth/callback", get(oauth_callback))
        .route("/connect-authorize", get(connect_authorize))
        .route(
            "/connect-authorize/confirm",
            post(connect_authorize_confirm),
        )
}
