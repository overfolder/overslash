//! Consent (agent enrollment) JSON API backing the dashboard consent page.

use super::*;

// ---------------------------------------------------------------------------
// Consent (agent enrollment) — JSON API backing the dashboard
// ---------------------------------------------------------------------------
//
// When /oauth/authorize finds no prior (user, client_id) → agent binding, it
// parks the request in `pending_authorize_store` and redirects the user's
// browser to the dashboard at `/oauth/consent?request_id=...`. The dashboard
// page then calls these endpoints (same session cookie as the rest of /v1)
// to render the enrollment card and to complete the flow. The final
// authorization-code redirect back to the MCP client is done by the
// dashboard itself (window.location) based on the `redirect_uri` returned
// from `finish`.

#[derive(Serialize)]
struct ConsentClientInfo {
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    elicitation_supported: bool,
}

#[derive(Serialize)]
struct ConsentConnectionInfo {
    ip: Option<String>,
}

#[derive(Serialize)]
struct ConsentParentOption {
    id: Uuid,
    name: String,
    kind: String,
    is_you: bool,
}

#[derive(Serialize)]
struct ConsentGroupOption {
    id: Uuid,
    name: String,
    member_count: i64,
}

#[derive(Serialize)]
struct ConsentReauthTarget {
    agent_id: Uuid,
    agent_name: String,
    parent_id: Option<Uuid>,
    parent_name: Option<String>,
    last_seen_at: Option<String>,
    /// Pre-fill for the elicitation toggle on the consent page so a reauth
    /// doesn't silently flip a user's previously-saved choice back to the
    /// `false` default. Read from the existing binding for this agent.
    elicitation_enabled: bool,
}

#[derive(Serialize)]
pub(super) struct ConsentContextResponse {
    request_id: String,
    user_email: String,
    /// The org the new agent will be created in — locked at `/oauth/authorize`
    /// time. Surfaced so the consent card can show it unmistakably and offer a
    /// switcher (see `consent_switch_org`).
    org_id: Uuid,
    org_name: String,
    org_slug: String,
    client: ConsentClientInfo,
    connection: ConsentConnectionInfo,
    mode: &'static str,
    reauth_target: Option<ConsentReauthTarget>,
    suggested_agent_name: String,
    parents: Vec<ConsentParentOption>,
    groups: Vec<ConsentGroupOption>,
}

#[derive(Deserialize)]
pub(super) struct ConsentFinishRequest {
    mode: String,
    agent_name: Option<String>,
    parent_id: Option<Uuid>,
    #[serde(default)]
    inherit_permissions: bool,
    #[serde(default)]
    group_names: Vec<String>,
    /// The `reauth_target.agent_id` shown to the user on the consent page,
    /// echoed back verbatim so mode="reauth" binds to the exact agent the
    /// user saw — not whatever a second `find_similar_for_user` call
    /// happens to return (newer enrollments, revocations, etc. could
    /// shift it between GET context and POST finish).
    reauth_agent_id: Option<Uuid>,
    /// User's choice from the Connection Settings card. `None` means the
    /// caller didn't speak the per-binding setting (older dashboard build,
    /// third-party POST) and the existing binding value is preserved.
    /// `Some(b)` is an explicit choice from the consent page; the server
    /// applies it across the agent's bindings, gated by capability.
    elicitation_enabled: Option<bool>,
}

#[derive(Serialize)]
pub(super) struct ConsentFinishResponse {
    redirect_uri: String,
}

#[derive(Deserialize)]
pub(super) struct ConsentSwitchOrgRequest {
    org_id: Uuid,
}

#[derive(Serialize)]
struct ConsentSwitchOrgResponse {
    /// Fresh pending request bound to the target org. The dashboard navigates
    /// to `/oauth/consent?request_id=<this>`.
    request_id: String,
    /// Absolute URL (honoring per-org subdomain) the dashboard should load so
    /// the new session cookie and `request_id` are both valid on that host.
    redirect_to: String,
}

// Slugify a human-typed name into an `agent:<slug>` identifier the way the
// design card does — lowercase, dashes only, no leading/trailing dashes,
// no double dashes. Mirrors the frontend `slugify` so the server and UI
// produce identical output whether the user edits the field or accepts the
// default.
fn slugify_agent_name(raw: &str) -> String {
    let lower = raw.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            // Any non-alphanumeric run (including literal dashes) collapses
            // to a single `-` — matches the frontend's
            // `.replace(/[^a-z0-9-]+/g, '-').replace(/-{2,}/g, '-')`.
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "mcp-client".to_string()
    } else {
        out
    }
}

pub(super) async fn consent_context(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Result<Json<ConsentContextResponse>, AppError> {
    let session_claims = session::extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("session expired".into()))?;

    let pending = state
        .pending_authorize_store(&ext)
        .get(&request_id)
        .ok_or_else(|| AppError::NotFound("authorization request expired".into()))?;

    // The session that landed on /oauth/authorize must be the one finishing
    // consent — protects against a swap-after-redirect attack where a second
    // tab's session accidentally completes someone else's flow.
    if pending.user_identity_id != session_claims.sub {
        return Err(AppError::Forbidden(
            "signed in as a different user than started this authorization".into(),
        ));
    }
    if pending.org_id != session_claims.org {
        return Err(AppError::Forbidden(
            "signed in to a different org than started this authorization".into(),
        ));
    }

    let org_row = org::get_by_id(state.db(&ext), pending.org_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("organization no longer exists".into()))?;

    let client = oauth_mcp_client::get_by_client_id(state.db(&ext), &pending.client_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("MCP client is no longer registered".into()))?;

    // Reauth detection: if there's a non-revoked prior binding for this user
    // that matches by client_name + software_id, offer that agent as the
    // reauth target. This covers the case where a client re-registered (new
    // client_id) after losing its persisted config.
    let similar = oauth_mcp_client::find_similar_for_user(
        state.db(&ext),
        pending.user_identity_id,
        client.client_name.as_deref(),
        client.software_id.as_deref(),
    )
    .await?;

    let suggested_agent_name = client
        .client_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .map(|s| slugify_agent_name(&s))
        .unwrap_or_else(|| "mcp-client".into());

    // User's direct children that qualify as "parents" for a new agent.
    // We include the user themselves plus any existing agents under them
    // so the user can attach the new MCP agent to an automation root.
    let user_row = identity::get_by_id(state.db(&ext), pending.org_id, pending.user_identity_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("user identity not found".into()))?;
    let mut parents = vec![ConsentParentOption {
        id: user_row.id,
        name: user_row.name.clone(),
        kind: user_row.kind.clone(),
        is_you: true,
    }];
    let children =
        identity::list_children(state.db(&ext), pending.org_id, pending.user_identity_id)
            .await
            .unwrap_or_default();
    for c in children {
        if c.kind == "agent" && c.archived_at.is_none() {
            parents.push(ConsentParentOption {
                id: c.id,
                name: c.name,
                kind: c.kind,
                is_you: false,
            });
        }
    }

    let scope = OrgScope::new(pending.org_id, state.db_pool(&ext));
    let groups_rows = scope.list_groups().await.unwrap_or_default();
    let mut groups = Vec::with_capacity(groups_rows.len());
    for g in groups_rows {
        // Filter out system groups ("Everyone", "Admins") — not user-
        // selectable for a new MCP agent.
        if g.is_system {
            continue;
        }
        let member_count = scope.count_members_in_group(g.id).await.unwrap_or(0);
        groups.push(ConsentGroupOption {
            id: g.id,
            name: g.name,
            member_count,
        });
    }

    let elicitation_supported = client.elicitation_supported();

    let (mode, reauth_target) = if let Some(sim) = similar {
        let agent =
            identity::get_by_id(state.db(&ext), pending.org_id, sim.agent_identity_id).await?;
        match agent {
            Some(a) if a.kind == "agent" && a.archived_at.is_none() => {
                let parent_name = if let Some(pid) = a.parent_id {
                    identity::get_by_id(state.db(&ext), pending.org_id, pid)
                        .await
                        .ok()
                        .flatten()
                        .map(|p| p.name)
                } else {
                    None
                };
                let existing_elicitation =
                    mcp_client_agent_binding::get_by_agent_identity(state.db(&ext), a.id)
                        .await?
                        .map(|b| b.elicitation_enabled)
                        .unwrap_or(false);
                (
                    "reauth",
                    Some(ConsentReauthTarget {
                        agent_id: a.id,
                        agent_name: a.name,
                        parent_id: a.parent_id,
                        parent_name,
                        last_seen_at: sim.client.last_seen_at.map(crate::routes::util::fmt_time),
                        elicitation_enabled: existing_elicitation,
                    }),
                )
            }
            _ => ("new", None),
        }
    } else {
        ("new", None)
    };

    Ok(Json(ConsentContextResponse {
        request_id: request_id.clone(),
        user_email: session_claims.email.clone(),
        org_id: org_row.id,
        org_name: org_row.name.clone(),
        org_slug: org_row.slug.clone(),
        client: ConsentClientInfo {
            client_name: client.client_name.clone(),
            software_id: client.software_id.clone(),
            software_version: client.software_version.clone(),
            elicitation_supported,
        },
        connection: ConsentConnectionInfo {
            ip: client.created_ip.clone(),
        },
        mode,
        reauth_target,
        suggested_agent_name,
        parents,
        groups,
    }))
}

/// POST /v1/oauth/consent/{request_id}/switch-org — re-bind a paused consent
/// request to a different org the user belongs to.
///
/// The consent flow is org-locked at `/oauth/authorize` time (`pending.org_id`
/// is captured from the session and both `consent_context` and
/// `consent_finish` reject a mismatched session org). So switching can't be a
/// cookie flip — we mint a *new* pending request that is born bound to the
/// target org, mint a session cookie for that org, and hand the dashboard the
/// URL to reload onto. The old pending record is left to expire so a failed
/// navigation still falls back to the original org.
///
/// Like the rest of the in-process stores, the cloned pending record only
/// lives in the process that handled this call. Under horizontal scaling a
/// cross-host `redirect_to` could miss it — the same v1 limitation documented
/// in `services/oauth_as.rs`; a Redis-backed store would lift it.
pub(super) async fn consent_switch_org(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<ConsentSwitchOrgRequest>,
) -> Result<Response, AppError> {
    let session_claims = session::extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("session expired".into()))?;

    // Peek (don't consume): a failed switch must leave the original request
    // intact so the user can still finish in the org they started in.
    let pending = state
        .pending_authorize_store(&ext)
        .get(&request_id)
        .ok_or_else(|| AppError::NotFound("authorization request expired".into()))?;

    // Same human as started the flow — we're changing the org, not the user.
    if pending.user_identity_id != session_claims.sub {
        return Err(AppError::Forbidden(
            "signed in as a different user than started this authorization".into(),
        ));
    }

    // Resolve the cross-org user_id. The pending record only carries an
    // org-scoped identity; membership is keyed by user_id.
    let user_id = match session_claims.user_id {
        Some(uid) => uid,
        None => {
            let scope = OrgScope::new(pending.org_id, state.db_pool(&ext));
            scope
                .get_identity(pending.user_identity_id)
                .await?
                .and_then(|i| i.user_id)
                .ok_or_else(|| {
                    AppError::Unauthorized("session has no resolvable user; sign in again".into())
                })?
        }
    };

    // Membership guard — only orgs the user actually belongs to.
    membership::find(state.db(&ext), user_id, body.org_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not a member of that org".into()))?;

    let target_org = org::get_by_id(state.db(&ext), body.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    // The user's identity in the target org (one per (org, user) by migration
    // 040's partial UNIQUE).
    let target_identity = identity::find_by_org_and_user(state.db(&ext), body.org_id, user_id)
        .await?
        .ok_or_else(|| {
            AppError::Internal(
                "membership exists but no user identity in target org (invariant violation)".into(),
            )
        })?;

    // Clone the client params into a fresh request bound to the target org.
    let new_request_id = oauth_as::generate_auth_code();
    let claim_email = target_identity
        .email
        .clone()
        .unwrap_or_else(|| pending.email.clone());
    state.pending_authorize_store(&ext).insert(
        new_request_id.clone(),
        oauth_as::PendingAuthorize {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            state_param: pending.state_param.clone(),
            user_identity_id: target_identity.id,
            org_id: target_org.id,
            email: claim_email.clone(),
            issued_at: Instant::now(),
        },
    );

    // Mint a session cookie scoped to the target org (mirrors `switch_org`).
    let jwt_secret = crate::routes::auth::signing_key_bytes(&state.config.signing_key);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let new_claims = jwt::Claims {
        sub: target_identity.id,
        org: target_org.id,
        email: claim_email,
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 7 * 24 * 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    let new_token = jwt::mint(&jwt_secret, &new_claims)
        .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;

    // `build_org_redirect` returns an absolute URL ending in `/`. The
    // request_id is URL-safe base64 (no padding), so it needs no escaping.
    let base = crate::routes::auth::build_org_redirect(&state, &target_org);
    let redirect_to = format!("{base}oauth/consent?request_id={new_request_id}");

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::SET_COOKIE,
        crate::routes::auth::session_cookie(&state, &new_token)?,
    );
    Ok((
        resp_headers,
        Json(ConsentSwitchOrgResponse {
            request_id: new_request_id,
            redirect_to,
        }),
    )
        .into_response())
}

pub(super) async fn consent_finish(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<ConsentFinishRequest>,
) -> Result<Json<ConsentFinishResponse>, AppError> {
    let session_claims = session::extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("session expired".into()))?;

    // Consume the pending record up front — consent is single-use, and a
    // replayable `request_id` would let a second finish call create a
    // duplicate agent and a second auth code. If any downstream lookup
    // fails the user re-starts the flow; the short `CONSENT_TTL` keeps the
    // window for that small.
    let pending = state
        .pending_authorize_store(&ext)
        .take(&request_id)
        .ok_or_else(|| AppError::BadRequest("authorization request expired".into()))?;

    if pending.user_identity_id != session_claims.sub {
        return Err(AppError::Forbidden(
            "signed in as a different user than started this authorization".into(),
        ));
    }
    if pending.org_id != session_claims.org {
        return Err(AppError::Forbidden(
            "signed in to a different org than started this authorization".into(),
        ));
    }

    let user = identity::get_by_id(state.db(&ext), pending.org_id, pending.user_identity_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("user identity not found".into()))?;

    let client = oauth_mcp_client::get_by_client_id(state.db(&ext), &pending.client_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("MCP client is no longer registered".into()))?;

    // A client stamped for a specific org (corp-subdomain registration) may
    // only bind an agent in that org. This is the authoritative re-check of the
    // authorize-time client-org gate at the single binding-creation site, so it
    // also covers the `consent_switch_org` path — which clones the pending
    // request into another org while keeping the original `client_id` and would
    // otherwise let a stamped client land a binding in a foreign org. NULL
    // (root/multi-org) clients bind in whatever org the flow resolved to. See
    // docs/design/mcp-enrollment-org-scoping.md.
    if let Some(client_org) = client.org_id
        && client_org != pending.org_id
    {
        return Err(AppError::Forbidden(
            "client is registered to a different org".into(),
        ));
    }

    let agent_identity_id = match body.mode.as_str() {
        "new" => {
            let raw_name = body.agent_name.as_deref().unwrap_or("").trim();
            let agent_name = if raw_name.is_empty() {
                client
                    .client_name
                    .as_deref()
                    .map(slugify_agent_name)
                    .unwrap_or_else(|| "mcp-client".into())
            } else {
                slugify_agent_name(raw_name)
            };

            // Parent must be the user themselves or one of their existing
            // agents — we already exposed exactly that list in the
            // context endpoint, so anything else is a forged submission.
            let parent_id = body.parent_id.unwrap_or(user.id);
            let parent = identity::get_by_id(state.db(&ext), pending.org_id, parent_id)
                .await?
                .ok_or_else(|| AppError::BadRequest("parent identity not found".into()))?;
            if parent.id != user.id
                && !(parent.kind == "agent"
                    && parent.archived_at.is_none()
                    && parent.owner_id == Some(user.id))
            {
                return Err(AppError::Forbidden(
                    "parent is not eligible for this enrollment".into(),
                ));
            }

            let agent = identity::create_with_parent(
                state.db(&ext),
                pending.org_id,
                &agent_name,
                "agent",
                None,
                parent.id,
                parent.depth + 1,
                user.id,
                body.inherit_permissions,
            )
            .await?;

            // Attach to selected groups, creating any missing ones by name.
            // System groups and duplicates are skipped. Failures are
            // logged but don't abort the enrollment — the user can always
            // fix group membership later from the dashboard.
            if !body.group_names.is_empty() {
                let scope = OrgScope::new(pending.org_id, state.db_pool(&ext));
                let existing = scope.list_groups().await.unwrap_or_default();
                for raw in &body.group_names {
                    let name = raw.trim();
                    if name.is_empty() {
                        continue;
                    }
                    let group_id = if let Some(g) = existing.iter().find(|g| g.name == name) {
                        if g.is_system {
                            continue;
                        }
                        g.id
                    } else {
                        match scope.create_group(name, "").await {
                            Ok(g) => g.id,
                            Err(e) => {
                                tracing::warn!("consent: create group '{name}' failed: {e}");
                                continue;
                            }
                        }
                    };
                    if let Err(e) = scope.assign_identity_to_group(agent.id, group_id).await {
                        tracing::warn!(
                            "consent: assign agent {} to group '{name}' failed: {e}",
                            agent.id
                        );
                    }
                }
            }

            agent.id
        }
        "reauth" => {
            // The client must echo back the reauth_target.agent_id that
            // `consent_context` resolved — binding to whatever
            // `find_similar_for_user` returns at finish-time would open
            // a race where a concurrent enrollment or revocation between
            // the GET and the POST shifts the target under the user.
            let echoed_agent_id = body
                .reauth_agent_id
                .ok_or_else(|| AppError::BadRequest("reauth_agent_id required".into()))?;

            // Guard against a caller submitting an arbitrary agent_id they
            // happen to know: the agent must be live, an agent-kind
            // identity, owned by the caller, AND there must be at least
            // one non-revoked prior binding from this user to that agent.
            // Together those invariants reduce to "the user already
            // enrolled this MCP client (or a previous one) against this
            // agent" — which is the honest definition of reauth.
            let agent = identity::get_by_id(state.db(&ext), pending.org_id, echoed_agent_id)
                .await?
                .ok_or_else(|| AppError::BadRequest("agent not found".into()))?;
            if agent.kind != "agent"
                || agent.archived_at.is_some()
                || agent.owner_id != Some(user.id)
            {
                return Err(AppError::Forbidden(
                    "agent is not available for reauth".into(),
                ));
            }
            if !oauth_mcp_client::user_has_binding_to_agent(
                state.db(&ext),
                pending.user_identity_id,
                agent.id,
            )
            .await?
            {
                return Err(AppError::Forbidden(
                    "agent has no prior enrollment for this user".into(),
                ));
            }
            agent.id
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "invalid mode '{}' (expected 'new' or 'reauth')",
                body.mode
            )));
        }
    };

    // Read the agent's existing per-binding elicitation flag BEFORE
    // upserting. Reauth under a re-registered client_id creates a fresh
    // binding row that uses schema defaults, so without a pre-fetch the new
    // row would hide whatever value the user saved on a prior binding.
    // (`auto_call_on_approve` lives on the agent identity now and is
    // naturally preserved across reauth — no special handling needed.)
    let prior_binding =
        mcp_client_agent_binding::get_by_agent_identity(state.db(&ext), agent_identity_id).await?;
    let prior_elicitation = prior_binding
        .as_ref()
        .map(|b| b.elicitation_enabled)
        .unwrap_or(false);

    mcp_client_agent_binding::upsert(
        state.db(&ext),
        pending.org_id,
        pending.user_identity_id,
        &pending.client_id,
        agent_identity_id,
    )
    .await?;

    // Resolve the per-agent value: an explicit choice from the consent page
    // wins (gated by capability — a hand-crafted `true` against a client
    // that didn't announce elicitation gets forced to `false`); a missing
    // field inherits the agent's prior value so older dashboard builds /
    // third-party POSTs don't destroy a previously-saved choice. Fan out
    // unconditionally to keep every binding row in sync with the per-agent
    // toggle (see `set_elicitation_enabled_for_agent`).
    let resolved_elicitation = match body.elicitation_enabled {
        Some(requested) => requested && client.elicitation_supported(),
        None => prior_elicitation,
    };
    mcp_client_agent_binding::set_elicitation_enabled_for_agent(
        state.db(&ext),
        agent_identity_id,
        resolved_elicitation,
    )
    .await?;

    // Fetch the agent's email (if any) so the access-token JWT carries a
    // sensible `email` claim. Agents usually inherit the owner's email
    // address for display purposes.
    let email = match identity::get_by_id(state.db(&ext), pending.org_id, agent_identity_id).await {
        Ok(Some(a)) => a.email.unwrap_or_else(|| pending.email.clone()),
        _ => pending.email.clone(),
    };

    let code = oauth_as::generate_auth_code();
    state.auth_code_store(&ext).insert(
        code.clone(),
        oauth_as::AuthCodeRecord {
            client_id: pending.client_id.clone(),
            identity_id: agent_identity_id,
            org_id: pending.org_id,
            email,
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            issued_at: Instant::now(),
        },
    );
    let mut redirect = format!(
        "{}?code={}",
        pending.redirect_uri,
        urlencoding::encode(&code)
    );
    if let Some(s) = pending.state_param.as_deref() {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Ok(Json(ConsentFinishResponse {
        redirect_uri: redirect,
    }))
}

#[cfg(test)]
mod slug_tests {
    use super::slugify_agent_name;

    #[test]
    fn slug_matches_frontend_behaviour() {
        assert_eq!(slugify_agent_name("Claude Desktop"), "claude-desktop");
        assert_eq!(slugify_agent_name("foo--bar"), "foo-bar");
        assert_eq!(slugify_agent_name("---foo___bar!!!"), "foo-bar");
        assert_eq!(slugify_agent_name("  spaces  "), "spaces");
        assert_eq!(slugify_agent_name(""), "mcp-client");
        assert_eq!(slugify_agent_name("!!!"), "mcp-client");
    }
}
