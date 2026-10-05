//! Same-org, cross-user read isolation for approvals and service instances.
//!
//! `cross_tenant_isolation.rs` pins the org boundary. This file pins the one
//! inside it: an identity in the same org with no relationship to a resource
//! must not read it. Before this, `GET /v1/approvals` (no scope, or
//! `?identity_id=` any identity) and `GET /v1/approvals/{id}` handed every
//! identity in the org every pending call's `action_detail`, and
//! `GET /v1/services/{id}/groups` / `GET /v1/services/{uuid}/actions` looked
//! instances up by org alone.
//!
//! Every assertion is on a **canary**: a unique string planted in the foreign
//! resource that must never appear in a stranger's response body.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

struct Org {
    base: String,
    client: Client,
    org_id: Uuid,
    /// Bootstrap admin key (org admin).
    admin_key: String,
}

impl Org {
    async fn get(&self, path: &str, key: &str) -> (u16, String) {
        let resp = self
            .client
            .get(format!("{}{path}", self.base))
            .header(common::auth(key).0, common::auth(key).1)
            .send()
            .await
            .unwrap();
        (
            resp.status().as_u16(),
            resp.text().await.unwrap_or_default(),
        )
    }

    async fn post(&self, path: &str, key: &str, body: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}{path}", self.base))
            .header(common::auth(key).0, common::auth(key).1)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A fresh identity (`kind`, optional parent) plus an identity-bound key.
    async fn identity(&self, kind: &str, parent: Option<Uuid>) -> (Uuid, String) {
        let mut body = json!({"name": format!("{kind}-{}", Uuid::new_v4()), "kind": kind});
        if let Some(p) = parent {
            body["parent_id"] = json!(p);
        }
        let (_, ident) = self.post("/v1/identities", &self.admin_key, body).await;
        let id: Uuid = ident["id"]
            .as_str()
            .unwrap_or_else(|| panic!("create identity: {ident}"))
            .parse()
            .unwrap();
        let (_, key) = self
            .post(
                "/v1/api-keys",
                &self.admin_key,
                json!({"org_id": self.org_id, "identity_id": id, "name": format!("k-{id}")}),
            )
            .await;
        let key = key["key"]
            .as_str()
            .unwrap_or_else(|| panic!("mint key: {key}"))
            .to_string();
        (id, key)
    }
}

impl Org {
    /// A user who is an org admin only through an admin-level `overslash`
    /// grant — `is_org_admin` stays false. The dev `admin` profile is this
    /// shape, and every gate here must treat it as the admin it is.
    async fn group_admin(&self) -> String {
        let (id, key) = self.identity("user", None).await;
        let (_, svc) = {
            let (status, body) = self.get("/v1/services/overslash", &self.admin_key).await;
            (status, serde_json::from_str::<Value>(&body).unwrap())
        };
        let svc_id = svc["id"].as_str().unwrap().to_string();
        let (_, group) = self
            .post(
                "/v1/groups",
                &self.admin_key,
                json!({"name": format!("admins-{}", Uuid::new_v4())}),
            )
            .await;
        let gid = group["id"].as_str().unwrap().to_string();
        let (status, body) = self
            .post(
                &format!("/v1/groups/{gid}/grants"),
                &self.admin_key,
                json!({"service_instance_id": svc_id, "access_level": "admin"}),
            )
            .await;
        assert!(status < 300, "grant: {body}");
        let (status, body) = self
            .post(
                &format!("/v1/groups/{gid}/members"),
                &self.admin_key,
                json!({"identity_id": id}),
            )
            .await;
        assert!(status < 300, "member: {body}");
        key
    }
}

async fn org(with_registry: bool) -> Org {
    let pool = common::test_pool().await;
    let (base, client) = if with_registry {
        common::start_api_with_registry(pool, None).await
    } else {
        let (addr, client) = common::start_api(pool).await;
        (format!("http://{addr}"), client)
    };
    let (org_id, _agent, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    Org {
        base,
        client,
        org_id,
        admin_key,
    }
}

struct PendingApproval {
    approval_id: String,
    owner_key: String,
    agent_id: Uuid,
    agent_key: String,
    canary: String,
}

/// A user with an agent that has made one gated call. The call's URL carries
/// the canary, so it lands in `action_summary` / `action_detail`.
async fn pending_approval(o: &Org) -> PendingApproval {
    common::allow_loopback_ssrf();
    let (owner_id, owner_key) = o.identity("user", None).await;
    let (agent_id, agent_key) = o.identity("agent", Some(owner_id)).await;
    // Cut the agent off from its owner's permissions so the call gates.
    o.client
        .patch(format!("{}/v1/identities/{agent_id}", o.base))
        .header(common::auth(&o.admin_key).0, common::auth(&o.admin_key).1)
        .json(&json!({"inherit_permissions": false}))
        .send()
        .await
        .unwrap();
    // A secret makes the call carry real risk; a bare read would be
    // auto-approved (D53) and leave no approval to isolate.
    o.client
        .put(format!("{}/v1/secrets/tk", o.base))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();
    let mock = common::start_mock().await;
    let canary = format!("canary-{}", Uuid::new_v4().simple());
    let (status, body) = o
        .post(
            "/v1/actions/call",
            &agent_key,
            json!({
                "service": "http", "method": "GET",
                "url": format!("http://{mock}/echo?{canary}"),
                "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}],
            }),
        )
        .await;
    assert_eq!(status, 202, "expected a gated call: {body}");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();
    PendingApproval {
        approval_id,
        owner_key,
        agent_id,
        agent_key,
        canary,
    }
}

/// The requester, its owner and an org admin see the approval on the list and
/// the detail; a same-org stranger sees it on neither, and its `/execution`
/// answers 404 rather than confirming the id exists.
#[tokio::test]
async fn a_stranger_never_reads_another_users_approval() {
    let o = org(false).await;
    let p = pending_approval(&o).await;
    let (_, stranger_key) = o.identity("user", None).await;
    let detail = format!("/v1/approvals/{}", p.approval_id);

    for (who, key) in [
        ("requester", &p.agent_key),
        ("owner", &p.owner_key),
        ("admin", &o.admin_key),
    ] {
        let (status, body) = o.get(&detail, key).await;
        assert_eq!(status, 200, "{who} must read the approval: {body}");
        let (status, body) = o.get("/v1/approvals", key).await;
        assert_eq!(status, 200);
        assert!(
            body.contains(&p.approval_id),
            "{who}'s default list must include the approval: {body}"
        );
    }

    let (status, body) = o.get(&detail, &stranger_key).await;
    assert_eq!(status, 404, "stranger GET must 404: {body}");
    assert!(!body.contains(&p.canary));

    let (status, body) = o.get(&format!("{detail}/execution"), &stranger_key).await;
    assert_eq!(status, 404, "stranger /execution must 404: {body}");

    for path in [
        "/v1/approvals".to_string(),
        "/v1/approvals?status=pending".to_string(),
        format!("/v1/approvals?identity_id={}", p.agent_id),
    ] {
        let (status, body) = o.get(&path, &stranger_key).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert!(
            !body.contains(&p.canary) && !body.contains(&p.approval_id),
            "{path} leaked a foreign approval to a stranger: {body}"
        );
    }
}

/// `?identity_id=` on a node the caller *is* related to keeps working — the
/// identity hierarchy panel depends on it.
#[tokio::test]
async fn the_owner_lists_its_agents_approvals_by_identity() {
    let o = org(false).await;
    let p = pending_approval(&o).await;
    let (status, body) = o
        .get(
            &format!("/v1/approvals?identity_id={}", p.agent_id),
            &p.owner_key,
        )
        .await;
    assert_eq!(status, 200);
    assert!(body.contains(&p.approval_id), "{body}");
}

/// An identity's permission rules say what it may do unattended, so they are
/// read by the same relationship: the identity, its ancestors, and org admins.
/// A same-org stranger gets 404 — the cross-tenant answer.
#[tokio::test]
async fn a_stranger_never_reads_another_users_permission_rules() {
    let o = org(false).await;
    let (owner_id, owner_key) = o.identity("user", None).await;
    let (agent_id, agent_key) = o.identity("agent", Some(owner_id)).await;
    let (_, stranger_key) = o.identity("user", None).await;
    let canary = format!("canary{}", Uuid::new_v4().simple());
    let (status, body) = o
        .post(
            "/v1/permissions",
            &o.admin_key,
            json!({"identity_id": agent_id, "action_pattern": format!("http:GET:{canary}.example.com/*")}),
        )
        .await;
    assert_eq!(status, 200, "seed rule: {body}");

    let path = format!("/v1/permissions?identity_id={agent_id}");
    for (who, key) in [
        ("agent", &agent_key),
        ("owner", &owner_key),
        ("admin", &o.admin_key),
    ] {
        let (status, body) = o.get(&path, key).await;
        assert_eq!(status, 200, "{who}: {body}");
        assert!(body.contains(&canary), "{who} must see the rule: {body}");
    }
    let (status, body) = o.get(&path, &stranger_key).await;
    assert_eq!(status, 404, "stranger must 404: {body}");
    assert!(!body.contains(&canary));
}

/// A private, user-level service instance: its owner, and an org admin, read
/// its groups and actions by id; another user in the org gets 404 on both.
#[tokio::test]
async fn a_stranger_never_reads_another_users_service_instance() {
    let o = org(true).await;
    let (_, owner_key) = o.identity("user", None).await;
    let (_, stranger_key) = o.identity("user", None).await;

    let canary = format!("x_{}", Uuid::new_v4().simple());
    let (status, svc) = o
        .post(
            "/v1/services",
            &owner_key,
            json!({"template_key": "x", "name": canary, "user_level": true, "status": "active"}),
        )
        .await;
    assert!(status < 300, "service create failed ({status}): {svc}");
    let svc_id = svc["id"].as_str().unwrap();

    for path in [
        format!("/v1/services/{svc_id}/groups"),
        format!("/v1/services/{svc_id}/actions"),
    ] {
        let (status, body) = o.get(&path, &owner_key).await;
        assert_eq!(status, 200, "owner {path}: {body}");
        let (status, body) = o.get(&path, &o.admin_key).await;
        assert_eq!(status, 200, "admin {path}: {body}");
        let (status, body) = o.get(&path, &stranger_key).await;
        assert_eq!(status, 404, "stranger {path} must 404: {body}");
        assert!(!body.contains(&canary));
    }
}

/// An admin by `overslash` grant (not by the `is_org_admin` flag) reads every
/// gated route — the shape of the dev `admin` profile the E2E suite signs in
/// as, which a flag-only check silently locked out.
#[tokio::test]
async fn an_admin_by_grant_reads_every_gated_route() {
    let o = org(true).await;
    let p = pending_approval(&o).await;
    let group_admin = o.group_admin().await;
    let (_, owner_key) = o.identity("user", None).await;
    let (status, svc) = o
        .post(
            "/v1/services",
            &owner_key,
            json!({"template_key": "x", "name": format!("x_{}", Uuid::new_v4().simple()), "user_level": true, "status": "active"}),
        )
        .await;
    assert!(status < 300, "service create failed ({status}): {svc}");
    let svc_id = svc["id"].as_str().unwrap();

    for path in [
        format!("/v1/approvals/{}", p.approval_id),
        format!("/v1/permissions?identity_id={}", p.agent_id),
        format!("/v1/services/{svc_id}/groups"),
        format!("/v1/services/{svc_id}/actions"),
    ] {
        let (status, body) = o.get(&path, &group_admin).await;
        assert_eq!(status, 200, "group admin {path}: {body}");
    }
    let (_, body) = o.get("/v1/approvals", &group_admin).await;
    assert!(body.contains(&p.approval_id), "{body}");
}
