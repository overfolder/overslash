//! Canary sweep for cross-user and cross-org secret leaks.
//!
//! Two orgs, several users each. **Every vault holds a secret with the same
//! names** (`canary`, `shortcut_api_token`), each with its own unique value.
//! Every actor then hits every vault through every surface, in every
//! spelling a path can take: the secrets API with its selectors, service
//! create/update bindings, inline (Mode A) secrets, secret requests, and
//! calls through services.
//!
//! The test does not pin each response code; it asserts invariants:
//!
//! * **No leak.** A response body seen by an actor never contains a canary
//!   from a vault that actor may not use. The fake upstream echoes the
//!   request headers, so an injected credential shows up in the body.
//! * **No write.** At the end, every canary is still at v1.
//! * **No foreign binding.** No user-level instance in either org is bound
//!   outside its owner's vault or the org vault.
//!
//! The one sanctioned crossing is checked as well: a shared org-level service
//! uses its configuring admin's secret for everyone the service is granted to,
//! and for nobody in the other org.
#![allow(clippy::disallowed_methods)] // final invariant sweep reads the DB directly

use crate::common;

use std::collections::BTreeMap;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{auth, everyone_group_id, start_api_with_registry, start_mock};

const NAMES: [&str; 2] = ["canary", "shortcut_api_token"];

/// One vault, labelled for messages.
#[derive(Clone)]
struct Vault {
    label: String,
    org: usize,
    /// `None` = the org vault.
    owner: Option<Uuid>,
}

/// Someone who makes requests.
#[derive(Clone)]
struct Actor {
    label: String,
    org: usize,
    key: String,
    /// Ceiling user — whose vault this actor owns.
    user: Uuid,
    user_name: String,
    is_admin: bool,
}

struct World {
    pool: sqlx::PgPool,
    base: String,
    client: Client,
    mock: std::net::SocketAddr,
    org_ids: [Uuid; 2],
    vaults: Vec<Vault>,
    actors: Vec<Actor>,
    /// Canary value → the vault holding it.
    canaries: BTreeMap<String, String>,
}

impl World {
    fn canary(vault: &Vault, name: &str) -> String {
        format!("CANARY::{name}::{}", vault.label)
    }

    /// Canaries this actor may legitimately see in a response: its own
    /// vault's (inline / own service), plus the configuring admin's on the
    /// shared org service of its own org — which `shared_ok` opts into.
    fn allowed_for(&self, actor: &Actor, shared_ok: Option<&str>) -> Vec<String> {
        let mut v: Vec<String> = self
            .vaults
            .iter()
            .filter(|vlt| vlt.owner == Some(actor.user))
            .flat_map(|vlt| NAMES.iter().map(move |n| Self::canary(vlt, n)))
            .collect();
        if let Some(c) = shared_ok {
            v.push(c.to_string());
        }
        v
    }

    fn assert_no_leak(&self, actor: &Actor, what: &str, body: &str, shared_ok: Option<&str>) {
        let allowed = self.allowed_for(actor, shared_ok);
        for (value, vault) in &self.canaries {
            if body.contains(value.as_str()) && !allowed.contains(value) {
                panic!(
                    "LEAK: {} saw the canary of vault {vault} via {what}\n{body}",
                    actor.label
                );
            }
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> (u16, String) {
        let resp = req.send().await.unwrap();
        (resp.status().as_u16(), resp.text().await.unwrap())
    }
}

async fn post_json(client: &Client, url: String, key: &str, body: Value) -> Value {
    client
        .post(url)
        .header(auth(key).0, auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Build one org: an admin, two members (each with an agent), all keys.
async fn build_org(
    base: &str,
    client: &Client,
    pool: &sqlx::PgPool,
    idx: usize,
    vaults: &mut Vec<Vault>,
    actors: &mut Vec<Actor>,
) -> Uuid {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": format!("Org{idx}"), "slug": format!("iso-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let admin_key = org["api_key"].as_str().unwrap().to_string();
    let admin_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND is_org_admin",
    )
    .bind(org_id)
    .fetch_one(pool)
    .await
    .unwrap();
    // Members in both orgs share names, so a handle never resolves across orgs
    // by accident of uniqueness.
    vaults.push(Vault {
        label: format!("org{idx}:admin"),
        org: idx,
        owner: Some(admin_id),
    });
    vaults.push(Vault {
        label: format!("org{idx}:ORG"),
        org: idx,
        owner: None,
    });
    actors.push(Actor {
        label: format!("org{idx}:admin"),
        org: idx,
        key: admin_key.clone(),
        user: admin_id,
        user_name: "admin".into(),
        is_admin: true,
    });
    for name in ["angel", "julia"] {
        let user = post_json(
            client,
            format!("{base}/v1/identities"),
            &admin_key,
            json!({"name": name, "kind": "user", "email": format!("{name}@org{idx}.test")}),
        )
        .await;
        let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();
        let agent = post_json(
            client,
            format!("{base}/v1/identities"),
            &admin_key,
            json!({"name": format!("{name}-agent"), "kind": "agent", "parent_id": user_id}),
        )
        .await;
        let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();
        for pattern in ["http:**", "shortcut:**", "shared:**"] {
            post_json(
                client,
                format!("{base}/v1/permissions"),
                &admin_key,
                json!({"identity_id": agent_id, "action_pattern": pattern, "effect": "allow"}),
            )
            .await;
        }
        let key_for = |id: Uuid| {
            post_json(
                client,
                format!("{base}/v1/api-keys"),
                &admin_key,
                json!({"org_id": org_id, "identity_id": id, "name": "k"}),
            )
        };
        let user_key = key_for(user_id).await["key"].as_str().unwrap().to_string();
        let agent_key = key_for(agent_id).await["key"].as_str().unwrap().to_string();
        vaults.push(Vault {
            label: format!("org{idx}:{name}"),
            org: idx,
            owner: Some(user_id),
        });
        for (label, key) in [
            (name.to_string(), user_key),
            (format!("{name}-agent"), agent_key),
        ] {
            actors.push(Actor {
                label: format!("org{idx}:{label}"),
                org: idx,
                key,
                user: user_id,
                user_name: name.into(),
                is_admin: false,
            });
        }
    }
    let _ = admin_id;
    org_id
}

async fn build() -> World {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool.clone(), None).await;
    let mock = start_mock().await;
    let (mut vaults, mut actors) = (Vec::new(), Vec::new());
    let a = build_org(&base, &client, &pool, 0, &mut vaults, &mut actors).await;
    let b = build_org(&base, &client, &pool, 1, &mut vaults, &mut actors).await;
    let mut w = World {
        pool,
        base,
        client,
        mock,
        org_ids: [a, b],
        vaults,
        actors,
        canaries: BTreeMap::new(),
    };
    // Fill every vault: users write their own; the org admin writes the org
    // vault. Same names everywhere, unique values.
    for vault in w.vaults.clone() {
        let writer = w
            .actors
            .iter()
            .find(|a| {
                a.org == vault.org
                    && match vault.owner {
                        Some(u) => a.user == u && !a.label.ends_with("-agent"),
                        None => a.is_admin,
                    }
            })
            .unwrap()
            .clone();
        let q = if vault.owner.is_none() {
            "?scope=org"
        } else {
            ""
        };
        for name in NAMES {
            let value = World::canary(&vault, name);
            let (status, body) = w
                .send(
                    w.client
                        .put(format!("{}/v1/secrets/{name}{q}", w.base))
                        .header(auth(&writer.key).0, auth(&writer.key).1)
                        .json(&json!({"value": value})),
                )
                .await;
            assert_eq!(status, 200, "seeding {}: {body}", vault.label);
            w.canaries.insert(value, vault.label.clone());
        }
    }
    w
}

/// Every spelling of "secret `name` in `target`'s vault", each with whether
/// it resolves — *within `actor`'s org*, where handles are looked up — to
/// `actor`'s own vault. (Both orgs have an `angel`, so `angel/x` typed in
/// org 1 is org 1's angel, never org 0's.)
fn spellings(w: &World, actor: &Actor, target: &Vault, name: &str) -> Vec<(String, bool)> {
    match target.owner {
        None => vec![(format!("org/{name}"), false)],
        Some(u) => {
            let mut v = vec![
                (format!("{u}/{name}"), u == actor.user),
                (format!("user:{u}/{name}"), u == actor.user),
            ];
            if let Some(a) = w.actors.iter().find(|a| a.user == u) {
                let org = target.org;
                // A bare handle: whichever same-named user is in the actor's org.
                let same_name_here = w
                    .actors
                    .iter()
                    .find(|b| b.org == actor.org && b.user_name == a.user_name)
                    .map(|b| b.user);
                let handle_mine = same_name_here == Some(actor.user);
                v.push((format!("{}/{name}", a.user_name), handle_mine));
                v.push((format!("user:{}/{name}", a.user_name), handle_mine));
                // An email names exactly one org's user.
                v.push((
                    format!("{}@org{org}.test/{name}", a.user_name),
                    u == actor.user,
                ));
            }
            v
        }
    }
}

/// One surface of the sweep per test, so nextest runs them in parallel. Each
/// test runs only its own surface's requests — every block in the actor loop
/// is gated on it, or the four tests would each redo the others' work.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// Inline (Mode A) secrets, plus each user's own service call.
    Inline,
    /// Creating a service bound to the target.
    Bind,
    /// Rebinding one's own service to the target.
    Rebind,
    /// `/v1/secrets*` with selectors, session reveal/restore, secret requests.
    SecretsApi,
}

// Multi-threaded: the actors run concurrently against an in-process
// server, and every request pays for an argon2 key check.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_inline_secret_crosses_a_vault() {
    sweep_surface(Surface::Inline).await;
}

// Multi-threaded: the actors run concurrently against an in-process
// server, and every request pays for an argon2 key check.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_new_binding_crosses_a_vault() {
    sweep_surface(Surface::Bind).await;
}

// Multi-threaded: the actors run concurrently against an in-process
// server, and every request pays for an argon2 key check.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_rebinding_crosses_a_vault() {
    sweep_surface(Surface::Rebind).await;
}

// Multi-threaded: the actors run concurrently against an in-process
// server, and every request pays for an argon2 key check.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn no_secrets_api_call_crosses_a_vault() {
    sweep_surface(Surface::SecretsApi).await;
}

async fn sweep_surface(surface: Surface) {
    let w = build().await;

    // A user-level `shortcut` service per non-admin actor's user, pointed at
    // the echoing fake, bound to the owner's own token. Only the surfaces that
    // use it (the positive control, and rebinding) pay for creating it.
    let mut own_service: BTreeMap<Uuid, String> = BTreeMap::new();
    let needs_own_service = matches!(surface, Surface::Inline | Surface::Rebind);
    for actor in w
        .actors
        .iter()
        .filter(|a| needs_own_service && a.label.ends_with("-agent"))
    {
        let (status, body) = w
            .send(
                w.client
                    .post(format!("{}/v1/services", w.base))
                    .header(auth(&actor.key).0, auth(&actor.key).1)
                    .json(&json!({"template_key": "shortcut", "name": "shortcut",
                                  "status": "active",
                                  "url": format!("http://{}", w.mock),
                                  "credentials": {"token": "shortcut_api_token"}})),
            )
            .await;
        assert_eq!(status, 200, "{}: {body}", actor.label);
        let svc: Value = serde_json::from_str(&body).unwrap();
        own_service.insert(actor.user, svc["id"].as_str().unwrap().to_string());
        // Skip the probe gate: the fake has no Shortcut probe route.
        sqlx::query("UPDATE service_instances SET status = 'active' WHERE id = $1::uuid")
            .bind(svc["id"].as_str().unwrap())
            .execute(&w.pool)
            .await
            .unwrap();
    }

    // Actors run concurrently: they are independent, and every write one
    // makes to a vault it may write is followed by its own restore, so the
    // last write to any vault is a restore whatever the interleaving.
    let w = &w;
    let own_service = &own_service;
    futures_util::future::join_all(w.actors.iter().map(|actor| async move {
            // Its own service echoes its own token — the positive control.
            if let Some(id) = own_service.get(&actor.user)
                && actor.label.ends_with("-agent")
                && surface == Surface::Inline
            {
                let (status, body) = w
                    .send(
                        w.client
                            .post(format!("{}/v1/actions/call", w.base))
                            .header(auth(&actor.key).0, auth(&actor.key).1)
                            // The action shape: it dials the instance's own `url` (the
                            // echoing fake). The verb shape would dial the template's
                            // real host.
                            .json(&json!({"service": "shortcut", "action": "search_stories",
                                          "params": {"query": "x"}})),
                    )
                    .await;
                let own = w
                    .vaults
                    .iter()
                    .find(|v| v.owner == Some(actor.user))
                    .unwrap();
                assert_eq!(status, 200, "{} own service: {body}", actor.label);
                assert!(
                    body.contains(&World::canary(own, "shortcut_api_token")),
                    "{} own service did not inject its own token: {body}",
                    actor.label
                );
                w.assert_no_leak(actor, "own service call", &body, None);
                let _ = id;
            }

            for target in &w.vaults {
                let owns_target = target.owner == Some(actor.user);
                // Inline is cheap, so it sweeps every name; the other surfaces
                // create rows per request and sweep the one name every vault
                // holds, keeping the suite's CPU cost in check.
                let names: &[&str] = if surface == Surface::Inline { &NAMES } else { &["canary"] };
                for &name in names {
                    for (spelled, mine) in spellings(w, actor, target, name) {
                        let ctx = format!("{} → {} as `{spelled}`", actor.label, target.label);

                        if surface == Surface::Inline {
                        // Inline (Mode A) — only the caller's own vault, ever.
                            let (status, body) = w
                                .send(
                                    w.client
                                        .post(format!("{}/v1/actions/call", w.base))
                                        .header(auth(&actor.key).0, auth(&actor.key).1)
                                        .json(&json!({
                                            "service": "http", "method": "GET",
                                            "url": format!("http://{}/echo", w.mock),
                                            "secrets": [{"name": spelled, "inject_as": "header",
                                                         "header_name": "X-Leak"}]
                                        })),
                                )
                                .await;
                            w.assert_no_leak(actor, &format!("inline {ctx}"), &body, None);
                            if !mine {
                                assert!(status >= 400, "inline accepted {ctx}: {status} {body}");
                            }


                    }

                    if surface == Surface::Bind {
                        // Binding a new service to it.
                            let (status, body) = w
                                .send(
                                    w.client
                                        .post(format!("{}/v1/services", w.base))
                                        .header(auth(&actor.key).0, auth(&actor.key).1)
                                        .json(&json!({"template_key": "shortcut",
                                                      "name": format!("probe-{}", Uuid::new_v4().simple()),
                                                      "url": format!("http://{}", w.mock),
                                                      "credentials": {"token": spelled}})),
                                )
                                .await;
                            w.assert_no_leak(actor, &format!("bind {ctx}"), &body, None);
                            if !mine {
                                assert!(status >= 400, "bind accepted {ctx}: {status} {body}");
                            }


                    }

                    // Rebinding its own service to it.
                        if surface == Surface::Rebind
                            && let Some(id) = own_service.get(&actor.user)
                        {
                            let (status, body) = w
                                .send(
                                    w.client
                                        .put(format!("{}/v1/services/{id}/manage", w.base))
                                        .header(auth(&actor.key).0, auth(&actor.key).1)
                                        .json(&json!({"credentials": {"token": spelled}})),
                                )
                                .await;
                            w.assert_no_leak(actor, &format!("rebind {ctx}"), &body, None);
                            if !mine {
                                assert!(status >= 400, "rebind accepted {ctx}: {status} {body}");
                            }
                            // Put it back on the owner's own token.
                            let _ = w
                                .send(
                                    w.client
                                        .put(format!("{}/v1/services/{id}/manage", w.base))
                                        .header(auth(&actor.key).0, auth(&actor.key).1)
                                        .json(&json!({"credentials": {"token": "shortcut_api_token"}})),
                                )
                                .await;
                        }
                    }

                    // The secrets API, by selector. `?scope=org` always names the
                    // caller's *own* org vault — there is no way to spell another
                    // org's — so that combination is the same-org case, covered
                    // when the loop reaches it.
                    if surface != Surface::SecretsApi
                        || (target.owner.is_none() && target.org != actor.org)
                    {
                        continue;
                    }
                    let selector = match target.owner {
                        Some(u) => format!("?owner={u}"),
                        None => "?scope=org".into(),
                    };
                    let (status, body) = w
                        .send(
                            w.client
                                .put(format!("{}/v1/secrets/{name}{selector}", w.base))
                                .header(auth(&actor.key).0, auth(&actor.key).1)
                                .json(&json!({"value": "OVERWRITTEN"})),
                        )
                        .await;
                    let same_org_admin = actor.is_admin && actor.org == target.org;
                    if !owns_target && !same_org_admin {
                        assert!(status >= 400, "{} overwrote {}: {body}", actor.label, target.label);
                    } else if status == 200 {
                        // The owner, or a same-org admin, may write; restore the
                        // canary for the sweep.
                        let _ = w
                            .send(
                                w.client
                                    .put(format!("{}/v1/secrets/{name}{selector}", w.base))
                                    .header(auth(&actor.key).0, auth(&actor.key).1)
                                    .json(&json!({"value": World::canary(target, name)})),
                            )
                            .await;
                    }
                    let (_, body) = w
                        .send(
                            w.client
                                .get(format!("{}/v1/secrets{selector}", w.base))
                                .header(auth(&actor.key).0, auth(&actor.key).1),
                        )
                        .await;
                    w.assert_no_leak(actor, &format!("list {}", target.label), &body, None);
                    if actor.org != target.org {
                        let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
                        assert!(
                            rows.is_empty(),
                            "{} listed {} across orgs: {body}",
                            actor.label,
                            target.label
                        );
                    }

                    // Reveal through a session, when the actor is a user.
                    if !actor.label.ends_with("-agent") {
                        let cookie = common::session_cookie(w.org_ids[actor.org], actor.user);
                        for path in ["versions/1/reveal", "versions/1/restore"] {
                            let (status, body) = w
                                .send(
                                    w.client
                                        .post(format!("{}/v1/secrets/{name}/{path}{selector}", w.base))
                                        .header("cookie", &cookie),
                                )
                                .await;
                            if !owns_target && !same_org_admin {
                                assert!(status >= 400, "{} {path} {}: {body}", actor.label, target.label);
                                w.assert_no_leak(actor, &format!("{path} {}", target.label), &body, None);
                            }
                        }
                    }
                }

                // A secret request aimed at the target's owner.
                if surface == Surface::SecretsApi
                    && let Some(u) = target.owner
                    && !owns_target
                    && !actor.is_admin
                {
                    let (status, body) = w
                        .send(
                            w.client
                                .post(format!("{}/v1/secrets/requests", w.base))
                                .header(auth(&actor.key).0, auth(&actor.key).1)
                                .json(&json!({"secret_name": "canary", "identity_id": u, "force": true})),
                        )
                        .await;
                    assert!(status >= 400, "{} requested into {}: {body}", actor.label, target.label);
                }
            }
    }))
    .await;

    sweep(w).await;
}

#[tokio::test]
async fn a_shared_org_service_crosses_users_but_never_orgs() {
    let w = build().await;
    let admin0 = w.actors.iter().find(|a| a.org == 0 && a.is_admin).unwrap();
    let everyone = everyone_group_id(&w.base, &w.client, &admin0.key).await;
    let (status, body) = w
        .send(
            w.client
                .post(format!("{}/v1/services", w.base))
                .header(auth(&admin0.key).0, auth(&admin0.key).1)
                .json(
                    &json!({"template_key": "shortcut", "name": "shared", "user_level": false,
                              "status": "active",
                              "url": format!("http://{}", w.mock),
                              "groups": [{"group_id": everyone, "access_level": "write",
                                          "auto_approve_level": "write"}],
                              "credentials": {"token": "shortcut_api_token"}}),
                ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let svc: Value = serde_json::from_str(&body).unwrap();
    sqlx::query("UPDATE service_instances SET status = 'active' WHERE id = $1::uuid")
        .bind(svc["id"].as_str().unwrap())
        .execute(&w.pool)
        .await
        .unwrap();
    let admin_vault = w
        .vaults
        .iter()
        .find(|v| v.owner == Some(admin0.user))
        .unwrap();
    let shared_canary = World::canary(admin_vault, "shortcut_api_token");

    for actor in w.actors.iter().filter(|a| a.label.ends_with("-agent")) {
        let (status, body) = w
            .send(
                w.client
                    .post(format!("{}/v1/actions/call", w.base))
                    .header(auth(&actor.key).0, auth(&actor.key).1)
                    .json(&json!({"service": "shared", "action": "search_stories",
                                  "params": {"query": "x"}})),
            )
            .await;
        if actor.org == 0 {
            // The sanctioned crossing: the admin's credential, for the grant.
            assert_eq!(status, 200, "{}: {body}", actor.label);
            assert!(body.contains(&shared_canary), "{}: {body}", actor.label);
            w.assert_no_leak(actor, "shared service", &body, Some(&shared_canary));
        } else {
            assert!(
                status >= 400,
                "{} reached org 0's shared service: {body}",
                actor.label
            );
            w.assert_no_leak(actor, "foreign shared service", &body, None);
        }
    }
    sweep(&w).await;
}

/// The final invariants, read straight from the DB.
async fn sweep(w: &World) {
    // No write landed: every canary is still exactly the value it was seeded
    // with, at v1 or restored to it.
    let rows: Vec<(Uuid, Option<Uuid>, String, i32)> = sqlx::query_as(
        "SELECT org_id, owner_identity_id, name, current_version FROM secrets
         WHERE org_id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&w.org_ids[..])
    .fetch_all(&w.pool)
    .await
    .unwrap();
    for vault in &w.vaults {
        for name in NAMES {
            let found = rows
                .iter()
                .filter(|(org, owner, n, _)| {
                    *org == w.org_ids[vault.org] && *owner == vault.owner && n == name
                })
                .count();
            assert_eq!(
                found, 1,
                "vault {} lost or duplicated `{name}`",
                vault.label
            );
            let version = rows
                .iter()
                .find(|(org, owner, n, _)| {
                    *org == w.org_ids[vault.org] && *owner == vault.owner && n == name
                })
                .unwrap()
                .3;
            // Read it back through its rightful owner (the org admin for the
            // org vault): the value is still the canary it was seeded with.
            let (reader, selector) = match vault.owner {
                Some(u) => (u, String::new()),
                None => (
                    w.actors
                        .iter()
                        .find(|a| a.org == vault.org && a.is_admin)
                        .unwrap()
                        .user,
                    "?scope=org".to_string(),
                ),
            };
            let cookie = common::session_cookie(w.org_ids[vault.org], reader);
            let reveal: Value = w
                .client
                .post(format!(
                    "{}/v1/secrets/{name}/versions/{version}/reveal{selector}",
                    w.base
                ))
                .header("cookie", cookie)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                reveal["value"],
                World::canary(vault, name),
                "vault {} `{name}` was overwritten",
                vault.label
            );
        }
    }

    // No user-level instance anywhere is bound outside its owner's vault or
    // the org vault.
    let bad: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT si.id, si.name, b.value
         FROM service_instances si,
              LATERAL (SELECT si.secret_name AS value
                       UNION ALL SELECT e.value FROM jsonb_each_text(si.credentials) e) b
         WHERE si.org_id = ANY($1)
           AND si.owner_identity_id IS NOT NULL
           AND b.value IS NOT NULL
           AND b.value NOT LIKE 'org/%'
           AND b.value NOT LIKE si.owner_identity_id::text || '/%'",
    )
    .bind(&w.org_ids[..])
    .fetch_all(&w.pool)
    .await
    .unwrap();
    assert!(bad.is_empty(), "foreign bindings: {bad:?}");

    // And no instance in one org names a vault of the other.
    for (i, org) in w.org_ids.iter().enumerate() {
        let other_users: Vec<String> = w
            .vaults
            .iter()
            .filter(|v| v.org != i)
            .filter_map(|v| v.owner.map(|u| u.to_string()))
            .collect();
        let bindings: Vec<(String,)> = sqlx::query_as(
            "SELECT b.value FROM service_instances si,
                  LATERAL (SELECT si.secret_name AS value
                           UNION ALL SELECT e.value FROM jsonb_each_text(si.credentials) e) b
             WHERE si.org_id = $1 AND b.value IS NOT NULL",
        )
        .bind(org)
        .fetch_all(&w.pool)
        .await
        .unwrap();
        for (b,) in bindings {
            assert!(
                !other_users.iter().any(|u| b.starts_with(u.as_str())),
                "org {i} binds into another org's vault: {b}"
            );
        }
    }
}
