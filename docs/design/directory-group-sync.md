# Directory group sync

**Status**: Implemented (OIDC claim source, Google Workspace Directory source)

Automatic provisioning of Overslash groups from an external directory. This
document covers the two sources that ship — the OIDC `groups` claim read at
sign-in, and a Google Workspace Directory pull — and the shape SCIM drops into
later.

Binding decisions: D107, *A directory group is a membership source, not a
ceiling*; and the Google Directory decision that refines it (see
[Google Workspace Directory source](#google-workspace-directory-source)).

---

## The problem

Overslash groups are Layer 1 of the permission model — the coarse ceiling a
request can never exceed. They have always been entirely manual. `groups`,
`group_grants` and `identity_groups` are admin-authored, and the only automatic
membership is the bootstrap seeding of Everyone / Admins / Myself. IdP
integration reads exactly four claims: `sub`, `email`, `name`, `picture`.

The consequence is Story 5 step 9 of [user-stories.md](user-stories.md): an
80-engineer org running Okta hand-assigns every new hire to a group after their
first login. The gap is recorded twice in that document — "Okta group →
Overslash group claim mapping" and, for the reverse direction, "IdP-driven
offboarding (SCIM)" — both noting that someone has to decide whether it is in
scope. This closes the first and leaves the second explicitly out.

## The model

Three objects, one responsibility each.

| | holds | written by |
|---|---|---|
| `directory_groups` | what the directory says exists | sync |
| `identity_directory_groups` | what it says about one human | sync, authoritatively |
| `group_directory_sources` | which Overslash group a directory group feeds | an admin |

A directory group is **not a ceiling**. It carries no grants, no rate limit and
no service visibility. It is the IdP's statement that some humans belong
together. It becomes access only where an admin has drawn the third-table edge.

**The reporter is part of a directory group's identity**, not an attribute of
it: the key is `(org_id, source, idp_config_id, external_id)`. Two IdPs are two
trust domains (D12), so Okta's `engineering` and Auth0's `engineering` are
different groups that happen to share a name, and merging them would let one
IdP's claim place people in a group the other IdP's users hold. It also breaks
revocation: membership is reconciled per `(idp_config_id, source)`, so a shared
row whose `idp_config_id` the second IdP's login had overwritten would fall
outside the first IdP's `DELETE` and its memberships could never be retracted —
access surviving a revocation. `NULLS NOT DISTINCT` keeps the later non-login
sources, which carry no `idp_config_id`, collapsing onto one row per group.

Effective membership is the view:

```sql
CREATE VIEW effective_identity_groups AS
    SELECT ig.identity_id, ig.group_id FROM identity_groups ig
    UNION
    SELECT idg.identity_id, gds.group_id
      FROM identity_directory_groups idg
      JOIN group_directory_sources gds
        ON gds.directory_group_id = idg.directory_group_id;
```

Exactly one hop. Directory groups cannot contain each other, so this is not
recursive and the ceiling query stays a flat join.

### Why not a fourth class of `groups`

The obvious shape is a `system_kind = 'external'` row under a reserved name
prefix (`google:engineering`), with the admin attaching grants to it directly.
It fails on the interaction with authoritative sync.

Authoritative sync has to delete. With derived membership in `identity_groups`,
that delete runs against the table holding every assignment an admin made by
hand, and correctness depends on every writer — now and later — respecting a
`source` discriminator. With the tables apart, the guarantee is structural:
`replace_memberships_for_identity` touches one table, that table holds nothing
an admin authored, and no bug in it can reach a manual assignment.

Two smaller consequences follow. The name prefix existed only to dodge
`groups_org_id_name_key`, a collision that cannot happen once the two live
apart. And `GET /v1/groups` stays about ceilings: otherwise the service-creation
picker, `GroupSearch`, `IdentityPickerModal` and the group list each learn to
exclude a fourth class — the tax `system_kind = 'self'` already charges once —
and an org with two hundred Okta groups buries the three that carry grants.

The cost is that a directory group confers nothing until an admin maps it.
That step was implied by containment anyway, and it is the step that keeps the
privilege decision with the admin.

## Trust rules

1. **Only an org's own IdP may speak about that org.** Sync runs only off an
   enabled `org_idp_configs` row with `group_sync_enabled`. A dedicated row
   already wins over managed sign-in in
   `org_signin::resolve_org_signin_credentials`, so its presence is what
   identifies the IdP this login came through. A `groups` claim on the
   Overslash-managed path comes from the operator's shared Google/GitHub OAuth
   app and says nothing about this org — D12.
2. **An absent claim is not an empty claim.** `None` (key missing, JSON null,
   or an unparsed shape) changes nothing. `Some([])` revokes. Collapsing them
   would let an upstream claim rename strip every user's derived access at the
   next sign-in.
3. **System groups refuse a directory source.** Admins membership is held in
   lockstep with `identities.is_org_admin`; a mapping would confer org-admin
   without setting the flag. Myself has one member by construction and Everyone
   already holds the org. `is_identity_in_admins` deliberately reads the base
   table, not the view, so this survives a bypassed handler guard.
4. **`kind = 'user'` only.** Agents inherit their owner-user's ceiling and hold
   no membership of their own.
5. **Membership is not authorization.** The ceiling is whatever the admin
   granted the mapped group. This mirrors D12's "availability is not
   membership" one layer down.

## Flow

```
sign-in ──▶ /userinfo claims ∪ id_token claims
              │
              ├─ org_idp_configs row? enabled? group_sync_enabled?  ── no ─▶ stop
              │
              ├─ claim present?                                     ── no ─▶ stop
              │
              ├─ upsert directory_groups (one per claim value)
              └─ reconcile identity_directory_groups
                    scoped to (idp_config_id, source)
                    audit `identity.directory_groups_synced` on a real delta
```

The sync hangs off a wrapper around `provision_org_subdomain`, not inside it.
The resolver has four success paths — known `external_id`, adopt-by-user,
adopt-by-email, fresh admission — and every one produces a human whose groups
the IdP just re-asserted; hanging the call on the single exit means a fifth
path cannot be added without it.

A failure is logged and the sign-in proceeds. A stale ceiling is repaired at
the next login; a user locked out of the dashboard because their IdP changed a
claim shape is not recoverable by anything they can do.

### Reading the claim

`/userinfo` and the ID token are merged, `/userinfo` winning. Both are needed:
Okta and Auth0 can release groups on `/userinfo`, **Entra will not** on the v2
endpoint.

The ID token's signature is not verified. OIDC Core §3.1.3.7 permits this for a
token fetched directly from the provider's token endpoint over TLS, in response
to a code we generated and bound with PKCE — there is no third party in the
path to forge it. What *is* checked is `nonce`, against the value this login
minted; a mismatch discards the token's claims entirely. Hardening to
`jwks_uri` verification is tracked in TECH_DEBT.md.

Accepted claim shapes: an array of strings, and a bare string. Non-string
elements are skipped rather than voiding the list, because one malformed entry
should not act as a revocation. `group_claim` is configurable because there is
no convention — Okta and Entra both use `groups` (names vs object GUIDs, which
is why `external_id` and `display_name` are separate columns), and Auth0 needs
a namespaced claim such as `https://acme.com/groups`.

## Surface

| Method | Path | Auth |
|---|---|---|
| `GET` | `/v1/directory-groups` | any member |
| `GET` | `/v1/directory-groups/{id}` | any member |
| `GET` | `/v1/directory-groups/{id}/members` | any member |
| `GET` | `/v1/groups/{id}/directory-sources` | any member |
| `POST` | `/v1/groups/{id}/directory-sources` | admin; 400 on a system group |
| `DELETE` | `/v1/groups/{id}/directory-sources/{directory_group_id}` | admin |
| `GET` | `/v1/groups/{id}/member-origins` | any member |

`GET /v1/groups/{id}/members` is unchanged — it returns a bare id list and is
already consumed, so origin detail rides alongside rather than reshaping a live
response. `DELETE /v1/groups/{id}/members/{identity_id}` answers **409** when
the membership is directory-derived: there is no manual row to delete, so the
removal would report success and change nothing while the admin believed access
was revoked.

Dashboard: a *Directory groups* section on `/org/groups` (discovered groups,
member counts, mapped-to pills), a detail page at
`/org/directory-groups/{id}`, a *Directory sources* card on the group detail
page, a `via <group>` badge with the remove button suppressed on derived
members, and a per-IdP *Group sync* column on `/org`.

Every add-a-pill affordance is the shared `PillPicker` component: the pills,
then a `+` that opens a searchable dropdown. Deliberately not `GroupSearch`,
which is an always-open chip *input* — right for a create form, wrong for a
relationship that already exists and is edited occasionally, where a permanent
search box reads as an unfinished form.

The detail page exists because a directory group is a thing an admin reasons
about on its own: who the IdP puts in it, what it grants, when it was last
seen. The list row answers none of those beyond a count, and the mapping edge
is the one place a directory group turns into access, so it deserves a page
rather than a cell.

## Google Workspace Directory source

Google never releases group membership in its ID token or on `/userinfo`, so an
org that signs in with Google gets nothing from the claim path. This source
reads the Admin SDK Directory API instead and writes the same two tables under
`source = 'google_directory'`, `idp_config_id = NULL`. Mapping, the view, and
the rule that discovery grants nothing are all unchanged — it is a second
writer, not a second model.

### Credential: one service account per instance

The instance has **one** service account with **domain-wide delegation** for
exactly one scope, `admin.directory.group.readonly`. Every org syncs through it.
The operator supplies its JSON key through `OVERSLASH_GOOGLE_DIRECTORY_SA_KEY`
(the key itself — how a Secret Manager value surfaces on Cloud Run) or
`OVERSLASH_GOOGLE_DIRECTORY_SA_KEY_FILE` (a path — a mounted Kubernetes or
Docker secret). It is parsed at boot: a malformed key, an unreadable file, or
both variables set stops the process. Unset means the feature is off on that
instance, and the dashboard says so. There is no per-org credential of any
kind. Operator setup: [runbooks/google-directory.md](../runbooks/google-directory.md).

A Workspace admin's whole job is in admin.google.com: add the instance's
**client ID** with that scope under *Domain-wide delegation*. The dashboard
shows both values, with copy buttons, before anything is connected.

Chosen over per-org keys (the first cut, D110) because a customer should not
need a Google Cloud project, the Admin SDK switched on in it, and a downloaded
key to share with us; and over an admin's OAuth consent because consent stops
working when the person who clicked "connect" leaves or loses the admin role,
and the sweep runs with nobody signed in.

The key's own `token_uri` is **ignored**. Assertions are always exchanged at
`https://oauth2.googleapis.com/token`.

### Proving which Workspace an org is

One shared service account means every connected Workspace has delegated to
the same client ID, so **Google no longer separates tenants — Overslash must.**
If an org could simply type an admin email, org A could enter
`admin@victim.com` and read the victim's groups.

So an org connects by **signing in with Google** as an admin of the Workspace
(`POST /v1/google-directory/connect` → Google → `/auth/callback/google`):

- **What Google says is the config.** The `hd` (hosted domain) from Google's
  `/userinfo` becomes `domain`; the verified email becomes `admin_subject`, the
  account the service account impersonates. Nothing is typed. A personal Google
  account has no `hd` and is refused; so is an unverified email or one outside
  `hd`.
- **Proving it is also probing it.** Before saving, the instance service
  account reads one page of groups as that admin. That single call checks the
  delegation grant (`unauthorized_client` → "add the client ID") and the admin
  privilege (403 → "sign in as an admin") together.
- **One org per Workspace per instance** (`UNIQUE (lower(domain))`). A second
  org cannot attach a Workspace someone else connected.
- **The link only works in the browser that asked for it.** The flow row is
  single-use, expires in ten minutes, and is bound to the admin who started it;
  the callback refuses any browser whose live session is someone else's.
  Without that, an org admin could mail the Google link to another Workspace's
  admin and attach that directory to their own org.

The connect rides the login's already-registered redirect URI with a
`gdir:<flow id>` state, so operators register nothing new — but the instance
needs its Google sign-in client (`GOOGLE_AUTH_CLIENT_ID/SECRET`) for the proof.

Reconnecting as a different Workspace disconnects the old one first: its
groups are not the new one's.

### Who it may speak about

**The connected domain is the trust boundary**, not the sign-in path. The
Workspace was proven to be the org's, so it may speak about the org's humans
whichever IdP they signed in through — but only about those whose email is
under `domain`. Anyone else is never touched, whatever Google reports. Matching
is by lower-cased email, judged by the part after the last `@`.

### Three triggers

| Trigger | Scope | Blocking? |
|---|---|---|
| Sign-in | that user: `groups?userKey=<email>` | no — spawned; the callback never waits on Google |
| Periodic sweep | the whole directory | background, every `sync_interval_hours` (default 8, 1–168) |
| **Sync now** | the whole directory | queues a sweep; at most one can be queued |

Sweeps go through one worker loop per replica
(`services/google_directory_worker.rs`) that leases due rows with
`FOR UPDATE SKIP LOCKED`, so replicas share work without two of them sweeping
the same org. A 15-minute lease covers a replica that dies mid-sweep.

**The manual queue is one nullable column**, `sync_requested_at`. Clicking sets
it only if it is `NULL`, so no number of clicks queues a second run — the API
answers `already_queued` and writes nothing. The claim clears it, so a click
that lands *during* a sweep queues exactly one follow-up instead of being
swallowed by the run in progress. The dashboard disables the button while a
run is queued.

### Direct membership only

Both paths read direct membership: nested groups (`type = GROUP`) are skipped
and `includeDerivedMembership` is not used. If the sweep expanded nesting but
`userKey` did not, membership would flap between sign-in and sweep. It also
keeps a directory group one hop from a ceiling, as above.

### A partial listing never revokes

The sweep is authoritative — someone Google no longer lists in a group loses
the membership — so it applies the same rule the claim path does: an absent
answer is not an empty one. Every page of every listing must succeed before a
single membership row changes. A 500 on page two of one group's members fails
the run (`last_sync_status = 'error'`, with Google's message) and revokes
nothing. A group deleted in Google keeps its row, and so the admin's mapping,
but loses its members; `last_seen_at` shows the staleness.

**Pausing** (`enabled = false`) stops syncing and keeps what the last sync
established. **Disconnecting** (`DELETE`) removes the connection and every
`google_directory` directory group, which cascades to memberships and
mappings: derived access is revoked at once.

### Surface

| Method | Path | Auth |
|---|---|---|
| `GET` | `/v1/google-directory` | admin; the instance's client ID + scope, and the org's connection or `null` |
| `POST` | `/v1/google-directory/connect` | admin (signed in); returns the Google `auth_url` |
| `PUT` | `/v1/google-directory` | admin; schedule and pause only |
| `DELETE` | `/v1/google-directory` | admin; disconnects |
| `POST` | `/v1/google-directory/sync` | admin; 202 `queued`, or 200 `already_queued` |

Dashboard: the *Google Workspace* section of Org Settings
(`/org/google-directory`). Before connecting it leads with *Authorize Overslash
in Google Admin* — the admin-console path, then the client ID and the scope,
each with a copy button — and a *Sign in with Google to connect* button. After,
it shows the Workspace, the admin it acts as, the schedule, the last sync,
*Sync now*, pause, reconnect and disconnect. Google groups carry a *Google
Workspace* tag in the *Directory groups* list.

## Deliberately not built

- **SCIM 2.0 push.** Same tables, `source = 'scim'`. Also the natural home for
  the offboarding half of the user-stories gap.
- **A periodic sweep for the claim source.** Its stale window is a session
  lifetime, and it has no credential to sweep with. The Google source has one.
- **Nested Google groups.** See *Direct membership only* above.
- **General group-in-group nesting.** Would make the view recursive and needs
  cycle detection. Nothing here blocks it.
- **ID-token signature verification.** See TECH_DEBT.md.
