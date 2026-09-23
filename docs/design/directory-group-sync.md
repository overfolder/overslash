# Directory group sync

**Status**: Implemented (OIDC claim source)

Automatic provisioning of Overslash groups from an external directory. This
document covers the OIDC `groups`-claim source that ships now, and the shape
the Google Admin SDK and SCIM sources drop into later.

Binding decision: D-NEXT, *A directory group is a membership source, not a
ceiling*.

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
member counts, mapped-to chips, map-to picker), a *Directory sources* card on
the group detail page, a `via <group>` badge with the remove button suppressed
on derived members, and a per-IdP *Group sync* column on `/org`.

## Deliberately not built

- **Google Admin SDK / Cloud Identity pull.** Writes the same tables with
  `source = 'google_directory'`. Needs a stored org-level credential and a
  sensitive-scope review; the `source` column and the nullable `idp_config_id`
  exist for it.
- **SCIM 2.0 push.** Same tables, `source = 'scim'`. Also the natural home for
  the offboarding half of the user-stories gap.
- **A periodic sweep.** The stale window today is a session lifetime. The
  anchored-claim pattern in `services/webhook_digest.rs` is the model.
- **General group-in-group nesting.** Would make the view recursive and needs
  cycle detection. Nothing here blocks it.
- **ID-token signature verification.** See TECH_DEBT.md.
