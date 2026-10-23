# Admin step-up — applying and evidencing it

CASA 3.3.1 ("administrative interfaces use MFA") and 2.4.1 ("re-auth before sensitive
transactions"). The decision is D-NEXT in [DECISIONS.md](../../DECISIONS.md), *"Admin-class
mutations need a fresh IdP sign-in"*.

## What shipped (code)

- `user_sessions` records how each session was signed in (migration 137): `auth_method`
  (`idp` / `magic_link` / `dev` / NULL), `auth_provider`, `authenticated_at`, and the ID
  token's `amr` / `acr`. A switch-org re-scope keeps them.
- `AdminAcl` and `InstanceAdminAuth` refuse any non-GET request from a dashboard session
  unless it is an IdP sign-in, through a provider the org signs in with, from the last
  `ADMIN_STEP_UP_MAX_AGE_SECS` (default 3600). The refusal is 403 `step_up_required`
  (`crates/overslash-api/src/services/admin_step_up.rs`).
- The dashboard shows *Confirm it's you* (`StepUpModal.svelte`), which sends the human
  through `/auth/login/{key}?step_up=true`. For an OIDC IdP that adds `max_age=0`, so
  the IdP re-authenticates and runs its MFA. Afterwards the human lands back on the same
  page with a new session. For an org with no IdP of its own the link goes to the root
  login with `step_up_org`, and the callback re-scopes the new session back into that org
  if the human is a member.
- Account → Sessions shows each session's sign-in method and the `amr` the IdP reported.
- `/v1/org-idp-configs` create, update, delete and discover now require `AdminAcl`.
  Before this, any credential in the org could call them, including an agent key.

Out of scope: personal orgs, API keys and MCP tokens, reads, and the API's own stateless
loopback token.

The migration runs in-process on deploy, like every other migration. No backfill is
needed: sessions created before it have NULLs, and their admins see the prompt once.

## The infra half (not auto-applied)

`infra/` now renders the window explicitly, so it can be cited from the plan:

| Where | Change |
|---|---|
| `infra/variables.tf`, `infra/modules/cloud-run/main.tf` | `admin_step_up_max_age_secs` (number, 1–86400, default 3600) → `ADMIN_STEP_UP_MAX_AGE_SECS` |
| `infra/env/prod.tfvars`, `infra/env/dev.tfvars` | `admin_step_up_max_age_secs = 3600` |

This is **in code, pending apply**. Because the app's default is the same 3600, the gate
is already live from the deploy alone. The apply only makes the value visible and pinned.

### Apply

Dev first, then prod. The plan must show exactly one in-place update to the Cloud Run
service (a new revision with the extra env var) and nothing else:

```bash
# from the repo root
make tofu-plan ENV=dev      # expect: ~ google_cloud_run_v2_service.api, + env ADMIN_STEP_UP_MAX_AGE_SECS = "3600"
make tofu-apply ENV=dev
make tofu-plan ENV=prod
make tofu-apply ENV=prod
```

### Verify

```bash
# 1. The revision carries the variable.
gcloud run services describe overslash-prod-api --region=europe-west1 --project=overslash \
  --format='value(spec.template.spec.containers[0].env)' | tr ';' '\n' | grep ADMIN_STEP_UP

# 2. The migration ran.
#    (db-shell / cloud-sql-proxy, read-only)
SELECT column_name FROM information_schema.columns
 WHERE table_name = 'user_sessions' AND column_name IN ('auth_method','authenticated_at');

# 3. A magic-link session cannot make an admin change in a shared org.
#    Sign in with an email link, switch to a shared org you administer, and try any
#    admin change (e.g. create a group). Expect the "Confirm it's you" prompt and, in
#    the network tab, 403 {"error":"step_up_required","reason":"idp_required",…}.

# 4. A step-up clears it. Continue with the org's IdP; the IdP must challenge
#    (password and/or second factor), you land back on the page, and the change
#    succeeds. Account → Sessions now shows the session "with Google" (or the org's IdP).
```

## MFA at the IdP — the written answer's other half

Overslash does not have a second factor of its own. 3.3.1 is answered by delegation, and
delegation is only true if the IdP actually enforces MFA. For each population:

| Who | Where MFA is enforced | Operator step |
|---|---|---|
| Overslash's own operators (instance admins, admins of the Overslash org) | Google Workspace 2-Step Verification, **enforced** for the domain; GitHub organization *Require two-factor authentication* | Confirm both settings are on and screenshot them (Admin console → Security → 2-Step Verification → *Enforcement: On*; GitHub org → Settings → Authentication security) |
| Customer orgs with their own IdP (Okta, Entra, Workspace) | The customer's IdP policy | None. This is the customer's control. The lab answer says so, and the org's admins can only reach admin actions through that IdP |
| Customer orgs signing in through Overslash-managed Google / GitHub | The human's Google / GitHub account settings | None enforceable by us. The prompt still forces a fresh IdP round-trip, and `amr` is recorded where Google sends it |

## Evidence to capture

For [evidence-index.md](../compliance/casa/evidence-index.md), 3.3.1:

1. The step-up prompt from verify step 3. `dashboard/scripts/screenshot-step-up.mjs`
   produces it against the e2e stack (`step-up-modal.png`).
2. The IdP's MFA challenge from verify step 4, on prod, with an operator account.
3. Account → Sessions after that sign-in, showing the IdP and the `amr` line (Google
   sends `amr` only sometimes; capture it when present).
4. The two IdP enforcement settings from the table above.

## Break-glass

- **An org's only IdP is broken** (expired client secret, IdP outage). Its admins cannot
  pass the gate, so they cannot fix the config either. An operator disables the row, which
  makes the rule "any IdP" again. The admin can then sign in with Google or GitHub at the
  root, switch to the org and repair the config:
  ```sql
  UPDATE org_idp_configs SET enabled = false WHERE org_id = '<org>' AND provider_key = '<key>';
  ```
  Record the change in the incident log. Re-enabling it is then an ordinary admin action.
- **The prompt is too frequent.** Raise `admin_step_up_max_age_secs` (at most 86400) and
  re-apply. Anything above a working day weakens the 2.4.1 answer. Say so in the
  assessment if you change it.
- **Self-hosted, no IdP at all.** With no Google/GitHub credentials and no org IdP, a
  fresh magic link qualifies instead and the prompt offers an email link. Adding an IdP
  removes that fallback automatically.
