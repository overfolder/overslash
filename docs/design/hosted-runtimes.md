# Hosted Runtimes

**Status:** Draft — Phase 0 in progress, Phase 1 under discussion
**Date:** 2026-11-09

---

## Problem

`services/whatsapp.yaml` and `services/telegram.yaml` ship as out-of-the-box
templates, but neither works out of the box. Each one points at a container the
user must run themselves (`whatsapp-mcp-docker`, `fast-mcp-telegram`), publish
over https, and pair. The user then pastes the URL and the container's
`AUTH_TOKEN` into Overslash. Most orgs can't do that, so for them WhatsApp and
Telegram don't exist.

Email had the same problem until D39. overfwd is stateless and shared, so
Overslash runs it once (`mailbox.overslash.com`) and supplies its key from a
platform rung below the org vault. The goal here is to give WhatsApp and
Telegram the same experience: create the instance, pair the phone, done.

The difference from overfwd is **session state**. A WhatsApp or Telegram
session is a long-lived login. Whoever holds it effectively holds the account,
and it has to stay connected to receive messages. That rules out "just deploy
it like overfwd" *unless the servers themselves change shape*, which is what
Phase 0 asks of them.

`external-mcp-services.md` lists "Hosted MCP runtime" and "Stateful sessions"
as non-goals. This document narrows those non-goals; it does not reverse them
wholesale. The earlier `feat/mcp-hosting` branch tried general hosting and grew
to 91 commits. Both phases below are deliberately narrow.

## Two phases

| | Phase 0 — platform-hosted gateways | Phase 1 — Overslash nodes |
|---|---|---|
| What runs | one shared Cloud Run service per hosted runtime, as with overfwd | `overslash-node` hosts running catalog workloads |
| Who adapts | **each runtime**: multi-tenant and stateless | Overslash: scheduler, ingress, egress, catalog |
| Overslash changes | small: platform credentials for several hosts, MCP gateway header, generated session tokens, Terraform | large: new binary, new tables, new transport |
| Unlocks | WhatsApp, Telegram and email out of the box in Overslash Cloud | self-hosted pools, bring-your-own nodes (incl. behind NAT), dedicated placement, third-party images that can't serve many tenants |
| Status | **in progress** | design under discussion; nothing built |

Phase 0 is the plan. Phase 1 is recorded in full below because most of its
decisions survive into whatever we build later, and because Phase 0 was chosen
*knowing* what Phase 1 costs.

---

## Phase 0 — platform-hosted multi-tenant gateways

### Shape

```
Agent ──► Overslash API ──► https://whatsapp-mcp.overslash.com/mcp   (Cloud Run, gVisor)
                       │       Authorization: Bearer <session token>    ← per instance, minted by Overslash
                       │       X-Gateway-Key: <platform key>            ← platform rung, host-pinned
                       ├──► https://telegram-mcp.overslash.com/mcp     (same shape)
                       └──► https://mailbox.overslash.com/email/*      (overfwd, D39, unchanged)
```

Each hosted runtime is one Cloud Run service. It needs no VPC connector, runs
as a service account with no roles, and uses a digest-pinned image pulled
through our Artifact Registry. In other words, it is the overfwd module again
(`infra/modules/cloud-run-overfwd/`).

### What each runtime must do (its side of the contract)

The runtimes are ours to version: `whatsapp-mcp-docker` is ours, and
`fast-mcp-telegram` gets a fork if upstream doesn't take the change. Each one
commits to:

1. **Multi-tenant.** A single process serves many sessions. The session
   token in `Authorization: Bearer` selects the tenant.
2. **Stateless containers.** Durable state lives outside the container:
   Postgres for whatsmeow, and object storage (S3/GCS) for Telethon sessions.
   Cloud Run can then replace an instance without losing sessions. Reconnecting
   after a replacement is the runtime's job.
3. **A gateway key.** Every request must carry the deployment key in
   `X-Gateway-Key`, or the server refuses it (`401`). This is the outer key,
   equivalent to overfwd's `OVERFWD_API_KEY`.
4. **Lazy session creation.** An unknown session token arriving with a valid
   gateway key creates an empty, unpaired session. That removes the need for a
   provisioning API, so Overslash needs no create hook (see "Session tokens"
   below).
5. **Pairing through MCP tools**, as `whatsapp.yaml` already declares
   (`pairing_start` / `pairing_complete`). Telegram's fork exposes the same
   pair of tools over Telethon's QR login, replacing the anonymous `/setup`
   page.
6. **Garbage collection.** Sessions that were never paired, or that have been
   logged out or idle for N days, are deleted server-side, much like
   fast-mcp-telegram's `TELEGRAM_INACTIVE_SESSION_DAYS`. Overslash does not
   call the runtime when an instance is deleted. This makes orphaned sessions
   a retention problem, not a security one, because a session is reachable
   only with both keys.
7. **Store only token hashes**, so a database dump yields no usable tokens.
8. **Exactly one live connection per session.** If Cloud Run runs more than
   one instance, the runtime must lease each session to one of them (for
   example with a Postgres advisory lock). Until it does, the service runs with
   `max_instances = 1`.

### What Overslash changes (PR "hosted gateways on Cloud Run")

- **Platform credentials for several hosts.** D39's single
  `OVERSLASH_PLATFORM_GATEWAY_{SECRET_NAME,HOST,KEY}` triple becomes a list.
  The unsuffixed triple still works, and each extra entry is
  `OVERSLASH_PLATFORM_GATEWAY_<ID>_{SECRET_NAME,HOST,KEY}`. Every entry stays
  pinned to its own host. D39 said "generalise when a second one appears", and
  now two have.
- **An MCP gateway header.** `x-overslash-mcp.auth` (kind `bearer`) gains an
  optional `gateway` block:
  `{ header: X-Gateway-Key, default_secret_name: whatsapp_gateway_key, optional: true }`.
  The value follows the cascade overfwd's `gateway` scheme uses: the org vault
  first (only on URLs the org tier points at, per `OrgVaultGate`), then the
  platform rung (host-pinned), then the header is left out. A self-hosted,
  single-tenant container therefore keeps working unchanged.
- **Generated session tokens.** `x-overslash-mcp.auth.generate: true` means
  that an instance created with no `secret_name` and no URL of its own gets a
  fresh random token. The token is written to the owner's vault and bound as
  the instance's secret. An instance that names its own URL is talking to the
  user's own container, so it must still bring that container's token.
- **Template hosts through variables.** `whatsapp.yaml` sets
  `url: ${WHATSAPP_MCP_URL?}` and `telegram.yaml` sets
  `url: ${TELEGRAM_MCP_URL?}`. The `?` form (D44) means that leaving the
  variable unset reproduces today's "bring your own URL" template exactly.
- **Terraform.** A generic Cloud Run gateway module is instantiated per hosted
  runtime (`enable_whatsapp_gateway`, `enable_telegram_gateway`), with digest
  pins, a Terraform-generated key in Secret Manager, a domain mapping, and the
  matching `OVERSLASH_PLATFORM_GATEWAY_<ID>_*` and
  `OVERSLASH_TEMPLATE_VAR_*` env vars on the API, all derived from one domain
  variable so they can't drift (the D44 lesson).

Nothing changes for overfwd.

### Session tokens, end to end

```
create instance (no url, no secret)
  └─ kernel_create_service: template has auth.generate → mint 32 random bytes
       → owner vault secret `<instance>_session_token` → instance.secret_name
pair
  └─ dashboard / agent → actions/call pairing_start
       → Authorization: Bearer <token>, X-Gateway-Key: <platform key>
       → runtime sees an unknown token + valid key → creates the session → returns the QR code
use
  └─ every MCP call carries the same two headers
delete instance
  └─ the vault secret goes with the instance; the runtime GCs the orphaned session later
```

The user never sees either key. The token sits in the vault like any other
instance secret, so it rotates, versions and audits the same way.

### Safety

- **Both keys are needed.** A leaked gateway key reaches no tenant's data. A
  leaked session token is useless without the gateway key. Both together
  expose exactly one session.
- **Host pinning.** The platform key is only ever sent to its own host. An org
  that points its instances at a self-hosted gateway, or at an attacker's,
  receives nothing.
- **Isolation.** Tenants are separated by the runtime's own code, the same
  trust model as overfwd. Cloud Run's sandbox, the role-less service account
  and the missing VPC connector keep a compromised runtime away from
  everything else.
- **Fairness.** Each runtime caps sessions per gateway key and per process.
  Per-org caps on hosted instances belong to the quota work in Phase 1, and
  Phase 0 relies on the runtime's own caps.

### Open in Phase 0

- Pairing in the dashboard. The generic pairing panel (declared in the
  template's YAML, see Phase 1) is wanted, but it does not block Phase 0.
  Until it lands, agents can drive `pairing_start` themselves.
- Telegram's fork: pairing tools over QR login, object-storage sessions, lazy
  creation.

---

## Phase 1 — Overslash nodes (design under discussion)

Recorded from the design grilling of 2026-11-09. Settled answers are marked ✅,
open ones ❓. Nothing here is built.

### Architecture

```
Overslash API (control plane)                     overslash-node (GCE VM, Debian)
──────────────────────────────                    ───────────────────────────────
nodes · hosted_sessions (desired state)  ◄──────  register + heartbeat (node key)
hosted:// resolver ──── HTTPS 10.x:7443 ───────►  ingress ──► workload (gVisor)
                        node key + session token        nftables CIDR egress ──► internet
```

- ✅ **Phase 1 scope:** the node plus a `docker` driver, runnable on a GCE VM.
  Everything else is sketched as future work.
- ✅ **Who runs nodes:** the deployment operator. Overslash Cloud runs
  multi-org nodes, so WhatsApp works out of the box. Adding a hosted runtime
  is gated behind a reviewed repo PR and a node release.
- ✅ **Packaging:** a separate `overslash-node` crate and binary. `overslash
  node` runs that binary if it's installed, or prints how to install it.
- ✅ **Catalog:** `hosted_runtimes/` ships the same way `services/` does. The
  node embeds the image digests at build time and refuses anything outside
  them, so the API assigns hosted runtimes by **key only** (never an image or
  env). A compromised API can therefore only schedule catalog entries.
- ✅ **v1 hosted runtimes:** whatsapp, telegram, overfwd.
- ✅ **Transport: direct.** The API calls the node's private ingress (Direct
  VPC egress from Cloud Run), and bodies stream through. A long-poll queue
  through Postgres was rejected. A reverse tunnel comes later, for nodes
  behind NAT or CG-NAT, eventually including user-added tools hosted on
  phones.
- ✅ **`hosted://<runtime>/<path>`** may appear in instance URLs, template
  `servers[0]` and `mcp.url`. The resolver picks a node and a transport, and
  only these URLs skip the SSRF and https checks, because their address comes
  from the `nodes` table, not from user input. Example: `email.yaml` →
  `${MAILBOX_HOST:hosted://overfwd}`.
- ❓ **Q40:** keep the pool out of the URL. The host part is always the hosted
  runtime key. The resolver returns `HostedTarget::{Direct, Tunnel}` (only
  `Direct` in Phase 1), and `nodes` gets `reachability` and `pool` columns
  from day one, so tunnels slot in without changing any URL.
- ✅ **Placement: all shared.** Each node runs one workload per hosted runtime,
  and creating a session takes milliseconds. Multi-session WhatsApp is a
  prerequisite. A dedicated workload per session is future work.
- ✅ **Isolation:** gVisor (`runsc`) with resource limits, dropped
  capabilities, `no-new-privileges`, a read-only rootfs, a non-root user, and
  one network per workload. `--allow-runc` exists for self-hosters only.
- ✅ **Egress:** each catalog entry lists **CIDR allowlists**, enforced by
  nftables on each workload's network. Private ranges are allowed only with an
  explicit annotation, and `169.254.169.254` never. DNS-pinned filtering was
  rejected as too weak, and an egress proxy is a maybe for later.
- ✅ **Node auth:** one `OVERSLASH_NODE_KEY` that both sides read, plus
  `_PREVIOUS` for rotation. It is generated by Terraform into Secret Manager
  and used for registration and for API → node calls. There are no per-node
  keys.
- ✅ **GCP:** a fixed number of Debian GCE VMs (`infra/modules/gce-node/`).
  Day 1: Shielded VM, no external IP (Cloud NAT), OS Login via IAP, a
  service account limited to logs and metrics, unattended-upgrades, the Ops
  Agent, and images only through our Artifact Registry. Day 2: CMEK, periodic
  recreation, and an entry in the CASA inventory.
- ✅ **Org budget:** a pooled `hosted_units` budget per org (default 4,
  overfwd costs 0) → `409 hosted_quota_exceeded`. **Node cap:**
  `max_sessions_per_node` → `503 hosted_capacity_exhausted`, alerting at 80%.
- ✅ **Token storage:** a `hosted_sessions` table (instance_id, runtime,
  node_id, AES-GCM token, status, last_seen), outside the user-facing vault
  and read only by a new `hosted_binding` policy (rule 7).
- ✅ **Provisioning:** synchronous inside `kernel_create_service`, so a failure
  leaves no row. A reconciler runs every 5 minutes, deleting orphaned sessions
  and marking lost ones "re-pair required".
- ✅ **Pairing declared in template YAML.** One generic dashboard panel runs
  the image's own MCP tools through `/v1/actions/call`:

  ```yaml
  x-overslash-hosted:
    runtime: whatsapp
    pairing:
      start:  { tool: pairing_start }
      poll:   { tool: pairing_complete, args: { wait_seconds: 20 } }
      qr:     .structured.qr
      code:   .structured.code // empty
      done:   .structured.status == "success"
      failed: .structured.status == "error"
  ```
- ✅ **Upgrades:** a node release restarts the workload. A short reconnect gap
  is acceptable.
- ✅ **Dev and tests:** `make local` runs a node. A `dummy` hosted runtime
  (tools `echo`, `sleep`, `fail`, `big_payload`, plus a fake QR pairing flow)
  is compiled in only under a test feature, for CI and debugging.
- ✅ **Dashboard:** a choice between "Hosted by Overslash" and "My own server"
  on the instance form, a status chip, the pairing panel, and an org-admin
  list of hosted runtimes and sessions. The platform operator's node list is
  deferred until there is an operator admin panel.
- ❓ **Q27/Q35, session lifecycle:** is create/list/delete (A) a fixed contract
  inside our versioned images, or (C) a YAML mapping onto each image's own
  admin API, in the style of pairing? Node-side adapters (B) were rejected.
  Phase 0's lazy creation plus GC sidesteps this question for now.
- ❓ **Q28, term:** "driver" (docker / podman / VM / exec), each declaring an
  isolation level of `process`, `container`, `sandbox` or `vm`.
- ❓ **Q38, non-goals:** no general scheduler, bin-packing, overlay network,
  rolling deploys, autoscaling or arbitrary workloads. If we need more than one
  of those, we adopt Nomad or k8s *as a driver* rather than grow the node.
- ❓ **Q39, images:** our versioned images are built in CI from `overspiral`
  repos into our own Artifact Registry and pinned by digest.
- ❓ **Q41, lifecycle:** the API assigns a hosted runtime to a node only while
  it has sessions there, or while it is a sessionless runtime the deployment
  actually resolves to. The first session waits for the workload to report
  ready (about 10 s at most), and removal waits a 30-minute grace period.
  Images are pre-pulled at boot. Nothing starts or stops per request.

### Glossary

| Term | Meaning |
|---|---|
| hosted runtime | A catalog entry: `whatsapp`, `telegram`, `overfwd`. Always written in full, because "runtime" already means `x-overslash-runtime`. |
| workload | A hosted runtime's running container on one node. |
| node | A host running `overslash-node`. |
| pool | All the nodes of one deployment (later: one org's own nodes). |
| hosted session | One tenant inside a workload, tied 1:1 to a service instance. overfwd has none. |
| placement | `shared` (many sessions per workload) or `dedicated` (one workload per session). |
| platform operator | Whoever runs the deployment. Not "instance admin", because "instance" means service instance. |

### Alternatives rejected along the way

- **Overslash deploys each tenant's Cloud Run service itself.** That gives the
  API project-wide deploy rights, doesn't port to self-hosting, and ties us to
  one provider.
- **Templates name their own images.** Any template author could then run code
  on shared infrastructure.
- **Node-side session adapters per image.** That puts image-specific Rust code
  in the node. We version the images instead.
- **A per-org copy of each gateway.** As D39 found for overfwd, a per-org copy
  protects nothing that a shared multi-tenant one leaks, and it multiplies
  cost and patching.
