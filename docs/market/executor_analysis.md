# Executor (executor.sh) — Competitive Analysis

*Last updated: 2026-06-23 (refresh of the 2026-04-13 analysis)*

**Repo:** github.com/RhysSullivan/executor
**First commit:** 2026-02-05
**Current version:** v1.5.17 (2026-06-22) — 92 releases, 2,262 commits
**Traction:** ~2,200 GitHub stars, 138 forks (was a fraction of this in April — strong adoption momentum)
**License:** MIT
**SaaS:** executor.sh — cloud is live with public pricing (see below)
**Author:** Rhys Sullivan (still effectively a solo dev; no funding round found. Also speaks at MCP Night, works adjacent to OpenCode / Vercel Domains.)

> **What changed since the 2026-04-13 analysis** (read this first):
> 1. **Overslash shipped MCP server mode** — the #1 priority recommendation from the April doc is done (Streamable HTTP + OAuth 2.1, DCR, 4 meta-tools). The April threat thesis ("if Executor deepens auth before Overslash ships MCP, the overlap grows in Executor's favor") is **largely neutralized**.
> 2. **Executor repositioned** from "one catalog for every tool" → **"MCP gateway: connect any agent to everything."** It now leads with **context/token efficiency**, not catalog breadth.
> 3. **Executor's cloud pricing is now public** (Free / Team $150/org/mo / Enterprise).
> 4. **Executor's auth/permission layer deepened slightly but is still shallow vs Overslash** — policies are now **owner-scoped (org | user)** with a most-restrictive-wins merge ("org = outer guardrail, user = inner; a user preference cannot weaken an org guardrail"). That's a real two-layer *ceiling*, conceptually adjacent to Overslash's group-ceiling + permission-key model — but it matches on **glob tool-address patterns** (`<integration>.<owner>.<connection>.<tool>`), not an identity hierarchy. Still no agent/sub-agent hierarchy, no `inherit_permissions`, no approval bubbling, no secret versioning; audit is "coming soon."
> 5. **Executor is deliberately NOT an agent-governance product.** Its `vision.md` states the goal is "an open source layer for your integrations… **It is not AI specific**… ship the primitives that build an extendable product." This sharpens the contrast: Executor = unopinionated integration-interop primitives; Overslash = opinionated agent identity/governance. The two have **diverged further, not converged**.
> 6. **Convergence vector to watch:** Executor's roadmap lists **"scope merging"** — "add tools at a global, workspace, account level, override secrets/policies per scope, create temporary scopes." That is its move toward multi-tenant hierarchy. If shipped well it narrows Overslash's multi-tenancy lead — but it's still scope/pattern-based, not identity-chain-based.

---

## What It Is

Executor is a **tool gateway and execution runtime for AI agents**. It sits between agents and external services, normalizing tools from multiple source types (OpenAPI, GraphQL, MCP servers, Google Discovery, custom JS) into a single uniform shape — "one name, one input schema, one output schema" — and exposing them through one MCP tool surface. It handles credential injection, tool-level policy enforcement, and pause/resume execution for human-in-the-loop.

**Current positioning:** "Connect any agent to everything." The headline pitch is now **context efficiency**: instead of loading 1,640 tool definitions (~278,800 tokens) into an agent's context, Executor exposes **one tool (~1,044 tokens)** and lets the agent discover/call by intent. This is the dominant new selling point and a genuinely sharp one — tool-context bloat is a top-of-mind 2026 problem.

---

## Architecture

TypeScript/Bun monorepo (96.6% TS) using Effect.js for DI and typed errors.

| Component | Tech | Purpose |
|-----------|------|---------|
| **SDK** (`@executor/sdk`) | TypeScript + Effect | Core runtime: ToolRegistry, SecretStore, PolicyEngine, SourceRegistry |
| **API** | Effect Platform HttpApi | REST endpoints with OpenAPI docs |
| **Execution engine** | Effect + QuickJS/SES WASM | Pause/resume, elicitation, sandboxed code execution |
| **Local app** | React + TanStack Router + SQLite | Local dashboard (port 4788) |
| **Cloud app** | Cloudflare Workers + Postgres + Drizzle | Multi-tenant SaaS at executor.sh |
| **CLI** | Bun-compiled binary | `executor web`, `executor mcp`, `executor call` |
| **Desktop** | Electron | Native Mac/Windows/Linux app; sources/secrets/sessions stay local |
| **Daemon** | background service | Persistent durable runtime |

### Plugin / source system

Extensibility via npm packages, not config. First-party source types: `plugin-openapi`, `plugin-graphql`, `plugin-mcp`, `plugin-google-discovery`, plus custom JS functions. Secret backends: `plugin-keychain`, `plugin-file-secrets`, `plugin-onepassword`, `plugin-workos-vault`. A catalog of **50+ ready-to-use tools** (web search/scrape, GitHub, Gmail, Slack, Discord, Sheets, Stripe, Dropbox, image gen, TTS, browser automation…).

### Cloud pricing (new since April)

| Tier | Cost | Limits |
|------|------|--------|
| Free | $0 | up to 3 members, 10,000 executions/mo, $0.20 per 1,000 overage |
| Team | $150 / org / mo | unlimited members, 250,000 executions/mo, 5-min timeout |
| Enterprise | custom | self-hosted/dedicated, SSO/SAML, audit logs, dedicated support |

Note: the Enterprise tier *advertises* SSO/SAML and audit logs, but the docs show audit/tracing is still "coming soon" and there is no documented org/RBAC model. These are roadmap, not shipped.

---

## Feature-by-Feature Comparison

### Where Executor and Overslash Overlap

| Concern | Executor | Overslash | Assessment |
|---------|----------|-----------|------------|
| Tool/action catalog | Plugin-driven, auto-detected from specs; 50+ shipped | YAML/OpenAPI templates, 3-tier registry; 10 shipped | Executor has more breadth + auto-detection; Overslash has curated governance |
| **Single-tool context collapse** | **Yes — headline feature** (1 tool vs N) | **Yes — same shape** (4 meta-tools + `overslash_search`) | **Architecturally equivalent**, but Executor markets it and Overslash doesn't (see Ideas) |
| Secret management | Multi-provider (keychain, file, 1Password, WorkOS) | Versioned vault, AES-256-GCM, identity-scoped, never-returned | Overslash is deeper (versioning, vault semantics) |
| Approval / HITL | Tool-level policy + pause/resume elicitation | Approval bubbling, specificity tiers, remembered approvals + TTL | Overslash is significantly more sophisticated |
| Policy engine | Owner-scoped (org\|user) glob patterns, most-restrictive-wins; allow / require-approval / block; spec-derived defaults | Two-layer: group ceiling + permission keys over identity hierarchy | Both two-layer ceilings now; Overslash binds to an identity chain, Executor to tool-address globs |
| Multi-tenancy | Scope-based (cwd or org ID); no documented hierarchy | Full org isolation + identity hierarchy + multi-org auth | Overslash is purpose-built for this |
| MCP server | **Native — Executor *is* an MCP server** | **Shipped** — Streamable HTTP + OAuth 2.1, DCR, 4 meta-tools | **Now at parity** (was Executor-only in April) |
| Dashboard | React SPA (local) + cloud | SvelteKit (agents, audit, approvals, billing, members) | Overslash has far more admin surface |
| OAuth | MCP OAuth2, header auth | Full engine: BYOC, per-user tokens, refresh, scope downgrade, white-label vault | Overslash is much deeper |
| Audit | "Coming soon" | Full audit trail + `/audit` dashboard + CSV export | Overslash shipped; Executor roadmap |

### Where Overslash Has No Equivalent (unchanged — still its moat)

Identity hierarchy (User→Agent→SubAgent, `inherit_permissions`); permission key system; trust model (agents cannot self-approve); approval bubbling; specificity tiers; remembered approvals + TTL; agent enrollment; comprehensive audit trail; two-tier rate limiting; service lifecycle states; group ceiling; OIDC/SAML org auth; multi-org membership; white-label token vault; Stripe billing; monitoring stack.

### Where Executor Has No Equivalent (mostly by design for Overslash)

1. **Code execution sandbox** — SES/QuickJS WASM (rated "best-in-class" JS isolation by third parties). Explicit non-goal for Overslash.
2. **Source auto-detection** — `detect(url)` identifies OpenAPI/GraphQL/MCP/Google-Discovery automatically. *(Still an open idea for Overslash — see below.)*
3. **Runtime npm plugin architecture** — extensible at runtime.
4. **Desktop app** — Electron, local-first.
5. **Local-first SQLite** — zero-infra default.
6. **GraphQL introspection + Google Discovery auto-load.**
7. **Context-efficiency narrative** — packaged and marketed (Overslash has the capability, not the story).

---

## Ideas to Adopt

> April's #2 (MCP server mode) is **done**. The remaining ideas, re-prioritized for June:

### 1. Market the token-collapse benefit *(NEW — highest-leverage, lowest-cost)*
Executor's strongest 2026 narrative is "1 tool, ~1,044 tokens vs 1,640 tools, ~278,800 tokens." **Overslash already delivers this** — agents see `overslash_search` + 3 meta-tools instead of one tool per action, so context stays flat as the catalog grows. We have the architecture and none of the messaging. Add the token-collapse framing to the MCP docs, the marketing site, and SKILL.md. **Scope: docs/marketing only. Do this first.**

### 2. Source auto-detection for template import *(carried over, still open)*
`POST /v1/templates/detect` — paste a URL, auto-detect spec type (OpenAPI/GraphQL/MCP), pre-fill the template. Reduces import friction; fits the template editor and bulk-import route already scaffolded (`/services/templates/import`). **Scope: one endpoint + dashboard UX.**

### 3. CLI for agent-side scripting *(carried over)*
Thin wrapper over the REST API: `overslash search`, `overslash execute`, `overslash auth whoami`, `overslash approve`. Good DX for local dev, CI, enrollment scripting. (Not code execution — out of scope.) **Scope: small.** Note: the `overslash` CLI binary now exists (`serve`/`web`/`mcp`/`mcp login`); this is about adding the agent-facing verbs.

### 4. Local development mode with SQLite *(carried over, still post-v1.0)*
A `--local` SQLite mode lowers the dev barrier vs the Postgres requirement. Useful for adoption, not the enterprise target. **Scope: medium-large (storage abstraction). After v1.0.**

### 5. Desktop app *(parked)*
Only relevant once local-first exists. Park.

---

## What NOT to Adopt (unchanged)

- **Code execution / sandboxing** — expands attack surface of an auth gateway; explicit non-goal.
- **Agent self-approval** (`onElicitation: "accept-all"`) — contradicts Overslash's core trust model.
- **Local-first as default** — Overslash's value prop needs Postgres; local SQLite is a dev convenience only.
- **npm runtime plugins** — Overslash is Rust + config-driven; adopt the *ideas* (auto-detect, source adapters), not the mechanism.

---

## Market Position Assessment

```
             Executor's territory          Overslash's territory
            ┌───────────────────┐         ┌───────────────────────┐
            │ Tool discovery    │         │ Identity hierarchy    │
            │ Context efficiency│         │ Permission chains     │
            │ Code execution    │         │ Approval bubbling     │
            │ Desktop / local   │         │ Audit trail (shipped) │
            │ Plugin ecosystem  │         │ Encrypted vault       │
            │                   │         │ OAuth + white-label   │
            │          ┌────────┼─────────┼────────┐  Multi-org   │
            │          │ Tool   │  MCP    │ Secret │  Billing     │
            │          │ catalog│ server  │ mgmt   │  Monitoring  │
            │          │ Policy │ (both)  │ Multi- │              │
            │          │ engine │         │ tenant │              │
            └──────────┼────────┘         └────────┼──────────────┘
                       │      Overlap zone         │
                       └───────────────────────────┘
```

**Still true:** Executor is a **tool runtime** (discover, normalize, sandbox, invoke). Overslash is an **auth gateway** (identity, permissions, secrets, approvals, audit). More complementary than competitive — an agent platform could use Executor for discovery/invocation and Overslash for the governance layer that gates it.

**Threat level: low-medium, and the gap is now safer for Overslash than in April.** Reasons:
- The April risk hinged on Overslash lagging on MCP. **That's closed** — MCP shipped with a deeper auth model than Executor's tool-level policies.
- Executor's auth/permissions remain shallow (no hierarchy, no RBAC, audit "coming soon"). Its Enterprise tier *advertises* SSO/SAML + audit but the docs show these aren't built.
- Executor is still effectively a solo project with no disclosed funding — fast cadence (92 releases) but limited surface to build out enterprise governance.

**Where Executor genuinely leads, and Overslash should respond:**
1. **Adoption momentum** — ~2,200 stars, MCP-Night visibility, an aggressive release cadence, and a crisp developer story. Overslash is private/pre-launch.
2. **The context-efficiency narrative** — Executor owns a story that Overslash's architecture already satisfies but never tells. This is the single highest-leverage, lowest-cost gap to close (Idea #1).
3. **Onboarding friction** — local-first + source auto-detection make Executor trivial to try; Overslash needs Postgres and manual templates.

**Action (June):** (1) Claim the token-collapse story in docs/marketing now (Idea #1). (2) Ship source auto-detection (Idea #2). (3) Add agent-side CLI verbs (Idea #3). None require architectural change; all narrow Executor's two real advantages (DX + narrative) while Overslash's governance moat stays uncontested.
