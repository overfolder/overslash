# Executor (executor.sh) — Competitive Analysis

*Last updated: 2026-04-13*

**Repo:** github.com/RhysSullivan/executor
**First commit:** 2026-02-05
**First release (v1.1.8):** 2026-03-09
**Current version:** v1.4.6-beta.0 (as of 2026-04-13)
**License:** MIT
**SaaS:** executor.sh (Cloudflare Workers + Postgres, live)
**Author:** Rhys Sullivan (solo dev, very fast shipping cadence — ~10 weeks from init to v1.4)

---

## What It Is

Executor is a **tool catalog and execution runtime for AI agents**. It sits between agents and external services, providing a unified registry of tools from multiple sources (OpenAPI, GraphQL, MCP servers, Google Discovery APIs) and a consistent invocation API. It handles credential resolution, basic policy enforcement, and pause/resume execution for human-in-the-loop approval.

Positioning: "One catalog for every tool, shared across every agent you use."

---

## Architecture

TypeScript/Bun monorepo using Effect.js for dependency injection and typed errors.

| Component | Tech | Purpose |
|-----------|------|---------|
| **SDK** (`@executor/sdk`) | TypeScript + Effect | Core runtime: ToolRegistry, SecretStore, PolicyEngine, SourceRegistry |
| **API** (`@executor/api`) | Effect Platform HttpApi | REST endpoints with OpenAPI docs |
| **Execution engine** | Effect + QuickJS WASM | Pause/resume, elicitation, sandboxed code execution |
| **Local app** | React + TanStack Router + SQLite | Dashboard for local use |
| **Cloud app** | Cloudflare Workers + Postgres + Drizzle | Multi-tenant SaaS at executor.sh |
| **CLI** | Bun-compiled binary | `executor web`, `executor mcp`, `executor call` |
| **Desktop** | Electron | Native app wrapping CLI + web UI |
| **MCP host** | MCP stdio + HTTP | Any MCP client connects directly |

### Plugin System

Extensibility is via npm packages, not config files:

- `plugin-openapi` — loads OpenAPI specs, generates tools
- `plugin-graphql` — introspects GraphQL endpoints
- `plugin-mcp` — bridges MCP servers into the catalog
- `plugin-google-discovery` — auto-loads Google APIs
- `plugin-keychain` — OS-native secret storage
- `plugin-file-secrets` — file-based secrets
- `plugin-onepassword` — 1Password vault
- `plugin-workos-vault` — enterprise secrets (cloud)

### Deployment Models

1. **Local-first (default)** — `executor web` starts SQLite-backed dashboard on localhost:4788
2. **CLI tool** — `executor call '<code>'` runs sandboxed JS with tool access
3. **MCP server** — `executor mcp` exposes catalog to any MCP client
4. **Cloud SaaS** — executor.sh on Cloudflare Workers
5. **Desktop** — Electron app for Mac/Windows/Linux

---

## Feature-by-Feature Comparison

### Where Executor and Overslash Overlap

| Concern | Executor | Overslash | Assessment |
|---------|----------|-----------|------------|
| Tool/action catalog | Plugin-driven, auto-detected from specs | YAML templates, 3-tier registry | Both solve it; different tradeoffs (see below) |
| Secret management | Multi-provider (keychain, file, 1Password, env) | Versioned vault, AES-256-GCM, identity-scoped | Overslash is deeper (versioning, never-returned-via-API) |
| Approval workflows | Elicitation (form + URL), pause/resume | Approval bubbling, specificity tiers, remembered approvals | Overslash is significantly more sophisticated |
| Policy engine | Regex pattern matching, allow/deny/require_approval | Two-layer: group ceiling + permission keys | Overslash is architecturally deeper |
| Multi-tenancy | Scope-based (cwd or org ID) | Full org isolation with identity hierarchy | Overslash is purpose-built for this |
| Dashboard UI | React SPA (tools, sources, secrets, settings) | SvelteKit (agents, services, API explorer, audit) | Both have dashboards; Overslash has more admin surface |
| REST API | Effect HttpApi with OpenAPI | Axum REST API | Both have typed, documented APIs |
| OAuth | MCP OAuth2 support, header-based auth | Full OAuth engine (BYOC, per-user tokens, refresh, scope downgrade) | Overslash is much deeper |

### Where Overslash Has No Equivalent

These are Overslash's core differentiators that Executor does not attempt:

1. **Identity hierarchy** (User → Agent → SubAgent, `inherit_permissions`, SPIFFE paths, idle GC)
2. **Permission key system** (`{service}:{action}:{arg}` with hierarchical resolution)
3. **Trust model** (agents cannot self-approve; credential-gated resolution)
4. **Approval bubbling** (gap detection, ancestor resolution, auto-bubble timeout)
5. **Specificity tiers** (structured tier suggestions for graduated permission grants)
6. **Remembered approvals with TTL** (organic permission accumulation)
7. **Agent enrollment** (user-initiated and agent-initiated consent flows)
8. **Comprehensive audit trail** (every action, approval, secret access logged with identity chain)
9. **Rate limiting** (two-tier: user bucket + identity cap)
10. **Service lifecycle states** (pending → active → error → archived with credential verification)
11. **Group-based access ceiling** (org-admin managed coarse-grained controls)
12. **User authentication** (OIDC, SAML, corporate SSO, per-org IdP)

### Where Executor Has No Equivalent

These are capabilities outside Overslash's scope (by design):

1. **Code execution sandbox** — QuickJS WASM, Deno subprocess, secure-exec runtimes
2. **Native MCP server** — Executor *is* an MCP server; agents connect directly
3. **Source auto-detection** — `detect(url)` identifies source type automatically
4. **Runtime plugin architecture** — npm-installable, init/teardown lifecycle, extensible at runtime
5. **Desktop app** — Electron distribution
6. **Local-first SQLite** — zero-infra default deployment
7. **GraphQL introspection** — auto-discovers queries/mutations as tools
8. **Google Discovery APIs** — auto-loads Google APIs

---

## Ideas to Adopt

### 1. Source Auto-Detection for Template Import

**What Executor does:** `detect(url)` takes any URL and identifies whether it's an OpenAPI spec, GraphQL endpoint, MCP server, or Google Discovery API. One URL → tools registered.

**What Overslash should consider:** Our OpenAPI import (§9) requires explicit upload. Adding a `detect` step to the template creation flow — paste a URL, Overslash auto-detects the spec type and pre-fills the template — would reduce friction significantly. This fits naturally into the dashboard template editor and the `overslash_auth` meta tool.

**Scope:** Dashboard UX + one new endpoint (`POST /v1/templates/detect`). Does not require architectural changes.

### 2. MCP Server Mode

**What Executor does:** `executor mcp` turns the tool catalog into an MCP server. Any MCP client (Claude Code, Cursor, Windsurf) connects and gets the full tool catalog with auth handled transparently.

**What Overslash should consider:** We already plan MCP compatibility (market_survey.md notes it). Executor's approach is instructive: ship a standalone MCP server binary/process that wraps the 3 meta tools (`overslash_search`, `overslash_call`, `overslash_auth`) and translates MCP tool calls to Overslash API calls. The MCP server handles elicitation → approval mapping natively.

**Scope:** New `overslash-mcp` binary or sidecar. The 3 meta tools already provide the right abstraction — the MCP server is a thin transport adapter. Priority: high. MCP adoption is accelerating fast and Executor already has this.

### 3. Local Development Mode with SQLite

**What Executor does:** Local-first by default. `executor web` starts a full instance backed by SQLite in the user's home directory. No Postgres, no Docker, no setup.

**What Overslash should consider:** Our current dev experience requires Postgres (even with `make local` automating Docker). A SQLite mode for local development and single-developer use would lower the barrier to entry dramatically. This could be a `overslash --local` flag that uses SQLite instead of Postgres, with a subset of features (no multi-tenant, simplified auth).

**Scope:** Medium-large. Requires a storage abstraction layer (or sqlx compile-time feature gate for SQLite). Worthwhile for adoption but not critical for the enterprise target market. Consider after v1.0.

### 4. CLI for Agent-Side Scripting

**What Executor does:** `executor call '<code>'` runs sandboxed JavaScript with tool access. Agents can write and execute code that calls tools. `executor resume --execution-id exec_123` resumes paused executions.

**What Overslash should consider:** A lightweight CLI that wraps the REST API would be useful for: (a) local development/testing without the dashboard, (b) CI/CD integration, (c) agent enrollment scripting. Not code execution (out of scope) but something like:

```bash
overslash search "github"
overslash execute github create_pull_request --repo=acme/app --title="Fix"
overslash auth whoami
overslash approve apr_abc123 --tier=2
```

**Scope:** Small. Thin wrapper over the REST API. Good DX investment.

### 5. Desktop App Distribution

**What Executor does:** Electron app for Mac/Windows/Linux with bundled CLI and embedded web UI.

**What Overslash should consider:** Low priority for now. The web dashboard covers the primary use case. Revisit if/when local-first mode exists — a desktop app makes sense as the container for a local Overslash instance, but not as a wrapper around a remote SaaS dashboard.

**Scope:** Only relevant after local-first mode. Park this.

### 6. Plugin-Driven Source Loading

**What Executor does:** Plugins handle the full lifecycle of a source: add, remove, refresh, detect. Each plugin type (OpenAPI, GraphQL, MCP) knows how to parse its source format and register tools.

**What Overslash should consider:** Our template system is YAML-config-driven, which is correct for the curated registry model. But supporting **programmatic source adapters** (a plugin that, given a URL, can auto-generate a template from an OpenAPI spec, GraphQL schema, or MCP server manifest) would complement the manual YAML approach. This is adjacent to idea #1 (auto-detection) but goes further — the adapter would produce a draft template, not just identify the type.

**Scope:** Medium. Could be a Rust trait (`SourceAdapter`) with implementations for OpenAPI and GraphQL. The adapter produces a `ServiceTemplate` struct that goes through the normal validation pipeline.

---

## What NOT to Adopt

### Code Execution / Sandboxing
Executor runs arbitrary code in QuickJS WASM sandboxes. This is explicitly a non-goal for Overslash (§2) and would expand the attack surface of a security-critical auth gateway. Do not adopt.

### Agent-Friendly Trust Model
Executor allows `onElicitation: "accept-all"` — agents can auto-approve their own tool calls. This directly contradicts Overslash's core trust assumption that agents cannot self-approve. Do not adopt.

### Local-First as Default
Executor defaults to local SQLite. Overslash's value proposition (multi-tenant, encrypted vault, org hierarchy) requires Postgres. A local mode is useful for dev (idea #3) but should never be the default deployment.

### Plugin Ecosystem via npm
Executor's npm-installable plugins work because it's a TypeScript runtime. Overslash is Rust — the extension model should be config-driven (YAML templates, OpenAPI import) rather than runtime code loading. Adopt the *ideas* from plugins (auto-detection, source adapters) but not the mechanism.

---

## Market Position Assessment

Executor is **the closest thing to a direct competitor** in the open-source space, but the overlap is partial:

```
             Executor's territory          Overslash's territory
            ┌───────────────────┐         ┌───────────────────────┐
            │ Tool discovery    │         │ Identity hierarchy    │
            │ Code execution    │         │ Permission chains     │
            │ MCP hosting       │         │ Approval workflows    │
            │ Desktop app       │         │ Audit trail           │
            │ Plugin ecosystem  │         │ Encrypted secret vault│
            │                   │         │ OAuth engine          │
            │          ┌────────┼─────────┼────────┐              │
            │          │ Tool   │         │ Secret │              │
            │          │ catalog│         │ mgmt   │              │
            │          │ Policy │         │ Multi- │              │
            │          │ engine │         │ tenant │              │
            └──────────┼────────┘         └────────┼──────────────┘
                       │      Overlap zone         │
                       └───────────────────────────┘
```

**Key takeaway:** Executor is a **tool runtime** (discover, invoke, sandbox). Overslash is an **auth gateway** (identity, permissions, secrets, audit). They are more complementary than competitive. An agent platform could use both: Executor for tool discovery and invocation, Overslash for the auth/permission/approval layer that gates those invocations.

**Threat level:** Low-medium. Executor's policy engine and secret management are basic compared to Overslash's. But Executor's shipping speed (~10 weeks to v1.4 with SaaS) and MCP-first approach give it strong developer adoption momentum. If Executor deepens its auth/permission layer before Overslash ships MCP support, the overlap zone grows in Executor's favor.

**Action:** Ship MCP server mode (idea #2) and source auto-detection (idea #1) as priority. These are the two capabilities where Executor has clear adoption advantages that Overslash should match quickly.
