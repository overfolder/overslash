# Strategic Notes — OSS + Hosted Model

*Last updated: 2026-04-05*

## The Plan

Full open-source release (complete feature set) + hosted offering at overslash.dev. First-class integration with OpenClaw and similar agent platforms.

---

## Strengths of This Approach

### 1. Overslash's Moat is Architecture, Not Features Behind a Paywall

The permission chain / approval bubbling system and the multi-tenant identity hierarchy are **architecturally deep** — they're not features you can bolt on after the fact. Competitors would need to redesign their data models to match. Open-sourcing the full feature set doesn't erode this moat; it **showcases** it.

### 2. The Nango/Supabase/PostHog Playbook Works Here

Infrastructure products that go full OSS with a hosted offering have repeatedly won their categories:
- **Nango** (OSS OAuth management) → Nango Cloud
- **Supabase** (OSS Firebase alternative) → Supabase Cloud
- **PostHog** (OSS analytics) → PostHog Cloud
- **Infisical** (OSS secret management) → Infisical Cloud

The pattern: self-hosted is free → developers adopt → teams hit operational complexity → they pay for hosted. This works especially well for **stateful infrastructure** (which Overslash is — Postgres, encrypted secrets, OAuth tokens).

### 3. Trust Demands Transparency

Overslash is a **secret vault and auth gateway**. Organizations are being asked to route their API keys, OAuth tokens, and agent permissions through it. Open-sourcing the full codebase is a **trust signal** — "you can audit exactly how we handle your secrets." Closed-source secret management is a hard sell in 2026.

### 4. Agent Platform Integration is a Network Effect

If OpenClaw, Overfolder, and other platforms integrate Overslash as their auth layer, every agent on those platforms becomes an Overslash user. Full OSS makes this integration frictionless — platform developers can read the code, self-host for development, and recommend the hosted version for production.

---

## Risks and Mitigations

### Risk: Large cloud providers clone it
**Mitigation:** The permission chain system and identity hierarchy are complex to replicate correctly. By the time a cloud provider ships a clone, Overslash should have community, integrations, and a service registry catalog that are hard to replicate. Also, Rust + the specific architectural choices make this non-trivial to fork-and-maintain.

### Risk: No revenue differentiation if everything is OSS
**Mitigation:** Hosted value-adds that don't need to be in the OSS core:
- **Managed infrastructure** (HA Postgres, automatic backups, encryption key management)
- **Global edge deployment** (low-latency OAuth and execution worldwide)
- **SOC 2 / compliance certifications** (enterprises need the paper, not just the code)
- **Team management, SSO, and billing** (multi-org SaaS features)
- **Uptime SLA and support**
- **Pre-built service template marketplace** (community contributes, hosted curates)
- **Analytics dashboard** (agent usage patterns, cost tracking, anomaly detection)

### Risk: Self-hosted users never convert
**Mitigation:** Overslash is operationally complex to run well (Postgres, encryption keys, OAuth callback URLs, webhook delivery, token refresh jobs). The "it works on my laptop" to "it runs in production" gap is significant. This is the natural conversion funnel.

---

## OpenClaw Integration Strategy

Making Overslash trivial to use with OpenClaw (and similar platforms) is the highest-leverage growth strategy:

1. **Enrollment SKILL.md** — agents on OpenClaw discover and enroll with Overslash via the SKILL.md convention. This should be a copy-paste, zero-config experience.
2. **Three meta tools** — `overslash_search`, `overslash_call`, `overslash_auth` should map cleanly to OpenClaw's tool-use patterns.
3. **MCP server** — ship an official Overslash MCP server so any MCP-compatible agent (Claude, Cursor, etc.) can use Overslash natively.
4. **Approval routing** — OpenClaw surfaces Overslash approvals in its native UX. The approval webhook + resolution API makes this straightforward.
5. **Hosted quickstart** — "Connect your OpenClaw agent to overslash.dev in 2 minutes" tutorial.

---

## Competitive Positioning

**Tagline candidates:**
- "The auth gateway for AI agents"
- "Secrets, OAuth, and permissions for any agent"
- "Your agents' keychain"

**Key differentiators to emphasize:**
1. **Only platform with hierarchical permissions + approval workflows** — enterprise-ready from day one
2. **Fully open source** — audit the code that handles your secrets
3. **Framework-agnostic REST API** — works with any agent platform, not just one SDK
4. **MCP-native** — the auth layer the MCP ecosystem is missing

---

## Pricing Model Sketch (Hosted)

| Tier | Target | Price | Includes |
|------|--------|-------|----------|
| Free | Individual developers | $0 | 1 org, 3 agents, 100 executions/mo |
| Pro | Small teams | $29-49/mo | 5 orgs, unlimited agents, 10k executions/mo |
| Team | Growing companies | $149-299/mo | Unlimited orgs, SSO, audit export, priority support |
| Enterprise | Large orgs | Custom | SLA, dedicated instance, compliance certs, custom IdP |

*Execution-based pricing aligns incentives — you pay when agents actually do things.*
