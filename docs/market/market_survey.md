# Market Survey — AI Agent Auth & Action Infrastructure

*Last updated: 2026-04-05*

Overslash sits in the emerging "AI agent infrastructure" category — specifically the **auth, secrets, permissions, and action execution** layer. This survey maps the competitive landscape and identifies where Overslash is differentiated.

---

## Competitive Landscape

### Composio (composio.dev)

**What:** Platform providing 250+ pre-built tool integrations for AI agents. Handles auth (OAuth, API keys), action execution, and provides SDKs for LangChain, CrewAI, Autogen, etc.

- **Open source:** Partial. SDK is OSS; managed platform is commercial.
- **Funding:** ~$3.2M seed (2024). Active GitHub presence, one of the most visible players.
- **Pricing:** Free tier with limited executions; paid tiers for production.

**vs Overslash:**
- Composio is higher-level and more opinionated — bundles action definitions, auth, and execution into an SDK-driven workflow.
- Overslash is a lower-level gateway — provides auth/secrets/execution infrastructure without coupling to specific agent frameworks.
- Composio **lacks** permission chains, approval workflows, and multi-tenant identity hierarchy.
- Composio has a **much larger pre-built action catalog** (250+ vs Overslash's service registry approach).
- Overslash's versioned encrypted secret vault is more sophisticated than Composio's token storage.

---

### Nango (nango.dev)

**What:** Open-source platform for managing OAuth connections and API integrations. Handles OAuth flows, token refresh, unified API layer. Originally SaaS-to-SaaS, increasingly positioned for AI agents.

- **Open source:** Yes (MIT). Nango Cloud is the hosted offering.
- **Funding:** ~$15M total (Series A, 2024). 4000+ GitHub stars.
- **Pricing:** Free self-hosted; Cloud: free tier → Pro (~$500/mo) → Enterprise.

**vs Overslash:**
- Nango is **primarily an OAuth/integration platform**, not an AI agent gateway.
- Strong overlap: OAuth flow management, token refresh, multi-provider support.
- Nango **lacks**: Permission chains, approval workflows, agent identity hierarchy, secret vault (beyond OAuth tokens), service registry, agent execution model.
- Nango has **more mature OAuth coverage** (200+ providers).
- Nango solves one piece of what Overslash does (OAuth); Overslash provides the full agent-specific stack.

---

### Arcade AI (arcade-ai.com)

**What:** Tool-use platform specifically for AI agents. Registry of tools/actions agents can discover and call. Handles auth for tool calls.

- **Open source:** Partial (SDK and toolkits). Core platform is commercial.
- **Funding:** ~$6M seed (2024).
- **Pricing:** Free tier; usage-based for production.

**vs Overslash:**
- **Closest conceptual competitor** — both are gateways that let agents authenticate and call actions.
- Arcade has a tool registry similar to Overslash's service registry.
- Arcade's auth model is **simpler** — OAuth but no multi-level permission chains or approval bubbling.
- Arcade **lacks**: Versioned secret vault, identity hierarchy, inherit_permissions, human-in-the-loop approval workflows.
- Arcade is more **framework-coupled** (tight SDK integrations) while Overslash is a standalone REST API.

---

### Anon (anon.com)

**What:** "Authenticated actions for AI agents." Enables agents to act on behalf of users in apps **without APIs** — using browser automation with real user sessions.

- **Open source:** No. Proprietary.
- **Funding:** ~$6.5M seed (2024). High-profile investors.
- **Pricing:** Enterprise/sales-driven.

**vs Overslash:**
- Solves a **different surface**: browser automation vs API-first.
- Overlap in the "agent acting on behalf of user" auth model.
- Anon **lacks**: Secret vault, permission chains, multi-tenant hierarchy, service registry.
- **Complementary** — Overslash handles API-based actions, Anon handles browser-based.

---

### Paragon (useparagon.com)

**What:** Embedded integration platform for SaaS products. Managed OAuth, workflow engine, pre-built connectors.

- **Open source:** No. Fully proprietary.
- **Funding:** ~$16M (Series A).
- **Pricing:** Enterprise-focused, $1,000+/mo.

**vs Overslash:**
- Targets a **different use case** — helping SaaS companies build user-facing integrations, not powering AI agents.
- Convergence emerging as AI agents get embedded into SaaS products.
- No agent-specific features: no permission chains, no agent identity model, no approval workflows.

---

### Toolhouse (toolhouse.ai)

**What:** Universal tool platform — write tools once, use across any LLM/framework. Tool execution, optimization, management.

- **Open source:** SDK is OSS; platform is commercial.
- **Funding:** Seed-stage (~mid-2025).

**vs Overslash:**
- Focuses on **tool definition and optimization**, not auth/secrets/permissions.
- Minimal overlap with Overslash's core features.
- Could sit on top of Overslash for execution.

---

### Letta (formerly MemGPT)

**What:** Agent framework with persistent memory and tool use. Stateful AI agents.

- **Open source:** Yes (Apache 2.0). Letta Cloud is the commercial entity.
- **Funding:** ~$10M.

**vs Overslash:**
- **Agent framework**, not an auth gateway. Different layer.
- Basic tool-calling but no sophisticated auth/permission system.
- Overslash is a **backend that Letta agents would call through**.

---

### Observability Layer (AgentOps, LangSmith, Braintrust)

**Not competitors.** These watch what agents do; Overslash enables what agents do. Complementary.

---

## Feature Comparison Matrix

| Feature | Overslash | Composio | Nango | Arcade AI | Anon | Paragon | Toolhouse |
|---|---|---|---|---|---|---|---|
| Secret vault (encrypted, versioned) | **Yes** | Basic | OAuth only | Basic | Session | OAuth only | No |
| OAuth flow management | **Yes** | Yes | **Best-in-class** | Yes | Browser | Yes | No |
| Permission chains + approvals | **Yes (unique)** | No | No | No | No | No | No |
| Authenticated HTTP execution | **Yes** | Yes | Via syncs | Yes | Browser | Via workflows | Via tools |
| Service registry / action catalog | Yes (7) | **250+** | **200+** | Yes | Limited | 100+ | Yes |
| Multi-tenant hierarchy | **Yes (unique)** | No | Limited | No | No | Per-customer | No |
| Open source | **Full** | Partial | **Yes** | Partial | No | No | Partial |
| Framework-agnostic (REST API) | **Yes** | SDK-coupled | REST+SDK | SDK-coupled | SDK-coupled | Embedded | SDK-coupled |
| MCP compatibility | Planned | Adding | Adding | Adding | No | No | Adding |

---

## Market Trends

### AI Agent Infrastructure is a Recognized Category
VC-backed, fragmenting into layers: frameworks (LangChain, CrewAI), observability (LangSmith), tool use/auth (Composio, Arcade, Overslash), compute (Modal, Cloudflare), memory (Letta, Zep).

### The "Agent Auth Problem" is Front and Center
As agents move to production, "how does this agent authenticate to third-party services on behalf of a user?" became a primary concern. No clear winner has emerged.

### MCP is the Biggest Tailwind
Model Context Protocol standardizes tool discovery and invocation but **has no standard auth/permissions layer**. This is precisely Overslash's gap to fill.

### Human-in-the-Loop is Becoming Mandatory
Regulatory pressure (fintech, healthcare) drives demand for auditable, permission-controlled agent actions. Very few platforms offer sophisticated approval workflows — **major Overslash differentiator**.

### Multi-Tenancy is Underserved
Most platforms are single-developer/team oriented. Enterprise AI agent adoption demands the org/user/agent/subagent hierarchy Overslash implements.

### Open Source is Winning in Infrastructure
The trend is strongly toward OSS cores with commercial cloud (Nango, Supabase, PostHog model).
