# Anthropic MCP Directory Submission — Compliance Status

Source of truth: <https://claude.com/docs/connectors/building/submission>
Reviewed: 2026-04-30
Submission category: **Remote MCP server** (Streamable HTTP, OAuth 2.1).
Not an MCPB/desktop extension and not (yet) an "MCP App" with carousel screenshots.

Legend: ✅ pass · ⚠️ partial · ❌ missing · N/A not applicable to this category.

---

## Summary

| Area | Status |
|---|---|
| OAuth 2.0 / 2.1 + DCR + PKCE | ✅ |
| Streamable HTTP transport | ✅ |
| AS / Resource metadata (RFC 8414, 9728) | ✅ |
| JSON-RPC error handling | ✅ |
| Tool `title` / `readOnlyHint` / `destructiveHint` annotations | ❌ |
| Privacy Policy (public URL) | ✅ <https://www.overslash.com/privacy> |
| Terms of Service (public URL) | ✅ <https://www.overslash.com/terms> |
| Public setup & usage docs | ❌ |
| Support channel | ✅ `contact@overslash.com` + public-repo issues |
| Logo & favicon assets | ⚠️ (exist locally; need public URLs) |
| Allowed link URIs declared | ❌ |
| `SECURITY.md` / vuln-disclosure policy | ❌ |
| Submission-form metadata package | ❌ (not yet assembled) |

Overall: the protocol surface is in good shape. The blockers for submission are non-code: tool annotations, privacy/ToS pages, support contact, and the submission-form information bundle.

---

## 1. Core compliance (Directory Terms & Policy)

> "Comply with Anthropic Software Directory Terms and Anthropic Software Directory Policy."
> "Maintain connector security and functionality. Respond to security issues promptly."

- ❌ No internal acknowledgement that the team has read and accepts the Directory Terms / Policy. Action: a maintainer must read both documents and confirm in the submission form.
- ⚠️ Public contact is `contact@overslash.com` and the public-repo issue tracker. Acceptable, but a `SECURITY.md` is still required to formalise scope, SLA, and safe harbor — see §13 below.
- ⚠️ No vulnerability-response runbook. Recommend a short internal doc (or section in `docs/`) describing who triages, how a fix is shipped, and how Anthropic gets notified.

## 2. Technical — security standards

> "Meet Anthropic's security standards."

- ✅ Tokens never leave the vault (CLAUDE.md rule 3). Per-org AES-256-GCM at rest.
- ✅ MCP access tokens are JWTs scoped `aud=mcp`, distinct from dashboard `oss_session` JWT — agent compromise cannot reuse a dashboard cookie and vice versa.
- ✅ Refresh tokens are single-use rotating, hashed-at-rest (`mcp_refresh_tokens`), with replay detection.
- ✅ DCR (RFC 7591) registers public clients only; no client secrets.
- ✅ Auth challenge on 401 returns RFC 9728 `WWW-Authenticate: Bearer resource_metadata=…` (`crates/overslash-api/src/routes/mcp.rs:81`).
- ⚠️ No formal threat-model document checked in. Useful to attach a 1-pager to the submission.
- ⚠️ Rate limiting / abuse controls on `/mcp` and `/oauth/*` not documented in this repo. Verify in deployment config and document.

## 3. Tool specifications — annotations

> "All tools must include a `title` and the applicable `readOnlyHint` or `destructiveHint`."

`crates/overslash-api/src/routes/mcp.rs:326–378` declares three tools. **None** carry `title`, `readOnlyHint`, or `destructiveHint`. This is a hard requirement.

| Tool | `title` | `readOnlyHint` | `destructiveHint` | Suggested annotations |
|---|---|---|---|---|
| `overslash_search` | ❌ | ❌ | ❌ | `title: "Search Overslash services"`, `readOnlyHint: true` |
| `overslash_call` | ❌ | ❌ | ❌ | `title: "Call an Overslash action"`, `readOnlyHint: false`, `destructiveHint: true`. **Note:** Overslash's permission/approval chain is defense-in-depth — it does not change what Claude should tell the user. The tool dispatches arbitrary upstream actions (Stripe charges, Gmail sends, calendar deletes), so from the MCP client's perspective it is a write/destructive surface. Claiming `readOnlyHint: true` because the gateway can block the call would mislead the client. |
| `overslash_auth` | ❌ | ❌ | ❌ | `title: "Identity & service status"`, `readOnlyHint: true` |

Action: extend each tool object in `tools_list_response` with the `title` field plus `annotations: { readOnlyHint, destructiveHint, openWorldHint, idempotentHint }` per the MCP `Tool` schema (2025-06-18). Cover with an integration test that asserts the presence of these fields.

## 4. Authentication — OAuth 2.0

> "Use OAuth 2.0 for authenticated services."

- ✅ OAuth 2.1 Authorization Code + PKCE.
- ✅ RFC 7591 Dynamic Client Registration at `POST /oauth/register`.
- ✅ RFC 7009 Token Revocation at `POST /oauth/revoke`.
- ✅ RFC 8414 AS metadata at `GET /.well-known/oauth-authorization-server`.
- ✅ RFC 9728 Resource metadata at `GET /.well-known/oauth-protected-resource`.
- ✅ Refresh-token rotation with replay detection (migration 033).
- ⚠️ Confirm that the deployed `issuer` in AS metadata matches the public canonical URL (e.g. `https://app.overslash.com`) used for submission. Misalignment causes Claude.ai client mismatch errors.
- ⚠️ Consent UI (`/oauth/consent`) is custom — verify copy is accurate, names the calling client, and links to the Privacy Policy and ToS once those exist.

## 5. Transport

> Streamable HTTP (and/or SSE) for remote MCP servers.

- ✅ `POST /mcp` + SSE for server-initiated streams (`elicitation/create`).
- ✅ Protocol version `2025-06-18` (`mcp.rs:307`).
- ✅ `Mcp-Session-Id` header round-trip.
- ✅ stdio shim (`crates/overslash-mcp`) for clients that cannot do remote OAuth — keep but it is **not** what gets submitted to the directory.

## 6. Link / URI handling

> "Declare allowed link URIs to suppress confirmation prompts. Every origin and scheme you list must be owned by you."

- ❌ No allowlist declared anywhere. Tool responses include `approval_url` pointing to `https://app.overslash.com/approvals/{id}` and the dashboard generally — these will trigger Claude's "open external link?" prompt on every render.
- Action: when assembling the submission form, list the production origin(s) (e.g. `https://app.overslash.com`, `https://overslash.com`) and confirm domain ownership in the form. If we ever add a desktop deep-link scheme, list it too.

## 7. Privacy policy

> Required via README + `manifest.json` `privacy_policies` array for **local** connectors. For remote MCPs the form still requires a public Privacy Policy URL.

- ✅ Privacy Policy: <https://www.overslash.com/privacy>
- ✅ Terms of Service: <https://www.overslash.com/terms>
- (Both managed in a separate marketing repo.)
- Action:
  - confirm both return 200 in production,
  - link them from `/oauth/consent`, the dashboard footer, and this repo's README,
  - paste the exact URLs into the submission form.
- Verify the policy text covers: data collected (org/user identity, OAuth tokens, action params, audit trail), storage/retention/encryption, third-party sharing (user-configured upstream services), subprocessors (Cloud SQL, Cloud Run, etc.), data-deletion/export contact.

> "Missing or incomplete privacy policies result in immediate rejection."

## 8. Documentation & support

> "Provide clear setup and usage instructions" + public docs (blog post or help-center article acceptable) + privacy policy + support channel.

- ⚠️ `SKILL.md` covers Claude Code / Cursor / Windsurf / OpenClaw enrollment well, but it is repo-internal. It is served at `/SKILL.md` from the API — that is acceptable but not discoverable.
- ❌ No public help-center article or marketing page describing the MCP server end-to-end (what tools exist, what permissions they need, what a typical interaction looks like).
- ✅ Support channel: `contact@overslash.com` plus public-repo GitHub issues. State both in the README and the submission form, with an SLA target ("we acknowledge within 2 business days").
- Action items:
  1. Promote the relevant parts of `SKILL.md` to a public docs page at, e.g., `https://docs.overslash.com/mcp` (or a section under `https://www.overslash.com`).
  2. Add a "Support" section to the README naming `contact@overslash.com` and the issues URL.

## 9. Asset requirements (MCP App carousel)

> PNG, ≥1000px wide, 3–5 images, crop to app response only — do not include the prompt.

- N/A as a hard requirement for a remote MCP server submission, but recommended for visibility.
- ⚠️ `docs/review/screenshots/` and `docs/screenshots/` exist for internal PR review — not the same as marketing carousel shots.
- If we want App-style placement: capture 3–5 in-Claude conversations exercising `overslash_search` → `overslash_call` (including a pending-approval flow), crop to the assistant turn, save as PNG ≥1000px.

## 10. Branding (logo & favicon)

- ⚠️ Assets exist locally: `dashboard/static/overslash-icon.png`, `favicon.png`, wordmark variants. They need to be reachable as public HTTPS URLs at submission time (e.g. `https://app.overslash.com/overslash-icon.png`) and the favicon must be set in the dashboard `<head>`.
- Action: confirm both URLs return 200 in production and supply them in the form.

## 11. Submission information package

The form requires the following — assemble before submitting.

- [ ] Server name: `overslash` (matches `serverInfo.name`, `mcp.rs:310`).
- [ ] Server URL: `https://app.overslash.com/mcp` (verify in prod).
- [ ] Tagline (≤1 sentence).
- [ ] Long description.
- [ ] Use cases (3–5 bullets).
- [ ] Authentication type: OAuth 2.1 (PKCE, DCR).
- [ ] Transport: Streamable HTTP + SSE.
- [ ] Read/write capabilities: read = `overslash_search`, `overslash_auth`; write = `overslash_call` (gated by Overslash permission/approval chain).
- [ ] Connection requirements: an Overslash account; agent enrollment via OAuth consent.
- [ ] Data handling summary (link to Privacy Policy).
- [ ] Third-party connections: dynamic — depends on which upstream services the user enables.
- [ ] Tool inventory: `overslash_search`, `overslash_call`, `overslash_auth` (full schemas above).
- [ ] Resources/prompts: none currently exposed.
- [ ] Logo URL + favicon URL.
- [ ] Test account credentials + setup notes.
- [ ] GA date and tested surfaces (Claude.ai web, Claude Desktop, Claude Code).
- [ ] Allowed link URIs (production origin(s) we own).
- [ ] Policy compliance confirmation checkbox.

## 12. Pre-submission checklist (gating items, in order)

1. ❌ Add `title` + `readOnlyHint` / `destructiveHint` annotations to all three tools (`mcp.rs:326`).
2. ✅ Privacy Policy <https://www.overslash.com/privacy> and Terms of Service <https://www.overslash.com/terms> are live — link from `/oauth/consent`, dashboard footer, and README.
3. ✅ Support channel confirmed (`contact@overslash.com` + public-repo issues) — surface in README.
4. ❌ Publish a public setup/usage doc (promote `SKILL.md` content to `docs.overslash.com/mcp` or `www.overslash.com/docs`).
5. ❌ Add `SECURITY.md` (see §13 for required content).
6. ❌ Determine and submit allowed link URIs (production origins we own).
7. ⚠️ Verify production `issuer` in `/.well-known/oauth-authorization-server` exactly matches the canonical public URL.
8. ⚠️ Verify the dashboard favicon and logo resolve at HTTPS URLs we will give Anthropic.
9. ⚠️ (Optional but recommended) Capture 3–5 carousel screenshots of in-Claude usage.
10. ✅ Run an end-to-end OAuth + tool-call test from a fresh Claude.ai connection against production.

Once items 1, 4, 5, 6 are landed and 7–8 verified, we are clear to file the directory submission form.

## 13. `SECURITY.md` — required content

Short file at the repo root, ~15 lines. GitHub auto-discovers it and surfaces it in the repo's "Security" tab and on the new-issue page, so it doubles as the public disclosure page.

Required sections:

- **Reporting address** — `security@overslash.com` is the convention; `contact@overslash.com` is acceptable if you don't want a separate alias.
- **What to include** — affected component, repro steps, impact, reporter contact info.
- **Response SLA** — e.g. "acknowledge within 2 business days, triage within 5".
- **Disclosure policy** — coordinated disclosure; ask reporters to hold public details until a fix ships, with a 90-day window.
- **Scope** — in-scope: `app.overslash.com`, the API, the OAuth endpoints, the MCP server, the dashboard. Out-of-scope: third-party services Overslash proxies to (those go to the upstream vendor).
- **Safe harbor** — explicit statement that good-faith research will not be pursued legally. This is the line that actually convinces researchers to report.
- *(Optional)* PGP key, Signal handle, hall-of-fame / bounty info.

---

## Appendix — code references

- MCP entry point: `crates/overslash-api/src/routes/mcp.rs`
  - `initialize` handler / `serverInfo`: line 303
  - `tools/list` response: line 326
  - JSON-RPC error helpers / codes: line 59, 245
  - 401 challenge with resource metadata: line 81
- OAuth metadata: `crates/overslash-api/src/routes/oauth_as.rs`
- OAuth endpoints (register/authorize/token/revoke): `crates/overslash-api/src/routes/oauth.rs`
- Migrations: `oauth_mcp_clients`, `mcp_refresh_tokens`, `mcp_client_agent_bindings` (033)
- stdio shim (not part of submission): `crates/overslash-mcp/src/lib.rs`
- Design doc: `docs/design/mcp-oauth-transport.md`
- Enrollment guide: `SKILL.md`
