# Nango Integration — OAuth & Connector Gateway

**Status**: In Consideration
**Date**: 2026-03-05
**Related**: `managed-connectors.md`, `gated-actions.md`, `tool-connectors.md`, `byoc-oauth.md`

## Overview

Replace the in-house OAuth token management, refresh logic, and API credential handling with [Nango](https://nango.dev) — an integration platform providing managed OAuth flows, token storage, auto-refresh, and an API proxy for 700+ services. Agent-runner connector tools would call Google/Slack/GitHub APIs through Nango's proxy endpoint instead of managing tokens directly.

## Motivation

The current OAuth/connector system is ~5,140 lines of Rust with known pain points:

- Token refresh logic duplicated between backend and agent-runner
- BYOG (Bring Your Own Google) adds significant complexity (separate credential storage, conditional flows)
- Multi-account support bolted on (nullable `account_email`, lazy backfill from userinfo API)
- Custom state parameter encoding with no standard format
- Scopes hardcoded, stored in DB but not validated
- Adding a new integration requires a new Rust module (~500-1,000 lines each)

## Current Implementation (What Nango Replaces)

### Files Involved

| File | Lines | Purpose |
|------|-------|---------|
| `backend/src/routes/integration.rs` | 989 | OAuth flows, callbacks, token storage |
| `backend/src/routes/oauth.rs` | 364 | Google login/signup (user auth — stays) |
| `backend/src/routes/byog.rs` | — | BYOG credential management |
| `backend/src/services/auth.rs` | 124 | AuthService for JWT & Google OAuth exchange |
| `agent-runner/src/tools/connectors/oauth.rs` | 321 | Token retrieval, refresh, BYOG handling |
| `agent-runner/src/tools/connectors/gmail.rs` | 1,087 | Gmail tools (search, read, draft, send) |
| `agent-runner/src/tools/connectors/google_calendar.rs` | 1,058 | Calendar tools (list, create, update, delete, free slots) |
| `agent-runner/src/tools/connectors/google_drive.rs` | 572 | Drive tools (search, read, list) |
| `agent-runner/src/tools/connectors/permissions.rs` | 626 | Approval workflows (stays — Nango doesn't do this) |

### Current oauth_tokens Schema

```sql
CREATE TABLE oauth_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL,
    service text NOT NULL,
    access_token text NOT NULL,
    refresh_token text,
    expires_at timestamptz,
    scopes text[],
    account_id uuid NOT NULL,
    account_email text,
    is_byog boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, service, account_email)
);
```

### Current Google Scopes

| Service | Scopes |
|---------|--------|
| Calendar | `calendar.events` |
| Gmail | `gmail.send`, `gmail.readonly` |
| Drive | `drive.readonly` |
| All | `openid`, `email`, `profile` |

## What Nango Provides

### Core Capabilities

| Capability | How it works |
|-----------|-------------|
| OAuth flow management | 700+ APIs with pre-configured OAuth templates. Handles consent screen, code exchange, token storage. |
| Token storage | AES-256-GCM encrypted at rest in Postgres. Self-hosted: BYOK via `NANGO_ENCRYPTION_KEY`. |
| Auto-refresh | Transparent on every proxy call. No custom refresh logic needed. |
| API proxy | `POST /proxy/{any_path}` with `Connection-Id` + `Provider-Config-Key` headers. Nango injects credentials, forwards request, returns response as-is. |
| Multi-account | Native. `connection_id` (our `user_id`) + provider key identifies a connection. Multiple accounts per provider supported. |
| Webhooks | Notifies on connection created, re-authorized, and refresh failure. |
| Connect UI | Drop-in frontend component for OAuth consent flows. |

### Supported Integrations (Relevant)

| Service | Supported | Current status in Overfolder |
|---------|-----------|------------------------------|
| Google Calendar | Yes | Implemented |
| Gmail | Yes | Implemented |
| Google Drive | Yes | Implemented |
| GitHub | Yes | Not implemented |
| Slack | Yes | Not implemented |
| Notion | Yes | Not implemented |
| Microsoft 365/Outlook | Yes | Not implemented |
| Todoist | Yes | Not implemented |
| Linear/Jira | Yes | Not implemented |

### Deployment Options

| Option | Cost | Features | Infrastructure |
|--------|------|----------|---------------|
| Cloud Free | $0/mo | 10 connections, 100K proxy reqs | Managed |
| Cloud Starter | From $50/mo | 20 connections (+$1/ea), 200K proxy reqs | Managed |
| Cloud Growth | From $500/mo | 100 connections (+$1/ea), 1M proxy reqs | Managed |
| Self-hosted Free | $0 | Auth + proxy + dashboard (limited features) | Docker Compose: Postgres + Redis |
| Self-hosted Enterprise | Annual license | Full feature parity with Cloud | Helm: 5 Node services, Postgres, Redis, Elasticsearch, S3 |

License: Elastic License v2 (ELv2). Self-hosting allowed; cannot offer Nango as a service to others.

## Integration Architecture

```
Frontend                Backend (Rust)           Nango                  External API
+--------+             +-------------+          +-------+              +--------+
| Connect| --click-->  | /connect    | -------> | OAuth | --consent--> | Google |
| button |             | redirect    |          | flow  | <--code----  |        |
+--------+             +-------------+          +-------+              +--------+
                                                    |
                                                    | stores tokens
                                                    v
Agent-Runner (Rust)                              +-------+
+------------------+    POST /proxy/gmail/v1/... | Nango | --with token--> Google API
| gmail_search     | ---Connection-Id: {user_id}->| Proxy |
| tool executes    | <--response-----------------+-------+
+------------------+
```

### Key Change

Agent-runner connector tools stop calling Google APIs directly. Instead they call Nango's proxy endpoint, passing `Connection-Id` (our `user_id`) and `Provider-Config-Key` (e.g. `google-calendar`). Nango injects the stored OAuth token. Agent-runner never touches tokens.

### Nango Multi-Tenant Mapping

| Nango concept | Overfolder concept |
|--------------|-------------------|
| `connection_id` | `user_id` (UUID as string) |
| `provider_config_key` | Service name (`google-calendar`, `gmail`, `google-drive`) |
| Connection | One user's auth to one service |
| `end_user.id` | `user_id` |

## What Changes, What Stays

### Changes

| Component | Before | After |
|-----------|--------|-------|
| `backend/routes/integration.rs` | Custom OAuth flows, callbacks, token storage (989 lines) | Thin redirect to Nango Connect UI. List endpoint queries Nango API. (~100 lines) |
| `agent-runner/connectors/oauth.rs` | Token retrieval, refresh, BYOG (321 lines) | Deleted entirely |
| `agent-runner/connectors/gmail.rs` | Direct Google API calls with `get_valid_token()` (1,087 lines) | Nango proxy calls (~500 lines) |
| `agent-runner/connectors/google_calendar.rs` | Direct Google API calls (1,058 lines) | Nango proxy calls (~500 lines) |
| `agent-runner/connectors/google_drive.rs` | Direct Google API calls (572 lines) | Nango proxy calls (~300 lines) |
| `oauth_tokens` table | Stores tokens, refresh logic, BYOG flag | Dropped. Nango stores tokens. |
| BYOG implementation | Custom credential storage + conditional flows | Eliminated. Nango manages the OAuth app. |
| Tool registry `build_for_user()` | Queries `oauth_tokens` table | Queries Nango `GET /connections?connection_id={user_id}` |
| Frontend integrations page | Custom OAuth redirect flow | Nango Connect UI component or redirect |

### Stays Unchanged

| Component | Reason |
|-----------|--------|
| `backend/routes/oauth.rs` | User authentication (login/signup), not service auth |
| `agent-runner/connectors/permissions.rs` | Approval workflows — Nango doesn't do this |
| Gated actions system | More sophisticated than anything Nango offers |
| Connector tool logic | Tools still parse inputs, format outputs, handle errors. Only the HTTP call changes. |
| Model routing, quota, streaming | Unrelated to auth |

## Nango Rust Client

No official Rust SDK exists. Call the REST API directly (~200 lines):

```rust
pub struct NangoClient {
    base_url: String,
    secret_key: String,
    client: reqwest::Client,
}

impl NangoClient {
    /// Proxy an API request through Nango (credential injection)
    pub async fn proxy(
        &self,
        method: Method,
        path: &str,
        connection_id: &str,
        provider_config_key: &str,
        body: Option<Value>,
    ) -> Result<Response> {
        let mut req = self.client.request(method, format!("{}/proxy/{}", self.base_url, path))
            .header("Authorization", format!("Bearer {}", self.secret_key))
            .header("Connection-Id", connection_id)
            .header("Provider-Config-Key", provider_config_key);
        if let Some(body) = body {
            req = req.json(&body);
        }
        Ok(req.send().await?)
    }

    /// List connections for a user
    pub async fn list_connections(&self, connection_id: &str) -> Result<Vec<Connection>> {
        // GET /connections?connection_id={id}
    }

    /// Get connection details (triggers token refresh if needed)
    pub async fn get_connection(
        &self,
        provider_config_key: &str,
        connection_id: &str,
    ) -> Result<Connection> {
        // GET /connections/{provider_config_key}/{connection_id}
    }
}
```

## Practical Concerns

### Latency

Every API call routes through Nango's proxy (extra hop). Nango Cloud: ~50-100ms added. Self-hosted on same network: ~5-10ms. Acceptable for Google API calls that already take 200-500ms.

### Cost at Scale

| Users | Connections (3 services each) | Tier | Monthly cost |
|-------|-------------------------------|------|-------------|
| 10 | 30 | Free (self-hosted) | $0 |
| 50 | 150 | Starter | ~$180 |
| 500 | 1,500 | Growth | ~$1,900 |
| 5,000 | 15,000 | Enterprise | Custom |

Self-hosted free eliminates connection-based pricing but has limited features (unclear exactly what's missing vs. Cloud).

### Migration

Existing `oauth_tokens` rows need migration to Nango connections. One-time script:
1. For each `oauth_tokens` row, create a Nango connection via API
2. Pass `access_token`, `refresh_token`, `expires_at`
3. Verify connections work via proxy test call
4. Drop `oauth_tokens` table after validation

### Security

- Nango Cloud: AWS-managed encryption keys. No BYOK.
- Self-hosted: `NANGO_ENCRYPTION_KEY` env var (AES-256, base64-encoded). No key rotation support.
- SOC 2 Type II, GDPR compliant.
- OAuth tokens never reach agent VMs (same security model as today).

## Estimated Effort

| Task | Days |
|------|------|
| Nango setup (Cloud or self-hosted Docker) | 1 |
| Rust HTTP client for Nango API (~200 lines) | 2 |
| Replace backend OAuth flows with Nango Connect | 3 |
| Simplify connector tools to use proxy calls | 3 |
| Update tool registry (query Nango for connections) | 1 |
| Remove `oauth_tokens` table + BYOG code | 1 |
| Frontend: swap OAuth redirect for Nango Connect UI | 2 |
| Migration script for existing tokens | 1 |
| Testing | 3 |
| **Total** | **~17 days (~3 weeks)** |

### Net Code Change

- Lines removed: ~3,500-4,000 (oauth.rs, token refresh, BYOG, integration routes)
- Lines added: ~1,200 (Nango client, simplified proxy-based connector tools)
- Net reduction: ~2,500 lines

## Benefits

1. **Adding new integrations becomes config, not code** — biggest win for v1/v2 (Notion, Slack, Microsoft 365, GitHub, Todoist, etc.)
2. **Eliminates token refresh duplication** between backend and agent-runner
3. **Kills BYOG complexity** — Nango manages the OAuth app centrally
4. **Multi-account support becomes native** instead of bolted-on
5. **~2,500 fewer lines** of custom auth plumbing to maintain
6. **Security improvement** — tokens encrypted at rest (currently plaintext in `oauth_tokens`)

## Risks

1. **Vendor dependency** — Nango becomes critical path for all connector functionality
2. **ELv2 license** — not OSI open source; limits how we can redistribute
3. **No encryption key rotation** on self-hosted deployments
4. **Cloud pricing scales with connections** — could become expensive at 5,000+ users
5. **Extra latency hop** through proxy (~50-100ms Cloud, ~5-10ms self-hosted)
6. **Limited self-hosted features** — unclear what's missing vs. Cloud on the free tier

## Decision

In consideration. Key factors for decision:

- [ ] Verify self-hosted free tier feature set is sufficient
- [ ] Test proxy latency from Cloud Run to Nango Cloud
- [ ] Confirm Nango handles Google's incremental consent correctly
- [ ] Evaluate whether ELv2 license is acceptable long-term
- [ ] Compare self-hosted operational cost vs. Cloud pricing at target scale
