# Testing Coverage Plan

Prioritized list of missing test coverage for the Overslash codebase, with specific test case descriptions grouped by severity.

## Current Coverage Inventory

| Category | Tests | Files |
|----------|-------|-------|
| Integration tests | ~35 | `integration.rs`, `auth_login.rs`, `oauth_x.rs`, `large_file.rs`, `eventbrite.rs` |
| Unit tests | ~29 | `crypto.rs`, `registry.rs`, `secret_injection.rs`, `permissions.rs`, `jwt.rs`, `health.rs` |
| **Total** | **~64** | **11 files** |

### What's covered today

- **Auth login**: dev token (enabled/disabled/idempotent), `/auth/me` (valid/401/invalid), Google login 404
- **Call flow**: happy path with permission, approval flow, allow & remember, deny keeps gating, unauthenticated, Mode C service action
- **Secrets**: versioning (put creates new version)
- **OAuth**: callback stores connection, BYOC priority (identity > org), pinned BYOC, callback fails without creds, token refresh (expired + valid), PKCE (X with / GitHub without)
- **BYOC**: full CRUD lifecycle including duplicate constraint (409)
- **Large files**: response too large, prefer_stream, streaming with auth, redirect following
- **Audit**: basic audit trail creation
- **Webhooks**: dispatch on approval resolve
- **Google Calendar**: all three execution modes (A, B, C)
- **Service registry API**: list, get, search
- **Crypto (unit)**: encrypt/decrypt roundtrip, wrong key, truncated data, hex key parse
- **Registry (unit)**: load from dir, find by host, search
- **Secret injection (unit)**: header with prefix, query param, missing secret
- **Permissions (unit)**: exact match, wildcard, no rules, deny overrides, partial coverage, empty keys, derive keys
- **JWT (unit)**: roundtrip, expired, wrong key
- **Health (unit)**: health + ready endpoints

### What's NOT covered

36 endpoints exist; many have zero or only indirect test coverage. The AuthContext extractor (sole authentication gate) has no unit tests. No cross-org isolation tests exist. Google OAuth callback flow is untested. Several CRUD delete endpoints are untested. Mode B (connection-based execution) lacks isolated tests. The `resolve_service_auth` cascading logic has no isolated tests.

---

## Group 1: Critical Gaps — Security-Sensitive Paths

**21 tests | Estimated effort: ~5 days**

Every test here protects against authorization bypass, data leakage, cross-tenant access, or credential exposure.

### 1.1 AuthContext Extractor Validation

The `AuthContext` extractor (`extractors.rs:62-126`) is the sole authentication gate for all `/v1/*` endpoints. It performs 5 validations (header presence, Bearer prefix, `osk_` format, DB lookup + Argon2 verify, expiry check) — none tested in isolation.

**New file: `crates/overslash-api/tests/auth_api_key.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 1 | `auth_missing_header_returns_401` | Request to any authed endpoint without Authorization header | Baseline: unauthenticated requests rejected |
| 2 | `auth_wrong_prefix_returns_401` | `Authorization: Bearer sk_xxx` (not `osk_`) | Rejects foreign key formats (extractors.rs:79-81) |
| 3 | `auth_key_too_short_returns_401` | `Authorization: Bearer osk_abc` (< 12 chars) | Prefix extraction at extractors.rs:84-88 must not panic |
| 4 | `auth_valid_prefix_wrong_hash_returns_401` | Correct 12-char prefix (matches DB row) but wrong full key | Argon2 verification at extractors.rs:106-111 actually rejects; prefix match alone is not auth |
| 5 | `auth_expired_key_returns_401` | Create key, set `expires_at` in past via direct DB update, then use it | Expiry check at extractors.rs:96-99 is the only temporal guard |
| 6 | `auth_revoked_key_returns_401` | Create key, revoke via `api_key::revoke()`, then use it | `find_by_prefix` filters `revoked_at IS NULL` — must verify this end-to-end |

### 1.2 Cross-Org Isolation

No test creates two orgs and verifies org A cannot access org B's resources. This is the most dangerous class of missing test.

**New file: `crates/overslash-api/tests/cross_org.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 7 | `cross_org_secret_invisible` | Org A creates secret "foo", org B queries `GET /v1/secrets/foo` → should 404 | `get_by_name` WHERE clause scopes by org_id |
| 8 | `cross_org_secret_list_isolation` | Org A creates secrets, org B lists → should see empty array | `list_by_org` scoping |
| 9 | `cross_org_connection_delete_rejected` | Org A's key tries `DELETE /v1/connections/{org_b_conn_id}` → should fail | `delete_by_org` checks org_id match |
| 10 | `cross_org_approval_list_isolation` | Org A creates approval (via gated call), org B lists approvals → empty | `list_pending_by_org` filters by org_id |
| 11 | `cross_org_webhook_delete_rejected` | Org A tries to delete org B's webhook | `delete_subscription` checks org_id |

### 1.3 Secret Value Never Exposed

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 12 | `get_secret_returns_metadata_only` | PUT secret with value "supersecret", GET it, assert body does NOT contain "supersecret" | SecretMetadata struct only has name + version, but regression could add value field |
| 13 | `list_secrets_returns_no_values` | Create multiple secrets, GET /v1/secrets, assert no response contains any value | Same concern for list endpoint |

### 1.4 Google OAuth Callback Security

The `google_callback` handler (`routes/auth.rs`) performs CSRF nonce validation, PKCE verifier exchange, and user creation with race condition handling — all entirely untested. Only the degenerate case (Google not configured → 404) is covered.

**New file: `crates/overslash-api/tests/auth_google.rs`**

Requires adding a mock `/userinfo` endpoint to the test mock server (~10 lines, reusing existing mock infrastructure).

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 14 | `google_callback_rejects_missing_nonce_cookie` | Call callback without nonce cookie | CSRF protection: cookie must be present |
| 15 | `google_callback_rejects_mismatched_nonce` | Call callback with nonce cookie that doesn't match state | CSRF protection: nonce must match |
| 16 | `google_callback_happy_path_creates_user_and_session` | Full flow with mock Google userinfo | Validates JWT minting, cookie setting, user creation |
| 17 | `google_callback_idempotent_for_existing_user` | Call twice with same email, verify same org_id/identity_id | `find_or_create_user` early return path |

### 1.5 Client Credentials Env Var Security Boundary

The `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS` flag (`client_credentials.rs:55`) gates env var credential reading. The name includes "DANGER" for a reason — this must be pinned by tests.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 18 | `client_credentials_errors_without_envvar_flag` | Initiate OAuth without BYOC creds and without env var flag → should error | Verifies env var path is off by default |
| 19 | `client_credentials_reads_envvars_when_flag_set` | Set env var flag + `OAUTH_TEST_CLIENT_ID` etc → verify resolution succeeds | Verifies env var naming convention works |

### 1.6 OAuth State Parameter Security

The connection OAuth callback (`routes/connections.rs:117-225`) parses `org_id:identity_id:provider:byoc_id:verifier` from the state parameter with no HMAC or nonce. Malformed state can cause parse errors; forged state with valid UUIDs could bind attacker-controlled tokens.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 20 | `oauth_callback_malformed_state_returns_400` | `GET /v1/oauth/callback?code=x&state=garbage` | `splitn(5, ':')` with insufficient parts must not panic |
| 21 | `oauth_callback_invalid_uuid_in_state_returns_400` | `state=not-a-uuid:also-bad:provider:_:_` | UUID parse must return 400, not 500 |

> **Security note:** Consider adding HMAC signing to the state parameter to prevent forgery. Currently any attacker with knowledge of valid org_id + identity_id can craft a valid state and bind arbitrary OAuth tokens. This is a potential vulnerability beyond the scope of testing.

---

## Group 2: Important Gaps — Core Business Logic

**22 tests | Estimated effort: ~5 days**

### 2.1 Untested CRUD Endpoints

Many endpoints are only exercised as side-effects of setup helpers, not directly tested.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 22 | `delete_secret_returns_true` | `DELETE /v1/secrets/{name}` after creating one | Soft delete sets `deleted_at` — untested |
| 23 | `delete_secret_not_found_returns_404` | `DELETE /v1/secrets/nonexistent` | Error path verification |
| 24 | `delete_secret_then_recreate_restores` | PUT → DELETE → PUT same name, verify second PUT succeeds | Upsert SQL clears `deleted_at` — critical for secret rotation |
| 25 | `delete_permission_returns_true` | Create permission, delete by ID, verify deleted | `permission_rule::delete` untested |
| 26 | `delete_webhook_returns_true` | Create webhook, delete by ID, verify deleted | `webhooks::delete_subscription` untested |
| 27 | `list_approvals_returns_pending` | Create approval (via gated call), list, verify it appears | `list_pending_by_org` only implicitly tested |

### 2.2 Mode B Execution (Connection-Based)

Mode B is tested indirectly through `test_google_calendar_three_modes` but needs a focused test for the token refresh path during execution.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 28 | `execute_mode_b_refreshes_expired_token` | Execute with connection whose `token_expires_at` is in past; mock refresh endpoint returns new token | Full refresh-during-execute path: actions.rs → oauth.rs → connection update |

### 2.3 OAuth Token Edge Cases

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 29 | `resolve_access_token_treats_none_expiry_as_valid` | Connection with `token_expires_at = NULL` → token returned without refresh | Documents `unwrap_or(false)` behavior at oauth.rs:173-176 |
| 30 | `refresh_preserves_old_refresh_token_when_omitted` | Mock refresh returns no `refresh_token`; verify DB still has original | Subtle: oauth.rs:212-219 passes None to `update_tokens` |

### 2.4 Mode C resolve_service_auth Cascade

The `resolve_service_auth` function (`actions.rs:507-598`) has three branches: explicit secrets bypass, OAuth connection lookup, API key fallback. No isolated test exercises the cascade.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 31 | `mode_c_auto_auth_prefers_oauth_over_api_key` | Identity has both OAuth connection and API key secret for service → OAuth injected | Cascade priority at actions.rs:520-571 |
| 32 | `mode_c_auto_auth_falls_back_to_api_key` | No OAuth connection → API key secret used | Fallback at actions.rs:573-595 |

### 2.5 Connection Delete Paths

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 33 | `delete_connection_org_key_vs_identity_key` | Org-level key can delete any connection; identity B's key cannot delete identity A's connection | Two code paths at connections.rs:266-269 |

### 2.6 Permission Listing Edge Case

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 34 | `list_permissions_with_org_key_returns_400` | Use org-level key (no identity_id) to GET /v1/permissions | `auth.identity_id.ok_or_else(...)` returns 400 |

### 2.7 Webhook HMAC Signature

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 35 | `webhook_signature_is_valid_hmac` | Register webhook, trigger via approval resolve, capture `X-Overslash-Signature`, recompute HMAC-SHA256 | If broken, no consumer can verify webhook authenticity |

### 2.8 Audit Log Filtering

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 36 | `audit_filter_by_action` | Create entries (secret.put, api_key.created), query `?action=secret.put`, verify only matching | `query_filtered` action filter |
| 37 | `audit_filter_by_date_range` | Query with `since` and `until` params | Date parsing + SQL date filtering |

### 2.9 Mode C Parameter Substitution

Requires `start_api_with_registry` + test service YAML pointing to mock server.

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 38 | `mode_c_path_param_substitution` | Execute with params `{ "id": "123" }` where action path is `/items/{id}` → mock receives `/items/123` | Path placeholder replacement in actions.rs |
| 39 | `mode_c_query_params_for_get` | Execute GET action with non-path params → query string at mock | GET actions put extra params in query string |
| 40 | `mode_c_json_body_for_post` | Execute POST action with non-path params → JSON body at mock | POST actions put extra params in body |
| 41 | `mode_c_service_not_found_returns_404` | Execute with nonexistent service key | Error path in service registry lookup |
| 42 | `mode_c_explicit_secrets_bypass_auto_auth` | Execute Mode C with explicit secrets → `resolve_service_auth` returns immediately | Bypass at actions.rs:515-517 |
| 43 | `get_approval_by_id` | Create approval, get by ID, verify all fields | `get_by_id` never directly tested |

---

## Group 3: Nice-to-Have — Edge Cases & Error Paths

**14 tests | Estimated effort: ~2.5 days**

### 3.1 Secret Injection Edge Cases

**Unit tests in: `crates/overslash-core/src/secret_injection.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 44 | `inject_multiple_secrets_different_types` | One header + one query secret in same request | Both injection paths working together |
| 45 | `inject_query_with_existing_params` | URL already has `?page=1`, inject query param | Separator logic: `if url.contains('?')` uses `&` |
| 46 | `inject_secret_special_chars_in_value` | Value contains `&`, `=`, `#` | Query injection does raw concat — documents behavior |

### 3.2 Permission Key Derivation Edge Cases

**Unit tests in: `crates/overslash-core/src/permissions.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 47 | `permission_key_strips_https` | `from_http("GET", "https://api.example.com/foo")` → `http:GET:api.example.com/foo` | `strip_prefix("https://")` path |
| 48 | `permission_key_strips_http` | Same for `http://` URLs | Same code path, different prefix |
| 49 | `permission_key_no_scheme` | URL with no scheme: `api.example.com/foo` | `unwrap_or(url)` fallback |

### 3.3 Crypto Edge Cases

**Unit tests in: `crates/overslash-core/src/crypto.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 50 | `encrypt_empty_plaintext_roundtrips` | `encrypt(key, &[])` then decrypt | No off-by-one in nonce handling |
| 51 | `encrypt_large_payload_roundtrips` | 1MB payload | No buffer overflow or truncation |

### 3.4 Registry Edge Cases

**Unit tests in: `crates/overslash-core/src/registry.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 52 | `registry_empty_directory` | `load_from_dir` on empty dir | Returns empty registry, not error |
| 53 | `registry_invalid_yaml_skips_file` | Dir with one valid + one invalid YAML | Loads valid, skips invalid gracefully |

### 3.5 Approval Expiry

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 54 | `approval_expire_stale_marks_expired` | Insert approval with `expires_at` in past, call `expire_stale()`, verify status = "expired" | Background task correctness |
| 55 | `resolve_expired_approval_returns_not_pending` | Create approval, expire it, try to resolve → should fail | `resolve` WHERE `status = 'pending'` guard |

### 3.6 Webhook Retry

**Add to: `crates/overslash-api/tests/integration.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 56 | `failed_delivery_appears_in_pending_for_retry` | Create delivery, mark failed, verify `get_pending_deliveries` returns it | Retry loop depends on this query |

### 3.7 HTTP Executor Edge Case

**Unit test in: `crates/overslash-api/src/services/http_executor.rs`**

| # | Test Name | What It Tests | Why It Matters |
|---|-----------|---------------|----------------|
| 57 | `no_body_skips_content_type` | Request with no body should not add Content-Type | Only added when body is Some |

---

## Implementation Sequencing

### Phase 1 — Critical Security Tests (tests 1–21)

Create three new integration test files:
- `crates/overslash-api/tests/auth_api_key.rs` — AuthContext extractor tests (1–6)
- `crates/overslash-api/tests/cross_org.rs` — org isolation tests (7–11)
- `crates/overslash-api/tests/auth_google.rs` — Google OAuth callback tests (14–17)

Add tests 12–13, 18–21 to `crates/overslash-api/tests/integration.rs`.

Infrastructure needed:
- Existing helpers: `start_api`, `start_api_with_dev_auth`, `bootstrap_org_identity`, mock server
- Cross-org tests: second `bootstrap_org_identity` call (helper already generates unique slugs)
- Google OAuth tests: mock `/userinfo` endpoint added to `common/mod.rs` mock server (~10 lines)

### Phase 2 — Core Business Logic (tests 22–43)

Add to `crates/overslash-api/tests/integration.rs`. Tests 38–42 need `start_api_with_registry` + test service YAML. Mode B test (28) needs mock OAuth token refresh endpoint. Auto-auth tests (31–32) need a service with both OAuth and ApiKey auth configured.

### Phase 3 — Edge Cases (tests 44–57)

Unit tests (44–53, 57) go in source files alongside existing `#[cfg(test)]` modules. Integration tests (54–56) go in `integration.rs`.

---

## Security Vulnerabilities Discovered

### OAuth State Parameter Forgery (Medium Severity)

The connection OAuth callback (`routes/connections.rs:117-225`) parses `org_id:identity_id:provider_key:byoc_id:verifier` directly from the `state` query parameter with **no HMAC, nonce, or signature**. This is separate from the Google OAuth flow, which correctly uses CSRF nonce cookies.

**Impact:** An attacker who knows (or guesses) valid `org_id` and `identity_id` UUIDs can craft a state parameter and complete an OAuth callback that binds an attacker-controlled token to the victim's identity.

**Recommendation:** Add HMAC-SHA256 signing to the state parameter using a server-side secret, or store state in the database with a random lookup key. This should be addressed as a code fix, not just tested.

---

## Summary

| Group | Tests | New Files | Effort | Risk Mitigated |
|-------|-------|-----------|--------|----------------|
| 1. Critical | 21 | `auth_api_key.rs`, `cross_org.rs`, `auth_google.rs` | ~5 days | Auth bypass, cross-tenant data leak, secret exposure, CSRF, credential leakage |
| 2. Important | 22 | None (extend existing) | ~5 days | CRUD gaps, Mode B refresh, OAuth token edges, auto-auth cascade, webhook integrity |
| 3. Nice-to-have | 14 | None (unit + extend integration) | ~2.5 days | Robustness, panic prevention, documented edge behavior, retry correctness |
| **Total** | **57** | **3 new files** | **~12.5 days** | |
