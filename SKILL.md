# Overslash — Agent Self-Onboarding

This document tells an LLM agent how to discover and enroll itself with an Overslash instance. After enrollment you will have an API key that lets you manage secrets, execute authenticated HTTP requests, and use service actions on behalf of a user.

## 1. Discovery

Find the Overslash base URL from one of these sources (check in order):

1. **Environment variable**: `OVERSLASH_URL` (e.g. `https://api.overslash.dev`)
2. **Tool/config file**: Your host application may provide it in a config object or MCP server definition.
3. **Ask the user**: "What is your Overslash instance URL?"

There are two ways to enroll. If you already have an enrollment token (starts with `ose_`), go to **Flow A**. Otherwise, use **Flow B** to request approval from a user.

---

## Flow A: Enroll with a Token

If a user has given you an enrollment token (a string starting with `ose_`), use it directly:

```
POST {base_url}/v1/enroll
Content-Type: application/json

{
  "token": "ose_..."
}
```

**Response** (200):
```json
{
  "api_key": "osk_...",
  "identity_id": "IDENTITY_UUID",
  "org_id": "ORG_UUID"
}
```

Store the `api_key` immediately — it is shown only once. You are now enrolled. Skip to **Using Your API Key**.

---

## Flow B: Agent-Initiated Enrollment

Use this when you have no token. You request enrollment, send an approval link to a user, and poll until they approve.

### Step 1: Initiate Enrollment

```
POST {base_url}/v1/enroll/initiate
Content-Type: application/json

{
  "name": "my-agent",
  "platform": "claude-code",
  "metadata": {}
}
```

- `name` (required): A display name the user will see when approving.
- `platform` (optional): Identifies the agent platform (e.g. `"claude-code"`, `"cursor"`, `"custom"`).
- `metadata` (optional): Arbitrary JSON for additional context.

**Response** (200):
```json
{
  "enrollment_id": "ENROLLMENT_UUID",
  "approval_url": "https://api.overslash.dev/enroll/approve/APPROVAL_TOKEN",
  "poll_token": "osp_...",
  "expires_at": "2025-01-01T01:00:00Z"
}
```

Save both the `poll_token` and `approval_url`. The request expires in 1 hour.

### Step 2: Send the Approval URL to the User

Present the `approval_url` and ask the user to open it:

> "To give me access to Overslash, please open this link and approve:
> {approval_url}"

The approval page shows the user your agent name and platform. They can approve (optionally renaming you) or deny.

### Step 3: Poll for Approval

While the user is reviewing, poll the status endpoint with your poll token:

```
GET {base_url}/v1/enroll/status?poll_token=osp_...
```

**Response** while pending:
```json
{
  "status": "pending"
}
```

**Response** once approved:
```json
{
  "status": "approved",
  "api_key": "osk_...",
  "identity_id": "IDENTITY_UUID",
  "org_id": "ORG_UUID"
}
```

**Response** if denied:
```json
{
  "status": "denied"
}
```

**Response** if expired:
```json
{
  "status": "expired"
}
```

Poll every 3–5 seconds. Stop after `status` is no longer `"pending"`.

Store the `api_key` immediately and securely.

---

## Using Your API Key

Authenticate all requests with:

```
Authorization: Bearer osk_...
```

Common operations:

| Action | Method | Endpoint |
|--------|--------|----------|
| Store a secret | PUT | `/v1/secrets/{name}` |
| Execute HTTP | POST | `/v1/execute` |
| List services | GET | `/v1/services` |
| Run a service action | POST | `/v1/execute` (Mode C) |

## Error Handling

| Scenario | What to do |
|----------|------------|
| Enrollment expired | Create a new enrollment request and re-send the approval URL |
| Enrollment denied | Inform the user and ask if they want to try again |
| Token invalid/used | The enrollment token may be single-use or expired. Ask the user for a new one |
| API key lost | The key cannot be recovered. The user must revoke the old identity and you must enroll again |
| `401 Unauthorized` | Your API key is invalid or revoked. Re-enroll |
| `403 Forbidden` | You lack permission for this action. Request approval or ask the user to grant permission |

## Quick Reference: Agent-Initiated Flow

```
Agent                          Overslash                       User
  |                               |                              |
  |-- POST /v1/enroll/initiate -> |                              |
  |<-- approval_url, poll_token --+                              |
  |                               |                              |
  |-- "Please open this URL" ---------------------------->       |
  |                               |                              |
  |                               | <-- GET approval page ------ |
  |                               | --- show agent details ----> |
  |                               | <-- POST approve ----------- |
  |                               |                              |
  |-- GET /v1/enroll/status ----> |                              |
  |<-- { status: "approved",   ---+                              |
  |      api_key: "osk_..." }    |                              |
  |                               |                              |
  |-- Bearer osk_... requests --> |                              |
```
