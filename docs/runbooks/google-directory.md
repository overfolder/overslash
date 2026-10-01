# Google Workspace Directory sync — operator setup

Every org on an Overslash instance syncs Google Workspace groups through **one
service account per instance**. The operator creates it once and hands its JSON
key to the API; each customer's Workspace admin then authorises that account's
client ID in their own admin console and connects by signing in with Google.
Design: [docs/design/directory-group-sync.md](../design/directory-group-sync.md).

The instance also needs its **Google sign-in client**
(`GOOGLE_AUTH_CLIENT_ID` / `GOOGLE_AUTH_CLIENT_SECRET`). Connecting proves which
Workspace an org is by a Google sign-in, which rides the login's existing
redirect URI (`<PUBLIC_URL>/auth/callback/google`) — nothing new to register.

## 1. Create the service account and its key

**Hosted (Terraform).** `enable_google_directory_sync = true` creates the
account (`<prefix>-gdir@<project>.iam.gserviceaccount.com`, no roles, no key),
the Secret Manager secret its key lives in, and enables the Admin SDK API. Do
it in two steps, because the API refuses to boot on the placeholder value:

```bash
# a) create the account + an empty secret, without wiring it to the API yet
tofu apply -target=google_service_account.google_directory \
           -target=module.secret_manager \
           -target='google_project_service.apis["admin.googleapis.com"]' \
           -var enable_google_directory_sync=true

# b) mint a key and store it (the key never touches Terraform state)
SA=$(tofu output -raw google_directory_service_account_email)
gcloud iam service-accounts keys create /tmp/gdir.json --iam-account "$SA"
gcloud secrets versions add <prefix>-google-directory-sa-key --data-file=/tmp/gdir.json
shred -u /tmp/gdir.json

# c) set enable_google_directory_sync = true in the env's tfvars and apply
```

**Self-hosted.** Any Google Cloud project works; it does not have to host
Overslash.

```bash
gcloud services enable admin.googleapis.com --project <project>
gcloud iam service-accounts create overslash-gdir --project <project> \
    --display-name "Overslash Google Workspace Directory sync"
gcloud iam service-accounts keys create gdir.json \
    --iam-account overslash-gdir@<project>.iam.gserviceaccount.com
```

The account needs **no IAM roles**. If the org policy
`iam.disableServiceAccountKeyCreation` blocks key creation, grant the project an
exception.

## 2. Give the key to the API

Exactly one of:

| Variable | Value | Typical source |
|---|---|---|
| `OVERSLASH_GOOGLE_DIRECTORY_SA_KEY` | the JSON key itself | a Secret Manager / Vault value surfaced as an env var (what Terraform does on Cloud Run) |
| `OVERSLASH_GOOGLE_DIRECTORY_SA_KEY_FILE` | a path to the JSON key | a mounted Kubernetes secret or Docker secret (`/run/secrets/gdir.json`) |

Prefer the file form where you have the choice: the key is multi-line, and a
file keeps it out of the process environment (child processes, crash dumps).

The key is parsed at boot. Setting both, an unreadable path, or a key that is
not a `service_account` JSON with `client_email`, `client_id`,
`private_key_id` and an RSA `private_key` **stops the process** with a message
naming the problem (never the key). Unset means the feature is off: the
dashboard's Google Workspace section says so, and connect is refused.

Verify: Org Settings → Google Workspace shows *Authorize Overslash in Google
Admin* with a numeric **client ID** — the service account's unique ID.

## 3. What a customer's Workspace admin does

1. admin.google.com → **Security → Access and data control → API controls →
   Manage Domain Wide Delegation → Add new**: the client ID and the scope
   `https://www.googleapis.com/auth/admin.directory.group.readonly`, both shown
   with copy buttons in the dashboard.
2. In Overslash, Org Settings → Google Workspace → **Sign in with Google to
   connect**, as a super admin (or an admin with the Groups privilege).

Delegation usually applies within minutes; Google allows up to 24h.

## Rotation

```bash
gcloud iam service-accounts keys create new.json --iam-account "$SA"
gcloud secrets versions add <prefix>-google-directory-sa-key --data-file=new.json   # or replace the mounted file
# roll the API (new revision / restart) so it reads the new key, then:
gcloud iam service-accounts keys delete <old-key-id> --iam-account "$SA"
```

The client ID does not change on rotation, so customers do nothing.
**Replacing the service account** changes the client ID, and every connected
Workspace must add the new one — avoid it.

## Troubleshooting

The connect result and each sync's error are shown on the section; the API
logs `google directory sync` per run.

| Symptom | Cause |
|---|---|
| "Google refused Overslash's service account" / `unauthorized_client` | Delegation missing, wrong client ID, or the scope text differs. Or it has not propagated yet. |
| "That account can't read the Workspace's groups" / 403 | The signed-in account is not an admin with Groups read. |
| 403 "Admin SDK API has not been used in project" | Admin SDK not enabled in the **service account's** project. |
| "not part of a Google Workspace" | A personal Google account (no `hd`). |
| "Another organization … already connected that Workspace" | One org per Workspace per instance; disconnect it there first. |
| Section says not set up on this instance | Neither key variable set on the API. |
