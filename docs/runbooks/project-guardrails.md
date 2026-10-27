# Project guardrails — default-SA Editor and project org policies

`infra/modules/project-guardrails/main.tf` does two things in each project:

1. **Takes `roles/editor` away from the two GCP-default accounts** that Google's IAM
   Recommender flagged ([gcp-posture.md](../compliance/casa/gcp-posture.md#iam-policy-googleiampolicyrecommender-global)):

   | Member | Was | Becomes | Why |
   |---|---|---|---|
   | `<number>-compute@developer.gserviceaccount.com` (default Compute Engine SA) | `roles/editor` | nothing | 0 permissions used in 90 days; nothing runs as it |
   | `<number>@cloudservices.gserviceaccount.com` (Google APIs service agent) | `roles/editor` | `roles/compute.editor`, **prod only** (`use_private_vpc`) | the 12 permissions it used are all the VPC connector's managed instance group |

   `google_project_iam_member_remove` keeps them removed. A binding someone re-adds by hand
   shows up as a create on the next plan and is removed again on apply.

2. **Sets project-level org policies.** Org-wide policies live in the org repo. These are the
   ones that are Overslash-specific, or that pin a guarantee this project relies on:

   | Constraint | dev | prod | What it guards |
   |---|---|---|---|
   | `iam.automaticIamGrantsForDefaultServiceAccounts` | enforced | enforced | A default SA is never *created* with Editor. Already inherited from the org; pinned here so it survives a change of parent |
   | `iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts` | enforced | enforced | Nobody *grants* a default SA Editor/Owner later |
   | `iam.disableAuditLoggingExemption` | enforced | enforced | The Data Access audit config cannot exempt a principal (6.7.1) |
   | `storage.publicAccessPrevention` | enforced | enforced | No bucket can be made public. All three buckets are already `enforced` |
   | `sql.managed.restrictPublicIp` | **off** | enforced | Prod's database stays private. Dev's has a public IP with no authorized networks |
   | `sql.managed.restrictAuthorizedNetworks` | **off** | enforced | Same split |
   | `iam.managed.disableServiceAccountKeyCreation` | **off** (`allow_service_account_key_creation`) | enforced | The org enforces it. Dev opts out so the Directory-sync key can be minted ([google-directory.md](google-directory.md)) |

   The dev key-creation override already exists. It was set by hand on 2026-10-27, and an
   `import` block in `infra/main.tf` adopts it.

`run.allowedIngress` is deliberately absent. The constraint applies to the whole project,
and overfwd and the shortener still run with `INGRESS_TRAFFIC_ALL`, so the only value that
fits today is `all`, which enforces nothing.

Infra is never auto-applied. This page is the human half.

## Before you apply

- **Who applies.** Org policies need `orgpolicy.policy.set`. Project Owner does **not**
  carry it, and `roles/orgpolicy.policyAdmin` can only be granted on the organization
  (overspiral.com). Run tofu as an identity that holds it there.
- **Secret-read alert.** `terraform_operators` (tfvars) lists the principals whose
  `tofu plan` secret reads do not page. If you apply as `angel@overspiral.com`, add it there
  first, or expect an `AccessSecretVersion` alert per plan.
- **Nothing depends on the default Compute SA.** Measured 2026-10-27, both projects:
  - Cloud Run services and jobs run as `overslash-<env>-{run,exporter,shortener,overfwd}`.
  - Cloud Build triggers run as `overslash-<env>-build`.
  - Scheduler jobs run as `overslash-<env>-scheduler`.
  - There are no Compute Engine instances.
  - The default SA has no user-managed keys and nobody holds `actAs` on it.
  - The only build that ever ran as it was the manual `gcloud builds submit` of 2026-04-29.

  Re-check before applying:

  ```bash
  P=overslash   # then overslash-dev
  N=$(gcloud projects describe $P --format='value(projectNumber)')
  gcloud run services list --project $P --format='value(metadata.name,spec.template.spec.serviceAccountName)'
  gcloud run jobs list --project $P --format='value(metadata.name,spec.template.spec.template.spec.serviceAccountName)'
  gcloud builds triggers list --project $P --region europe-west1 --format='value(name,serviceAccount)'
  gcloud scheduler jobs list --project $P --location europe-west1 \
    --format='value(name,httpTarget.oauthToken.serviceAccountEmail,httpTarget.oidcToken.serviceAccountEmail)'
  gcloud compute instances list --project $P
  gcloud iam service-accounts keys list --managed-by=user --iam-account $N-compute@developer.gserviceaccount.com
  # expect: no "-compute@developer" anywhere, no instances, no keys
  ```

- **Manual builds after this.** A `gcloud builds submit` must name its account:
  `--service-account=projects/<p>/serviceAccounts/overslash-<env>-build@<p>.iam.gserviceaccount.com`.
  The org's `cloudbuild.useBuildServiceAccount` already requires this.

## Apply: dev first, then prod

```bash
make tofu-init
make tofu-plan ENV=dev
# Expect, under module.project_guardrails:
#   google_org_policy_policy.service_account_key_creation   (imported, 0 to change)
#   + 6 google_org_policy_policy
#   + 2 google_project_iam_member_remove
#   + google_project_service.apis["orgpolicy.googleapis.com"]
#   no google_project_iam_member.cloudservices_compute_editor (dev has no VPC connector)
# If unrelated drift shows up and you don't want it now:
#   cd infra && tofu workspace select dev && tofu plan -var-file=env/dev.tfvars \
#     -target=google_project_service.apis -target=module.project_guardrails -out=dev.tfplan && cd ..
make tofu-apply ENV=dev

make tofu-plan ENV=prod
# Expect: 11 to add, 0 to change, 0 to destroy under the same targets. That is the dev set
# plus google_project_iam_member.cloudservices_compute_editor[0], and no import.
make tofu-apply ENV=prod     # asks you to type `prod`
```

A read-only targeted plan was run on both workspaces before the PR. Prod showed exactly
`11 to add, 0 to change, 0 to destroy`. Dev showed 10 adds before the `import` block went in.
The sandbox cannot read the existing dev policy, so the operator's plan is the first to show
the import.

**Order inside the apply.** Terraform grants `roles/compute.editor` before it removes Editor
from the cloudservices agent, so the VPC connector never loses its instance-group
permissions. It sets the `preventPrivilegedBasicRoles…` policy only after both removals.

### Without Terraform (the Editor half only)

Dev's default Compute SA binding was removed this way on 2026-10-27, and `overslash-dev-api`
kept serving (`/health` 200). The module's `member_remove` is a no-op against an
already-removed binding, so doing this first is safe. For prod:

```bash
gcloud projects add-iam-policy-binding overslash \
  --member=serviceAccount:212015650448@cloudservices.gserviceaccount.com \
  --role=roles/compute.editor --condition=None
gcloud projects remove-iam-policy-binding overslash \
  --member=serviceAccount:212015650448@cloudservices.gserviceaccount.com \
  --role=roles/editor --condition=None
gcloud projects remove-iam-policy-binding overslash \
  --member=serviceAccount:212015650448-compute@developer.gserviceaccount.com \
  --role=roles/editor --condition=None
```

Grant before you remove, in that order.

## Verify — evidence for the CASA pack

```bash
for P in overslash-dev overslash; do
  echo "== $P"
  # 1. No Editor on either default account; compute.editor on cloudservices in prod only
  gcloud projects get-iam-policy $P --flatten='bindings[].members' \
    --format='value(bindings.role,bindings.members)' | grep -E 'compute@developer|cloudservices'
  # 2. The project-level policies
  for C in iam.automaticIamGrantsForDefaultServiceAccounts \
           iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts \
           iam.disableAuditLoggingExemption storage.publicAccessPrevention \
           sql.managed.restrictPublicIp sql.managed.restrictAuthorizedNetworks \
           iam.managed.disableServiceAccountKeyCreation; do
    printf '%s ' $C
    gcloud org-policies describe $C --project $P --format='value(spec.rules[0].enforce)'
  done
done
# 3. Recommender closes the P2s once it re-observes (can take a day). The command needs a
#    quota project where you hold serviceusage.services.use.
CLOUDSDK_BILLING_QUOTA_PROJECT=overslash-dev gcloud recommender recommendations list \
  --project overslash --location global --recommender google.iam.policy.Recommender \
  --format='value(priority,description,stateInfo.state)'
```

Expected:

- **Step 1:** dev prints only `roles/compute.instanceGroupManagerServiceAgent` for
  cloudservices. Prod prints that plus `roles/compute.editor`. Neither prints `roles/editor`.
- **Step 2:** every constraint prints `True`, except the three dev ones listed as off above,
  which print `False`.
- **Step 3:** the two `roles/editor` recommendations are gone, or `SUCCEEDED`.
- **Smoke test:** `api.overslash.com` 200, and the shortener (which reaches Valkey through
  the VPC connector) still resolves a link.

## Rollback

- **Editor half:** re-add the binding with `gcloud projects add-iam-policy-binding … --role=roles/editor`
  and delete the module's `member_remove` resource, or the next apply removes it again. The
  `preventPrivilegedBasicRoles…` policy blocks that re-grant, so set it to `FALSE` first.
- **A policy that blocks something legitimate:** flip its `enforce` in the module, or
  `gcloud org-policies reset <constraint> --project <p>` to fall back to what the org
  inherits.
