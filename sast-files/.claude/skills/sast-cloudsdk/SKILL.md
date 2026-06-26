---
name: sast-cloudsdk
description: >-
  Detect Cloud SDK misuse — public bucket ACLs, hardcoded access keys/secrets
  in SDK client constructors, and overly broad IAM policies/roles — across AWS
  (boto3, SDK JS/Java), Azure SDK, GCP google-cloud SDK, and IaC tools
  (Terraform, CDK, Pulumi). Uses a three-phase approach: recon (inventory SDK
  call sites and IaC blocks), batched verify (parallel subagents, 3 candidates
  each, taint and policy analysis), and merge (consolidate into
  sast/cloudsdk-results.md and sast/cloudsdk-results.json). Maps to OWASP Web
  2025 A02 and CWE-732.
version: 0.1.0
---

# Cloud SDK Misuse Detection

You are hunting for **Cloud SDK misuse** — three families of security defect that arise when application code and IaC call cloud provider SDKs without proper access controls or credential hygiene:

1. **Public bucket ACLs** — storage containers configured to allow anonymous read or write access, leaking application or user data to the public internet.
2. **Hardcoded credentials** — long-lived access keys, secret keys, service-account JSON blobs, or connection strings embedded literally in source code or IaC, giving any reader of the code (or git history) full cloud-account access.
3. **Overly broad IAM policies** — `Action: *`, `Resource: *`, subscription-scoped Owner/Contributor role assignments, or `allUsers` IAM bindings that violate least-privilege and turn any single compromised workload into full account takeover.

Unlike application-layer bugs, Cloud SDK misuse findings are often directly exploitable without needing a user-input trace: the misconfiguration itself is the vulnerability. The bucket is public right now. The key is committed right now. The policy is attached right now.

**Prerequisites**: `sast/architecture.md` must exist. Run `sast-analysis` first to know which cloud provider(s) and IaC tools the project actually uses — do not chase boto3 calls in a GCP-only repo.

This skill produces two outputs:

- `sast/cloudsdk-results.md` — human-readable findings
- `sast/cloudsdk-results.json` — canonical machine-readable findings (schema defined in the root CLAUDE.md)

Intermediate files (`sast/cloudsdk-recon.md`, `sast/cloudsdk-batch-*.md`) may be created during execution and must be cleaned up at the end.

> **Note on tooling overlap**: Dedicated scanners — `truffleHog`, `gitleaks`, `tfsec`, `checkov`, `kics`, `bandit` (plugin-based), `cfn-lint`, `Semgrep` with cloud rulesets — are faster and more exhaustive for credential and IaC scanning. This skill complements them: it catches cross-file patterns (e.g. a hardcoded key that feeds into a bucket-ACL call), runtime-path context that static scanners miss, and policy-analysis nuance. If the repo already runs one of those scanners in CI, cross-check findings and note which are net-new.

---

## What is Cloud SDK Misuse

### Public Bucket ACLs

A storage bucket (S3, GCS, Azure Blob Container) is made world-readable or world-writable by an explicit SDK call or IaC declaration. The content of the bucket determines severity:

- A bucket holding user-generated content, PII, session tokens, configuration files, or application data is **critical** when public-read-write and **high** when public-read (read-only still leaks the data, but arbitrary writes additionally enable malware hosting, data tampering, and phishing via the bucket's CDN URL — raise to **critical** for public-read-write).
- A bucket explicitly designated for static public-asset hosting (CSS, JS, images) with no user-generated content, a documented asset-type allowlist, and upload controlled by a separate authenticated path can be treated as **info** after confirming those conditions.

The key question is always: "Does this bucket receive or store data beyond the specific public asset category its configuration was designed for?"

### Hardcoded Credentials

A long-lived access key, secret key, password, or service-account credential embedded literally in source code, configuration files, or IaC. This differs from:

- Credentials read from `os.environ` / `process.env` / `System.getenv` — these are environment-injected and are **not** hardcoded.
- Credentials retrieved at runtime from a secrets manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler) — these are **not** hardcoded.
- Test fixtures clearly marked `// test-only`, scoped to a test account with no real resources, and confirmed not deployed to production — downgrade to **info** with a note.

AWS access key IDs start with `AKIA` (long-lived) or `ASIA` (short-lived STS — usually fine but verify). A literal `AKIA`-prefixed key is **critical** regardless of context.

### Overly Broad IAM

An IAM policy or role binding that grants more privilege than the workload requires. Common shapes:

- `"Action": "*"` or `"Resource": "*"` in an AWS IAM policy JSON
- `"Effect": "Allow"` with a wildcard action and an unscoped resource on a production-bound policy
- Azure role assignment with `Owner` or `Contributor` at subscription scope (vs. resource group or resource scope)
- GCP IAM binding with `role: roles/owner` or `role: roles/editor` on a project (vs. a specific service)
- GCP IAM binding with `member: allUsers` or `member: allAuthenticatedUsers` granting any role
- Terraform `aws_iam_policy` with a wildcard `Statement` attached to a resource that is deployed to production

**FP-killers for IAM**: a policy is acceptable when (a) its `Resource` ARN is scoped to a specific, narrow resource and its `Action` list is the documented minimum for the workload, and (b) there is inline documentation (comment, ticket reference) justifying any elevated scope.

---

## What Cloud SDK Misuse IS and IS NOT

### IS

- A literal AWS access key ID + secret in a Python file, Terraform variable, `.env` committed to git, Java properties file, or IaC JSON.
- A `put_bucket_acl(ACL='public-read-write')` call on a bucket that receives user uploads or application data.
- A `bucket.make_public()` call in a GCP Python script without a confirmed static-asset designation.
- An IAM policy with `"Action": "*"` on any non-toy resource.
- An Azure `BlobServiceClient` instantiated with a literal storage account key string.
- A GCP `storage.Client()` constructed with a literal `service_account_info={...}` dict in source code.
- A `google_storage_bucket_iam_member` Terraform resource binding `allUsers` to any role other than `roles/storage.objectViewer` on a confirmed public-asset bucket.
- `BlockPublicAcls=False` explicitly set in `put_public_access_block` on a bucket that processes sensitive data.

### IS NOT

- A bucket ACL of `public-read` on a bucket explicitly and verifiably used only for static assets (fonts, images, JS bundles) with no user-generated-content upload path — mark as **info**, note the asset designation, and do not flag as a vulnerability.
- A credential string read from `os.environ.get('AWS_SECRET_ACCESS_KEY')`, `boto3.Session()` with no explicit key (defers to the SDK credential chain), or a secrets-manager call.
- An IAM policy in a `test/` directory or clearly marked `// test-only` that is never attached to a production resource — downgrade to **info** with a note.
- IAM policies in vendored third-party modules (e.g. `node_modules/`, `vendor/`) — out of scope.
- GCP service account impersonation where the credential is fetched from the metadata server at runtime.
- Application-layer bugs (SQLi, XSS, SSRF) even inside code that also calls cloud SDKs — those belong to their own skills.

### Patterns That Indicate Correct Usage (Lower Confidence)

- `boto3.client('s3')` or `boto3.Session().client('s3')` with no explicit `aws_access_key_id` argument — the SDK credential chain resolves from the environment, instance role, or config file.
- `google.auth.default()` — ADC (Application Default Credentials) via Workload Identity or metadata server.
- `DefaultAzureCredential()` — the Azure SDK credential chain; not hardcoded.
- `os.environ['AWS_ACCESS_KEY_ID']` / `process.env.AWS_ACCESS_KEY_ID` — environment-injected.
- `secretsmanager.get_secret_value(SecretId='myapp/prod/db')` — secrets-manager retrieval.
- `BlockPublicAcls=True` in `put_public_access_block` with all four flags set.
- An `aws_s3_bucket_public_access_block` resource with `block_public_acls = true`, `block_public_policy = true`, `ignore_public_acls = true`, `restrict_public_buckets = true` immediately following the bucket declaration.

---

## Vulnerable vs. Secure Examples

### AWS / boto3 (Python)

**Vulnerable:**

```python
import boto3

# Hardcoded long-lived key — anyone who reads this file owns the account
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region_name='us-east-1',
)

# Public-read-write on a user-uploads bucket — world can read AND write
s3.put_bucket_acl(Bucket='user-uploads', ACL='public-read-write')

# Explicitly disabling all public-access protection
s3.put_public_access_block(
    Bucket='user-uploads',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': False,
        'IgnorePublicAcls': False,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False,
    }
)
```

**Secure:**

```python
import boto3

# No explicit key — resolves via credential chain (instance role, env var, ~/.aws/credentials)
s3 = boto3.client('s3', region_name='us-east-1')

# Block all public access
s3.put_public_access_block(
    Bucket='user-uploads',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True,
    }
)
# Use pre-signed URLs for controlled temporary access instead of public ACLs
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'user-uploads', 'Key': key},
    ExpiresIn=3600,
)
```

### AWS IAM Policy (Python JSON inline)

**Vulnerable:**

```python
import boto3, json

iam = boto3.client('iam')
# God-mode policy — any workload using this can do anything in the account
iam.create_policy(
    PolicyName='AppPolicy',
    PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",          # wildcard action
            "Resource": "*"         # wildcard resource
        }]
    })
)
```

**Secure:**

```python
import boto3, json

iam = boto3.client('iam')
# Least-privilege: only the actions the app actually needs, scoped to its own bucket
iam.create_policy(
    PolicyName='AppS3ReadPolicy',
    PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::my-app-bucket",
                "arn:aws:s3:::my-app-bucket/*"
            ]
        }]
    })
)
```

### Azure SDK (Python)

**Vulnerable:**

```python
from azure.storage.blob import BlobServiceClient, PublicAccess

# Literal storage account key — rotate immediately if committed
client = BlobServiceClient(
    account_url="https://myaccount.blob.core.windows.net",
    credential="DefaultEndpointsProtocol=https;AccountName=myaccount;"
               "AccountKey=dGhpcyBpcyBub3QgYSByZWFsIGtleQ==;EndpointSuffix=core.windows.net"
)

# Setting container public access to 'container' exposes all blobs as list+read
client.create_container('user-data', public_access=PublicAccess.Container)
```

**Secure:**

```python
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

# DefaultAzureCredential resolves via Managed Identity, environment, or CLI login
credential = DefaultAzureCredential()
client = BlobServiceClient(
    account_url="https://myaccount.blob.core.windows.net",
    credential=credential
)

# No public access — use SAS tokens for controlled sharing
client.create_container('user-data')  # PublicAccess defaults to None
```

### GCP (Python)

**Vulnerable:**

```python
from google.cloud import storage
from google.oauth2 import service_account

# Literal service-account JSON in source — full project access for anyone who sees the code
info = {
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "key-id",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
    "client_email": "svc@my-project.iam.gserviceaccount.com",
    "client_id": "123456789",
}
credentials = service_account.Credentials.from_service_account_info(info)
client = storage.Client(credentials=credentials, project="my-project")

bucket = client.bucket("user-uploads")
# Makes every object in the bucket readable by anyone on the internet
bucket.make_public(recursive=True, future=True)
```

**Secure:**

```python
from google.cloud import storage

# ADC via Workload Identity Federation or metadata server — no key in code
client = storage.Client()

bucket = client.bucket("user-uploads")
# Use uniform bucket-level access + IAM instead of per-object ACLs
bucket.iam_configuration.uniform_bucket_level_access_enabled = True
bucket.patch()
# Grant specific service accounts read access rather than making public
policy = bucket.get_iam_policy(requested_policy_version=3)
policy.bindings.append({
    "role": "roles/storage.objectViewer",
    "members": {"serviceAccount:frontend@my-project.iam.gserviceaccount.com"},
})
bucket.set_iam_policy(policy)
```

### Terraform (AWS)

**Vulnerable:**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "user-uploads-prod"
  acl    = "public-read-write"   # world read + write
}

# No aws_s3_bucket_public_access_block resource — all public-access guardrails absent

resource "aws_iam_policy" "app" {
  name   = "app-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"        # wildcard — full account takeover if workload is compromised
      Resource = "*"
    }]
  })
}
```

**Secure:**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "user-uploads-prod"
  # no acl — defaults to bucket-owner-full-control; further blocked below
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

resource "aws_iam_policy" "app" {
  name   = "app-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject"]
      Resource = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })
}
```

### Terraform (GCP)

**Vulnerable:**

```hcl
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.uploads.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"   # anonymous internet — anyone can read
}

resource "google_project_iam_member" "app_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:app@${var.project_id}.iam.gserviceaccount.com"
  # Owner at project level — catastrophic blast radius
}
```

**Secure:**

```hcl
resource "google_storage_bucket_iam_member" "app_read" {
  bucket = google_storage_bucket.uploads.name
  role   = "roles/storage.objectViewer"
  # Scoped to the specific service account that needs access
  member = "serviceAccount:frontend@${var.project_id}.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "app_storage" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"   # minimum role for managing objects
  member  = "serviceAccount:app@${var.project_id}.iam.gserviceaccount.com"
}
```

---

## Test Fixture Reference

These cases are used to calibrate verify-phase reasoning:

| Case | Code | Expected verdict |
|---|---|---|
| TP — critical | `s3.put_bucket_acl(Bucket='user-uploads', ACL='public-read-write')` on a bucket with user-generated content | reachable, critical |
| TN — info | `s3.put_bucket_acl(Bucket='static-assets', ACL='public-read')` with a documented static-only policy and no UGC upload path | false positive, info |
| TN — not a finding | `s3.put_public_access_block(Bucket='uploads', PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})` | mitigated, no finding |
| TP — critical | `boto3.client('s3', aws_access_key_id='AKIAIOSFODNN7EXAMPLE', aws_secret_access_key='...')` in production code | reachable, critical, chain_id: cloud-key-exposure |
| TN — not a finding | `boto3.client('s3', aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'])` | FP — env-var reference |
| TP — high | `"Action": "*", "Resource": "arn:aws:s3:::my-bucket/*"` (wildcard action, scoped resource) | conditional, high |
| TP — critical | `"Action": "*", "Resource": "*"` on a production-attached policy | reachable, critical |
| TN — info | `"Action": "*", "Resource": "*"` in `test/fixtures/iam.json` marked `// test-only` | FP, downgrade to info |

Only the TP rows result in findings. TN rows must not appear in the output JSON.

---

## Execution

### Phase 1: Recon — Inventory SDK Call Sites and IaC Blocks

Read `sast/architecture.md` first. Identify which cloud provider(s) and IaC tools are in scope and skip families that are not used by this project. Then run the grep and glob patterns below in parallel.

#### AWS boto3 / AWS SDK JS / AWS SDK Java

Grep for these patterns across `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.java`, `**/*.json`, `**/*.yml`, `**/*.yaml`, `**/*.properties`, `**/*.env*`, `**/*.tf`, `**/*.tfvars`:

| Pattern | What it finds |
|---|---|
| `put_bucket_acl.*ACL.*public-read` | Python boto3 public ACL call |
| `putBucketAcl.*PublicRead` | SDK JS/Java public ACL |
| `aws_access_key_id\s*=\s*['"]AKIA` | Hardcoded AWS access key ID (Python kwarg) |
| `AWSAccessKeyId.*AKIA` | Hardcoded key in properties/env/config |
| `aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]` | Hardcoded AWS secret key (40-char base64) |
| `BlockPublicAcls.*False` | Explicit disable of public-access block |
| `"Action":\s*"\*"` | Wildcard IAM action in JSON policy |
| `"Resource":\s*"\*"` | Wildcard IAM resource in JSON policy |
| `acl\s*=\s*"public-read` | S3 bucket ACL in Terraform HCL |
| `block_public_acls\s*=\s*false` | Explicit public-access unblock in Terraform |
| `create_policy\|put_role_policy\|put_user_policy` | IAM policy attachment entry points |
| `aws_iam_access_key` | Long-lived IAM user key resource in Terraform |

#### Azure SDK

Grep across `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.cs`, `**/*.java`, `**/*.bicep`, `**/azuredeploy*.json`, `**/arm/**/*.json`:

| Pattern | What it finds |
|---|---|
| `BlobServiceClient.*credential=.*['"][A-Za-z0-9+/=]{60,}` | Literal key in Azure BlobServiceClient |
| `AccountKey=` | Literal account key in connection string |
| `PublicAccess\.Container\|PublicAccess\.Blob` | Container/blob public access set |
| `RoleDefinitionId.*Owner\|Contributor` | Broad Azure role assignment in ARM/bicep |
| `roleDefinitionId.*Owner\|Contributor` | Same, alternate casing |
| `subscription.*scope.*role` | Subscription-scoped role assignment |

#### GCP google-cloud SDK

Grep across `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.java`, `**/*.tf`:

| Pattern | What it finds |
|---|---|
| `from_service_account_info\s*\(` | Literal SA JSON dict passed to SDK |
| `service_account_info\s*=\s*{` | Inline SA credentials dict |
| `make_public\s*\(` | `bucket.make_public()` call |
| `allUsers\|allAuthenticatedUsers` | Public IAM member in binding |
| `roles/owner\|roles/editor` | Overly broad GCP role on project |
| `"private_key":\s*"-----BEGIN` | Literal RSA/EC private key in JSON blob |
| `member\s*=\s*"allUsers"` | Public GCS IAM member in Terraform |

#### Committed credential files

Glob for:

- `**/.env`, `**/.env.*` (excluding `.env.example`, `.env.sample`, `.env.template`)
- `**/*credentials*.json`, `**/*service-account*.json`, `**/*serviceaccount*.json`
- `**/*keyfile*.json`, `**/*key.json`
- `**/*.pem`, `**/*.p12`, `**/*.pfx`

For each hit, note: file path, line number, cloud provider family, candidate category (public-acl / hardcoded-cred / broad-iam), and a one-line description of why it is a candidate. Verify against `sast/architecture.md` that the resource is production-bound and not a test fixture or vendored dependency.

Write all candidates to `sast/cloudsdk-recon.md` as a flat list grouped by category. If zero candidates are found across all families, write `sast/cloudsdk-results.md` and `sast/cloudsdk-results.json` (with empty `findings: []`) noting no cloud-SDK misuse was detected, clean up, and stop.

### Phase 2: Verify — Taint and Policy Analysis (Batched)

Split the candidate list from `sast/cloudsdk-recon.md` into batches of **3 candidates each**. Launch one subagent per batch, in parallel. Give each subagent this instruction pattern:

> Read the assigned candidate files, the surrounding call context, and `sast/architecture.md`. For each candidate, apply the verification questions below for its category. Determine whether the candidate is a true positive or false positive; assign severity, exploitability, and confidence; write all findings to `sast/cloudsdk-batch-<n>.md`.

**Verify questions — Public ACL candidates**:

1. What data does the bucket contain? Read the code that writes to the bucket (upload handlers, ETL jobs, SDK `put_object` / `upload_file` / `upload_blob` calls feeding this bucket). Is the content exclusively public static assets (CSS, JS, fonts, images) with no user-generated or application-specific data path?
2. Is there a documented static-asset designation? Look for comments, README sections, or IaC annotations explicitly stating this bucket serves only public content with an asset-type allowlist.
3. Is there an `aws_s3_bucket_public_access_block` resource (Terraform) or `put_public_access_block` call (SDK) with all four flags `True` already in the same file or nearby that would override or remediate the ACL? If yes, the ACL is effectively moot — do not flag.
4. Is the ACL set in a dev/test fixture path (`test/`, `tests/`, `fixtures/`, `examples/`, `demo/`) that is not deployed to production?
5. For `public-read-write`: does any code path allow unauthenticated users to write objects? This enables malware hosting, phishing pages, and data tampering — raise to critical.

If the bucket receives any user-generated content or application data: **TP, severity critical** when `public-read-write`, **high** when `public-read`. If confirmed static-asset-only with no UGC path: **FP, flag as info**. If dev/test fixture only: **info**.

`exploitability`: `reachable` when the bucket contains user or application data and the ACL is in production-bound code; `conditional` when data type is unclear or when a public-access block may partially mitigate; `unreachable` when confirmed static-only or test-only.

`confidence`: `high` when `public-read-write` or `make_public(recursive=True)` on a bucket with named user-upload paths; `medium` when `public-read` on a bucket whose content type requires investigation; `low` when in an examples/ directory.

**Verify questions — Hardcoded credential candidates**:

1. Is the key string a literal static value, or is it a variable reference that happens to have the word "key" in its name (e.g. `aws_access_key_id=access_key_var` where `access_key_var` is read from the environment)? Trace the variable to its assignment.
2. For `AKIA`-prefixed strings: confirm it is 20 characters, starts with `AKIA`, and is followed by alphanumeric characters — this is a genuine AWS Access Key ID format. A placeholder like `AKIAIOSFODNN7EXAMPLE` in example documentation is a teaching example (flag as info, not critical).
3. Is the credential read from `os.environ`, `process.env`, a secrets-manager call (`get_secret_value`, `SecretClient.get_secret`, `SecretManagerServiceClient.access_secret_version`), or a Kubernetes secret mounted as an environment variable? If so, FP.
4. Is the file a test fixture marked `// test-only` or in a `test/` directory, and does `sast/architecture.md` confirm it is never deployed to production? If yes, info.
5. Is the key in a `.env` file? Check whether `.env` is listed in `.gitignore`. If it is gitignored and not committed to the repo, it is not a finding. If the `.env` file itself is committed (visible in the repo), it is a finding regardless of `.gitignore` because the file is already in git history.

If literal `AKIA`-prefixed key (not a known placeholder): **TP, severity critical**. If literal secret key without public key prefix confirmation: **TP, severity high**. If environment variable reference or secrets-manager call: **FP**. If test-only with no production path: **info**.

`exploitability`: `reachable` for any committed long-lived credential; `conditional` for a credential in a non-deployed config file; `unknown` when deployment scope is unclear.

`confidence`: `high` for `AKIA`-prefixed key or a 40-char base64 secret alongside an `AKIA` key; `medium` for other secret-shaped strings without the key-ID prefix; `low` for pattern matches in obvious example/template files.

**Verify questions — Broad IAM candidates**:

1. What is the `Resource` field? If it is `"*"` (all resources in the account), the blast radius is account-wide — **TP**. If it is a specific ARN (e.g. `arn:aws:s3:::my-bucket/*`), check whether the `Action` list is also scoped — if yes, likely **FP**.
2. What is the `Action` field? A list like `["s3:GetObject","s3:PutObject"]` on a scoped resource is fine. A wildcard `"*"` on any resource is always **TP**. A service-level wildcard (`s3:*`) on all buckets is **medium** to **high** depending on the bucket's sensitivity.
3. Is the policy actually attached to a resource? An IAM policy that is defined but never attached via `aws_iam_role_policy_attachment`, `aws_iam_user_policy`, or `aws_iam_group_policy` is still a finding (it could be attached later) but lower confidence.
4. For Azure role assignments: is the scope at the subscription (bad) or a resource group / specific resource (acceptable)? Read the `scope` field.
5. For GCP: is `allUsers` or `allAuthenticatedUsers` the member? Is the role anything beyond `roles/storage.objectViewer` on a confirmed public-asset bucket?
6. Is this policy in a test directory, a vendored third-party module, or a commented-out block?

Severity: **critical** when `Action: *` + `Resource: *` (account takeover). **High** when `Action: *` on a scoped resource, or `Resource: *` with a broad-but-not-wildcard action set. **Medium** when subscription-scoped broad role in Azure, or project-level `roles/editor` in GCP. **Low** when `allUsers` gets read-only access to a confirmed public-asset bucket (defense-in-depth gap).

`exploitability`: `reachable` when the policy is attached to a production workload and the `Action`/`Resource` scope exceeds documented need; `conditional` when the policy exists but workload attachment is unclear; `unreachable` when in test fixtures not deployed.

`confidence`: `high` for `"Action": "*", "Resource": "*"` in production-bound Terraform or deployed SDK call; `medium` for broad role assignments where scope requires confirmation; `low` for policies in example directories or unattached resources.

**chain_id assignment**:

- Finding is a hardcoded key AND `sast-hardcodedsecrets` has already reported the same literal in `sast/hardcodedsecrets-results.json`: set `chain_id: "cloud-key-exposure"`. Do not duplicate the finding body — reference the partner finding ID in the description.
- Finding is a public bucket ACL or missing public-access block in Terraform/CDK/Pulumi AND `sast-iac` has already reported the same resource in `sast/iac-results.json`: set `chain_id: "iac-public-bucket"`. Reference the partner finding ID.
- Finding is standalone with no partner: `chain_id: null`.

Each batch subagent owns its assigned candidates end-to-end and must not read files outside its assigned slice.

### Phase 3: Merge — Consolidate Batch Results

Read every `sast/cloudsdk-batch-*.md`. Merge into a single `sast/cloudsdk-results.md` using the template below. De-duplicate: if the same hardcoded key appears in multiple files (e.g. copy-pasted across `config/dev.py` and `config/staging.py`), collapse into one finding whose `location` points to the first occurrence and whose description lists all affected paths.

Also emit `sast/cloudsdk-results.json` per the canonical schema (see root CLAUDE.md). Severity levels for cloud SDK misuse:

- **critical** — literal `AKIA`-prefixed access key in source; `public-read-write` ACL on a bucket confirmed to hold user or application data; `Action: *` + `Resource: *` IAM policy on a production-bound workload; literal GCP service-account private key in source.
- **high** — `public-read` ACL on a bucket with non-public content; hardcoded secret key alongside a confirmed AKIA key; `Action: *` on a scoped resource; subscription-level Owner/Contributor in Azure; `roles/owner` or `roles/editor` at GCP project level.
- **medium** — overly broad IAM policy that is not wildcard but materially exceeds least-privilege (e.g. `s3:*` on all buckets); project-level `roles/editor` in GCP; `BlockPublicAcls=False` without a confirmed ACL call but on a sensitive bucket; `allAuthenticatedUsers` binding beyond read-only; `aws_iam_access_key` resource in Terraform (prefer OIDC).
- **low** — missing `server_side_encryption_configuration` on a sensitive S3 bucket (posture gap); `allUsers` with read-only on a near-public bucket (defense-in-depth gap).
- **info** — public ACL on a confirmed static-only bucket; IAM wildcard in a test fixture never deployed; hardcoded key in a commented-out block; placeholder example keys in documentation.

After writing results, delete `sast/cloudsdk-recon.md` and all `sast/cloudsdk-batch-*.md` files.

### False-positive handling

- **Environment-variable references**. `boto3.client('s3', aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'])` — the credential comes from the environment. Not a hardcoded credential. Do not flag.
- **ADC / credential-chain clients**. `boto3.client('s3')`, `DefaultAzureCredential()`, `google.auth.default()`, `storage.Client()` with no explicit credential — these resolve at runtime via IAM roles, Workload Identity, or the local credential cache. Not hardcoded.
- **Static-asset CDN buckets**. A `public-read` ACL on a bucket fronting a CDN where: (a) the bucket name contains `static`, `assets`, `public`, `cdn`, (b) only CSS/JS/image extensions are uploaded to it, (c) there is no user-data write path, and (d) the IaC or code has a comment confirming this intent. Flag as **info**, note the CDN wiring, and do not count as a vulnerability.
- **Test-only IAM**. A `"Action": "*"` policy in a file under `test/`, `tests/`, `spec/`, `fixtures/`, or `examples/` that is not referenced by any production Terraform module or deployment script — flag as **info** with a note that it should never be promoted.
- **Example/demo repos**. Files under `examples/`, `demo/`, `samples/` explicitly called out in the README as teaching material — downgrade everything to **info**.
- **Vendor/generated code**. IaC auto-generated by the cloud console, CDK `cdk.out/`, or Terraform `.terraform/` lock files — exclude from findings. These are not human-maintained.
- **Gitignored `.env` files**. If the `.env` file is in `.gitignore` and is not tracked by git (confirmed by checking `git ls-files`), it is not a committed credential — do not flag. If it IS tracked by git, it is a finding.

Do not silently drop findings. Every downgrade must appear in the finding notes with the reason.

---

## Findings

Write the merged output to `sast/cloudsdk-results.md` using this template:

```markdown
# Cloud SDK Misuse — Findings

_Scanned N candidates across AWS (boto3/SDK JS/Java), Azure SDK, GCP google-cloud SDK, Terraform, CDK, and Pulumi._

## Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |

## Findings

### [CLOUDSDK-001] <short title>

- **Severity**: critical | high | medium | low | info
- **File**: `path/to/file.py:42`
- **Category**: hardcoded-cred | public-acl | broad-iam
- **Cloud**: AWS | Azure | GCP | multi-cloud
- **CWE**: CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **chain_id**: cloud-key-exposure | iac-public-bucket | null

**Offending snippet**

```python
s3 = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
)
```

**Why it matters**

The literal AKIA-prefixed access key and 40-character secret key are embedded in source code at `infra/setup.py:12`. Any developer, CI system, or attacker with read access to this repository (including public forks, CI logs, or a leaked archive) can authenticate as the IAM user associated with this key. Long-lived keys do not expire automatically; this key will remain valid until explicitly rotated in the AWS console. If the repository has ever been public, even briefly, the key should be treated as compromised.

**Fix**

1. Revoke the key immediately in the AWS IAM console.
2. Remove the literal key from source code.
3. Replace with IAM instance roles (EC2), OIDC federation (GitHub Actions, GitLab CI), or Workload Identity for production workloads.
4. For local development, configure `~/.aws/credentials` or `AWS_PROFILE` — never embed keys in code.
5. Run `git filter-repo` or BFG Repo Cleaner to purge the key from git history.

```python
# No explicit key — SDK resolves via instance role or environment
s3 = boto3.client('s3', region_name='us-east-1')
```

**Notes**

Also present at `scripts/deploy.py:7` — collapsed into this finding. FP check: confirmed literal key, not an env-var reference. If `sast-hardcodedsecrets` also reported this key, link that finding ID here and set chain_id to `cloud-key-exposure`.

---

### [CLOUDSDK-002] ...
```

Also write `sast/cloudsdk-results.json`:

```json
{
  "findings": [
    {
      "id": "cloudsdk-001",
      "skill": "sast-cloudsdk",
      "severity": "critical",
      "title": "Hardcoded AWS access key and secret in SDK client constructor",
      "description": "A literal AKIA-prefixed AWS access key ID and 40-character secret key are embedded at infra/setup.py:12. Any reader of the repository can authenticate as the IAM user associated with this key. Long-lived keys do not expire. Also present at scripts/deploy.py:7. Cross-reference: sast-hardcodedsecrets-001 if that skill also reported this literal.",
      "location": { "file": "infra/setup.py", "line": 12, "column": 5 },
      "remediation": "Revoke the key immediately in IAM. Remove from source. Replace with IAM instance role, OIDC federation, or environment-variable injection from a secrets manager. Run git filter-repo to purge from history.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "cloud-key-exposure"
    }
  ]
}
```

If no findings, still write both files with an empty `findings` array and an explanatory note in the markdown:

```
_No Cloud SDK misuse detected across N candidates.
Note: dedicated scanners (truffleHog, gitleaks, tfsec, checkov, kics, Semgrep cloud rulesets) should still be run in CI — they cover more patterns than this skill and catch historical commits in git log._
```

---

## chain_id Reference

| chain_id | Meaning | Skills involved |
|---|---|---|
| `cloud-key-exposure` | A hardcoded cloud credential found by this skill that is also (or could be) reported by `sast-hardcodedsecrets`. Link findings; do not duplicate the finding body. | `sast-cloudsdk` + `sast-hardcodedsecrets` |
| `iac-public-bucket` | A public bucket ACL or missing public-access block in Terraform/CDK/Pulumi that is also (or could be) reported by `sast-iac`. Link findings; do not duplicate. | `sast-cloudsdk` + `sast-iac` |
| `null` | Finding is standalone; no cross-skill chain identified. | — |

When cross-linking, include the partner skill's finding ID in the **Notes** section of the markdown finding and in the `description` field of the JSON. Do not emit two JSON findings with the same root cause — pick the skill that has the richer context (usually `sast-cloudsdk` for SDK-call-site evidence; `sast-iac` for pure IaC-only findings without an SDK companion call) and set the `chain_id` on both.

---

## Important Reminders

- Always read `sast/architecture.md` before recon. A project targeting GCP does not need boto3 grep patterns. A pure-Python backend without Azure dependencies does not need bicep globs.
- The three finding families (public-acl, hardcoded-cred, broad-iam) have different exploitation paths and different urgency. A hardcoded `AKIA` key is a direct credential compromise right now. A broad IAM policy is a blast-radius amplifier that only matters when another vulnerability is also present. A public bucket leaks data silently and may have been doing so since the bucket was created.
- When a bucket's public-access block is set with all four flags `True` immediately after (or in the same resource block as) a `public-read` ACL call, the block takes precedence and the ACL is effectively moot — downgrade or eliminate the finding and note the mitigation explicitly.
- Recommend running `truffleHog` (for git history scanning beyond the working tree), `gitleaks` (pre-commit), `tfsec`/`checkov`/`kics` (IaC CI gate), and `Semgrep` with the `p/aws-lambda`, `p/terraform`, or equivalent cloud rulesets in CI. This skill is a complement that adds SDK call-site context and cross-file policy tracing.
- If you find a credential, check `sast/hardcodedsecrets-results.json` before emitting a finding. If the same literal is already reported there, set `chain_id: "cloud-key-exposure"` on both and reference each other's finding IDs — do not create a duplicate.
- If you find a public bucket in IaC, check `sast/iac-results.json` before emitting a finding. If the same resource is already reported there, set `chain_id: "iac-public-bucket"` on both and reference each other's finding IDs — do not create a duplicate.
- Committed credentials are compromised credentials. Treat rotation as urgent regardless of whether the key appears to have been used maliciously — assume compromise and rotate before closing the finding.
