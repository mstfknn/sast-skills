---
name: sast-agentidentity
description: >-
  Detect over-privileged non-human agent identities — service accounts, API
  tokens, IAM roles, and CI credentials used by automated pipelines that carry
  broader permissions than the agent's task requires, violating least privilege
  for non-human identities. Applies LLM-driven scope-vs-need analysis to
  distinguish genuine over-permission from permissions constrained by boundary
  controls or OIDC short-lived issuance. Outputs findings to
  sast/agentidentity-results.md and the canonical sast/agentidentity-results.json.
  Use when asked to audit agent credentials, CI/CD role permissions, or
  programmatic identity least privilege.
version: 0.1.0
---

# Over-Privileged Agent Non-Human Identity Detection

You are hunting for **over-privileged non-human identities** — service accounts, API tokens, IAM roles, and programmatic credentials used by AI agents, CI/CD pipelines, and automated workflows that carry more permission than the agent's documented task actually requires. This is not a regex scan for wildcards. The core question is always: **does the credential scope exceed the documented need of this agent's task, and does any boundary control prevent escalation?**

ASI26 ASI03 / CWE-269 (Improper Privilege Management) / CWE-250 (Execution with Unnecessary Privileges).

**Prerequisites**: `sast/architecture.md` must exist. Run `sast-analysis` first so you know which cloud provider, CI platform, and agent frameworks the project actually uses.

This skill produces two outputs:

- `sast/agentidentity-results.md` — human-readable findings
- `sast/agentidentity-results.json` — canonical machine-readable findings (schema defined in the root CLAUDE.md)

Intermediate files (`sast/agentidentity-recon.md`, `sast/agentidentity-batch-*.md`) may be created during execution and must be cleaned up at the end.

> **Note on tooling overlap**: Dedicated scanners — `checkov`, `tfsec`, `semgrep` with IAM rulesets, `actionlint` — catch some of these patterns. This skill goes further: it applies LLM reasoning about whether the agent's *actual documented task* justifies the scope it has been granted, catches cross-file patterns (an `.mcp.json` env var feeding into a Terraform-deployed IAM role), and surfaces the distinction between static long-lived credentials and dynamically issued OIDC tokens.

---

## What Is an Over-Privileged Agent Identity

A non-human identity is over-privileged when the permissions it holds exceed the minimum required to complete the agent's documented, observable task. The vulnerability is not the existence of a credential — it is the mismatch between scope and need.

**Typical shapes:**

- **Wildcard IAM actions or resources** — `"Action": "*"` / `"Resource": "*"` in an agent IAM policy, or `AdministratorAccess` attached to an agent role. Even without a wildcard, a list of 40 actions on `"Resource": "*"` may be over-privileged if the agent only needs `s3:GetObject` on one bucket.
- **CI `permissions: write-all` or implicit-all** — a `permissions: {}` block (meaning "inherit repository defaults," which are often broad) or an explicit `write-all` on a workflow that only needs `contents: read`. If a step injects `AWS_ACCESS_KEY_ID` at the job level but only one of five steps requires it, the credential is visible for longer than necessary.
- **Static long-lived API keys in agent environment config** — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AWS_ACCESS_KEY_ID`, or vendor API keys set as static environment variables in `.mcp.json`, agent framework config, or `docker-compose.yml`. Static = long-lived = if leaked, the blast radius is unbounded until manual revocation.
- **`iam:PassRole` without condition** — allows the agent to pass any role to any service, which is effectively `sts:AssumeRole` with an open account. Combined with `iam:CreateRole`, this is account takeover.
- **Container privilege escalation** — `privileged: true` on an agent container, `/var/run/docker.sock` bind mount, or `hostNetwork: true`. These grant the agent kernel-level reach regardless of the IAM policy assigned to the pod.
- **Secrets injected at job scope instead of step scope** — in GitHub Actions, a secret visible to all steps in a job can be exfiltrated by a compromised dependency or supply-chain attack on any step, not just the one that legitimately needs it.

### What Over-Privileged Agent Identity IS

- An IAM policy or CI permissions block granting capabilities the agent's code never exercises.
- A static credential where a dynamically issued short-lived credential (OIDC, Vault) would suffice.
- A secret or token injected at a scope wider than necessary (job vs. step, namespace vs. specific resource).
- A container runtime privilege that enables host escape, regardless of the IAM policy assigned to the workload.

### What Over-Privileged Agent Identity is NOT

- **Human user credentials** — a developer's AWS access keys configured in `~/.aws` are a different threat model (`sast-hardcodedsecrets` handles literal key values in code; this skill handles programmatic agent identity at the infrastructure layer).
- **Tokens explicitly scoped to minimum and reviewed** — a `GITHUB_TOKEN` used only in a workflow step that runs `gh pr comment` where `permissions: pull-requests: write` is set exactly, with all other permissions denied. That is correct least privilege — not a finding.
- **Secrets managed by a vault with dynamic short-lived credentials** — if the project uses GitHub Actions OIDC → AWS STS AssumeRoleWithWebIdentity with a TTL of 15 minutes scoped to a single S3 bucket, the dynamic issuance eliminates the static credential risk even if the IAM *statement* is somewhat broad.
- **Permissions constrained by an SCP or permission boundary** — `"Action": "*"` on `"Resource": "*"` in an inline policy where the account has an SCP that explicitly denies `iam:*`, `ec2:*`, and all data-plane services except S3 is not the same risk as the same inline policy with no boundary. Note the boundary but downgrade severity.

**Defer to a sibling skill — do not raise an agentidentity finding for these:**

- **Missing authentication on an MCP tool handler** (`auth: null`, no caller-identity check, wildcard `allowedOrigins`) is **sast-mcpsec**, not agentidentity. This skill covers a credential or role scoped *broader than the task needs* — an over-privileged identity (static keys, `permissions: write-all`, wildcard IAM) — not the *absence of an auth gate* on a tool.
- **Hidden instructions or shell hooks** in skill config or repo config are **sast-skillaudit** / **sast-configrce**. A hard-coded secret *value* in source is **sast-hardcodedsecrets** (this skill handles the identity/scope layer, not the literal-string layer).

### Patterns That Eliminate or Downgrade Findings

Presence of any of the following should trigger careful FP analysis before raising a finding:

- **OIDC dynamic credential issuance** — GitHub Actions `id-token: write` permission plus `aws-actions/configure-aws-credentials` with a `role-to-assume` and `aws-region`. The key is never static; it expires in ≤1 h. This eliminates the static credential risk. The *role's* IAM policy may still be over-scoped — evaluate that separately.
- **Permission boundaries** — `PermissionsBoundary: arn:aws:iam::123456789012:policy/AgentBoundary` on the IAM role. A wildcard in the role's inline policy is constrained by the boundary. Downgrade from critical to medium; note the boundary ARN.
- **SCPs** — organizational service control policies that explicitly deny privileged actions. The same logic as a permission boundary — downgrade, don't eliminate, because SCPs can be changed by the org admin and are not visible in the repo scan.
- **Scoped GitHub `permissions:` block** — `permissions: contents: read` at the job level with no broader inheritance means the `GITHUB_TOKEN` can only read repository contents. If the step that uses it is consistent with that scope, the GitHub token is correctly privileged.
- **Vault or secret manager dynamic issuance** — HashiCorp Vault AWS secrets engine, AWS Secrets Manager rotation, or Doppler secrets injection with a short TTL. The static key is never present on disk or in the CI environment.
- **Resource ARN constraints** — `"Resource": "arn:aws:s3:::my-agent-bucket/*"` with `"Action": ["s3:GetObject", "s3:PutObject"]` is fine even without a wildcard check if the agent's task is specifically "read and write to that one bucket." The question is always task vs. scope.

---

## Vulnerable vs. Secure Examples

### GitHub Actions — CI Credential Scope

**Vulnerable:**

```yaml
# .github/workflows/agent.yml
name: AI Agent Deploy

on:
  push:
    branches: [main]

permissions: write-all                    # all repository permissions open

jobs:
  run-agent:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}       # static key
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}       # injected at job level
    steps:
      - uses: actions/checkout@v4
      - name: Run database migration
        run: python migrate.py                                   # only needs DB access
      - name: Run AI summarization
        run: python summarize.py                                 # only needs ANTHROPIC_API_KEY
      - name: Upload report
        run: aws s3 cp report.txt s3://my-bucket/               # only needs s3:PutObject
```

Three problems: (1) `permissions: write-all` grants GITHUB_TOKEN write access to issues, PRs, packages, and deployments when only `contents: read` is needed for checkout. (2) `AWS_ACCESS_KEY_ID` is a static long-lived key visible to all steps including `checkout` and `python migrate.py`, which do not need AWS access. (3) `ANTHROPIC_API_KEY` is visible to `migrate.py` which does not need it — if migrate.py is compromised, the API key leaks.

**Secure:**

```yaml
# .github/workflows/agent.yml
name: AI Agent Deploy

on:
  push:
    branches: [main]

permissions:
  contents: read                          # minimum for checkout only

jobs:
  migrate:
    runs-on: ubuntu-latest
    # No AWS or ANTHROPIC credentials here — migration uses DB_URL from Vault
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - name: Run database migration
        env:
          DB_URL: ${{ secrets.DB_URL }}   # only what this step needs
        run: python migrate.py

  summarize-and-upload:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write                     # OIDC for AWS — no static key
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@010d0da01d0b5a38af31e9c3470dbfdabdecca3a  # v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsS3PutOnly
          aws-region: us-east-1
          # TTL: 15 minutes, scoped to one bucket by the IAM policy
      - name: Run AI summarization
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # scoped to this step only
        run: python summarize.py
      - name: Upload report
        run: aws s3 cp report.txt s3://my-bucket/              # OIDC role has only s3:PutObject
```

### Terraform — Agent IAM Role

**Vulnerable:**

```hcl
# infra/agent-role.tf
resource "aws_iam_role" "agent" {
  name = "ai-agent-role"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "agent_admin" {
  role       = aws_iam_role.agent.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # full account control
}
```

The agent's task is to read objects from one S3 bucket and write summaries to DynamoDB. `AdministratorAccess` grants IAM management, EC2 control, RDS access, and every other service. A compromised agent process can create new IAM users, exfiltrate all S3 data in the account, and destroy infrastructure.

**Secure:**

```hcl
# infra/agent-role.tf
resource "aws_iam_role" "agent" {
  name = "ai-agent-summarizer"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  # Permission boundary caps escalation even if inline policy is misconfigured later
  permissions_boundary = aws_iam_policy.agent_boundary.arn
}

resource "aws_iam_policy" "agent_summarizer" {
  name = "AgentSummarizerPolicy"
  policy = jsonencode({
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::my-input-bucket/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/SummaryTable"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agent_summarizer" {
  role       = aws_iam_role.agent.name
  policy_arn = aws_iam_policy.agent_summarizer.arn
}
```

### MCP / Agent Framework Config

**Vulnerable:**

```json
// .mcp.json — static keys hardcoded as env vars, no scope restriction
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXX",
        "AWS_ACCESS_KEY_ID": "AKIAXXXXXXXXXXXXXXXX",
        "AWS_SECRET_ACCESS_KEY": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      }
    }
  }
}
```

Two compounding problems: (1) static long-lived keys committed to the repo (also a `sast-hardcodedsecrets` finding — cross-link, do not duplicate). (2) The filesystem MCP server is granted root (`/`) access with full-account AWS credentials in its environment — any tool call by the MCP server inherits both.

**Secure:**

```json
// .mcp.json — no static keys; agent reads from Vault or environment
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/agent/workspace"],
      "env": {}
    }
  }
}
```

AWS credentials are injected at runtime via instance profile (EC2), Workload Identity (GKE), or OIDC federation — never static, never in config files.

### Kubernetes — Agent Workload

**Vulnerable:**

```yaml
# k8s/agent-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-agent
spec:
  template:
    spec:
      serviceAccountName: ai-agent-sa
      containers:
        - name: agent
          image: myco/ai-agent:latest
          securityContext:
            privileged: true                       # kernel-level access
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock      # Docker-in-Docker escape vector
          env:
            - name: OPENAI_API_KEY
              value: "sk-XXXXXXXXXXXXXXXXXXXXXXXXXX"  # static key in manifest
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ai-agent-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/AdminRole
```

Four findings: `privileged: true`, Docker socket mount (container escape), static `OPENAI_API_KEY` in manifest (baked into `kubectl describe` output), and the SA annotated to an `AdminRole`.

**Secure:**

```yaml
# k8s/agent-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-agent
spec:
  template:
    spec:
      serviceAccountName: ai-agent-sa
      automountServiceAccountToken: true   # needed for IRSA
      containers:
        - name: agent
          image: myco/ai-agent@sha256:ab12cd34ef56...
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          env:
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:             # from K8s Secret, not hardcoded
                  name: ai-agent-secrets
                  key: openai-api-key
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ai-agent-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/AgentS3ReadOnly
    # Role has: s3:GetObject on arn:aws:s3:::input-bucket/* only
```

---

## Execution

### Phase 1: Recon — Inventory Agent Identity Surfaces

Enumerate every file that could define or inject a programmatic credential for an agent or automated pipeline. Run these `Glob` patterns in parallel:

- `**/.mcp.json`, `**/mcp.json`, `**/.mcp/*.json`, `**/mcp-config*.json`, `**/mcp-servers*.json`
- `**/.github/workflows/*.yml`, `**/.github/workflows/*.yaml`
- `**/.gitlab-ci.yml`, `**/.circleci/config.yml`, `**/Jenkinsfile*`, `**/azure-pipelines.yml`, `**/.travis.yml`, `**/circle.yml`
- `**/*.tf`, `**/*.tfvars` (IAM policy documents, role definitions)
- `**/cdk/**/*.ts`, `**/cdk/**/*.py`, `**/pulumi/**/*.ts`, `**/pulumi/**/*.py` (CDK/Pulumi IAM constructs)
- `**/k8s/**/*.yml`, `**/k8s/**/*.yaml`, `**/kubernetes/**/*.yml`, `**/manifests/**/*.yml`, `**/helm/**/templates/*.yml`
- `**/docker-compose*.yml`, `**/compose*.yml`
- `**/.env`, `**/.env.*`, `**/agent.env`, `**/agent-config.json`, `**/agent.yaml`, `**/agent.yml`
- `**/iam-policy*.json`, `**/policy*.json`, `**/trust-policy*.json`

For each hit, note: path, artifact type (CI workflow / Terraform / K8s manifest / MCP config / etc.), and a one-line description of what agent/pipeline it configures. Cross-reference `sast/architecture.md` to confirm which files are active production configuration vs. examples or stale experiments.

Write the inventory to `sast/agentidentity-recon.md` as a flat list grouped by artifact type, one row per file. If **no** files match any pattern, write both result files with `findings: []`, note that no agent identity surfaces were found, clean up, and stop.

### Phase 2: Verify — Least-Privilege Analysis (Batched)

Split the recon inventory into batches of **3 files each**. Launch one subagent per batch, in parallel. Give each subagent this instruction:

> Read your assigned files and `sast/architecture.md`. For each file, apply the identity rule-set below. For every candidate, reason step by step: (1) what is this agent's documented task? (2) what permissions does this credential/role grant? (3) does the scope exceed the task? (4) are there boundary controls (SCP, permission boundary, OIDC TTL, scoped resource ARN) that constrain the excess? Write all findings and FP decisions to `sast/agentidentity-batch-<n>.md`.

**Identity rule-set for subagents:**

**GitHub Actions rule-set:**

- `permissions: write-all` — always a candidate. Is write access to packages, deployments, security events, or repository secrets required by any step in the workflow? If the workflow only does checkout + test, this is over-privileged.
- Missing top-level `permissions:` block — GitHub defaults to the repository's base permission, which may be `write` on all resources. Treat as implicit over-permission candidate; verify against the repo's default permission setting if visible.
- `secrets.*` injected at `jobs.<job>.env` level rather than `jobs.<job>.steps[*].env` — the secret is visible to all steps including third-party actions. Check: does every step in the job actually need it?
- `permissions: {}` — empty block means "inherit defaults," which may be broad. Check what the steps actually do.
- Static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / vendor API keys in `env:` at workflow or job level rather than OIDC. Is there an `id-token: write` + `aws-actions/configure-aws-credentials` with a role ARN? If yes, the static key may be redundant — flag for cleanup. If no, flag as `high` (static credential).

**Terraform / CDK / Pulumi IAM rule-set:**

- `"Action": "*"` with `"Resource": "*"` — always `high`. Check: (a) is there a `PermissionsBoundary` resource on the same role? If yes, downgrade to `medium` with boundary noted. (b) Is there an SCP visible in the Terraform code that denies privileged actions? Note if present.
- `"Action": "*"` with a specific resource ARN — candidate. Is the action list really "all actions" on one resource, or is the role a data-plane role that only needs a handful of actions? `s3:*` on `arn:aws:s3:::my-bucket/*` may be fine for a backup agent but is over-privileged for a read-only summarizer.
- `"Resource": "*"` with a scoped action list — candidate. `["s3:GetObject", "s3:ListBucket"]` on `"Resource": "*"` is over-privileged if the agent only accesses one specific bucket. Flag as `medium` — scope the resource ARN.
- `iam:PassRole` without a condition — `Condition: { StringEquals: { "iam:PassedToService": "lambda.amazonaws.com" } }` is acceptable; no condition means the agent can pass any role to any service. `high`.
- `sts:AssumeRole` without a condition on the target role — similar to PassRole. `high`.
- `AdministratorAccess` managed policy attached to an agent role — `critical`. Document what the agent's task is (from adjacent Terraform comments, variable names, module outputs) and confirm the task cannot be done with a scoped policy.
- `aws_iam_access_key` resource — static key creation. Flag as `high` unless accompanied by a comment citing a documented exception (e.g. "third-party service that does not support OIDC").

**Kubernetes rule-set:**

- `privileged: true` in agent container `securityContext` — `high` unless the agent's documented task is container management (e.g. it IS the Docker daemon). Reason about the task.
- `/var/run/docker.sock` hostPath mount — `high`. Effective host root. Same task reasoning.
- `eks.amazonaws.com/role-arn` annotation on a ServiceAccount — read the referenced role ARN, then find the matching Terraform/IAM policy. Apply Terraform rule-set reasoning.
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or cloud access keys in `env.value` (not `env.valueFrom.secretKeyRef`) — `high` static credential in manifest.
- `automountServiceAccountToken: true` (or missing, which defaults to true) on a pod that does not call the Kubernetes API — unnecessary SA token exposure.

**MCP / agent framework config rule-set:**

- `.mcp.json` `env:` block containing API keys or cloud credentials — `high`. Is the value a literal key (hardcoded) or a `${ENV_VAR}` reference (runtime injection)? Hardcoded: also cross-link to `sast-hardcodedsecrets`.
- MCP server `args` containing filesystem paths broader than the agent's workspace (e.g. `/`, `/home`, `/etc`) — `medium`. The MCP server can read or write outside the agent's working directory.
- Agent framework config (`agent.yaml`, `agent.json`) with `role: admin` or `permissions: all` — read the framework's permission model and assess whether the agent task requires admin.

**docker-compose rule-set:**

- `environment:` block with literal API keys or cloud credentials — `high` static credential.
- `privileged: true` on agent service — `high`.
- `/var/run/docker.sock` volume mount — `high`.
- `network_mode: host` on agent service — `medium`. The agent can bind to any host port and access internal network services.

**FP-killer checklist for every candidate:**

1. Is there OIDC dynamic credential issuance (TTL ≤ 1 h, role ARN scoped to specific resources)?
   - If YES and the credential is the only access vector: downgrade to `info` or drop entirely. Still evaluate the *role's* policy separately.
2. Is there a permission boundary or SCP visible in the repo that constrains the wildcard?
   - If YES: downgrade from `critical` → `high`, or `high` → `medium`; document the boundary ARN/policy.
3. Is the credential scoped to exactly the resources the agent's task requires?
   - If YES (specific ARNs, no wildcard resources): not a finding even if the action list is somewhat broad.
4. Is the file in `examples/`, `docs/`, `test/fixtures/`, or `demo/`?
   - If YES: downgrade to `info`. Note it is example material.
5. Is the static credential reference `${SECRET_NAME}` rather than a literal value?
   - If YES: it is a runtime-injected reference, not a hardcoded secret. The *scope* question remains, but cross-link to `sast-hardcodedsecrets` only if the literal value is actually present.

**Setting severity, exploitability, and confidence:**

| Condition | Severity | Exploitability | Confidence |
|---|---|---|---|
| `AdministratorAccess` or `Action: *` / `Resource: *` on agent role, static long-lived key, no boundary | critical | reachable | high |
| `iam:PassRole` without condition, or `sts:AssumeRole` without target condition | critical | reachable | high |
| `permissions: write-all` in CI + static cloud key at job level | high | reachable | high |
| `Action: *` / `Resource: *` with a permission boundary in place | high | conditional | medium |
| Broad action list (`s3:*`) on `Resource: *`, no boundary, OIDC issuance | medium | conditional | medium |
| Scoped action list on `Resource: *` (wrong resource scope, not action scope) | medium | conditional | high |
| Static API key at job level where step-level injection would suffice | high | conditional | high |
| Privileged container / Docker socket mount | high | reachable | high |
| `network_mode: host` on agent container | medium | conditional | medium |
| Broad resource path in MCP filesystem server | medium | conditional | medium |
| OIDC + scoped role, minor action excess | low | unreachable | low |
| Example file with hardcoded credentials | info | unreachable | high |

**chain_id values:**

- Findings that combine a static credential in a config file with over-permissioned IAM/CI scope: `chain_id: "identity-secret-chain"` (chains with `sast-hardcodedsecrets` findings on the same credential).
- Findings where an over-permissioned IAM policy (Terraform/CDK) is the root cause of the CI or agent credential's scope: `chain_id: "identity-iac-chain"` (chains with `sast-iac` findings on the same role resource).

Each batch subagent writes its findings to `sast/agentidentity-batch-<n>.md` and must not read files outside its assigned slice.

### Phase 3: Merge — Consolidate Batch Results

Read every `sast/agentidentity-batch-*.md`. Merge into `sast/agentidentity-results.md` using the template below. De-duplicate: if the same pattern fires in multiple nearly-identical CI workflow files (e.g. three workflows all use `permissions: write-all`), collapse into one finding listing all affected paths.

Also emit `sast/agentidentity-results.json` per the canonical schema.

After writing both result files, delete `sast/agentidentity-recon.md` and all `sast/agentidentity-batch-*.md` files.

---

## Findings

Write `sast/agentidentity-results.md` using this template:

```markdown
# Over-Privileged Agent Identity — Findings

_Scanned N credential surfaces across GitHub Actions, Terraform, Kubernetes, MCP config, and docker-compose._

## Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |

## Findings

### [AGENTID-001] <short title>

- **Severity**: critical | high | medium | low | info
- **File**: `path/to/file.yml:14`
- **Category**: GitHub Actions / IAM / Kubernetes / MCP config
- **Chain**: identity-secret-chain | identity-iac-chain | (none)

**Offending snippet**

```yaml
permissions: write-all
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
```

**Agent task vs. credential scope**

The workflow `agent.yml` runs database migrations and an AI summarization step. The task requires: (1) `contents: read` for checkout, (2) `s3:PutObject` on one bucket for upload, (3) `ANTHROPIC_API_KEY` for the summarization step. `permissions: write-all` grants write access to packages, deployments, security events, issues, pull-requests, and repository secrets — none of which are exercised by any step. The static `AWS_ACCESS_KEY_ID` is visible to all five steps in the job; only the `aws s3 cp` step needs AWS access.

**Why it matters**

If any step is compromised (supply-chain attack on a dependency, script injection via a GitHub expression, or a vulnerable third-party action), the attacker gains: (a) a GITHUB_TOKEN with write access to packages and deployments, enabling tampering with published artifacts; (b) a static AWS key with the permissions of the attached IAM role, valid until manual rotation.

**Boundary controls present**

None identified. No SCP or permission boundary visible in the repository.

**Fix**

1. Replace `permissions: write-all` with a minimum set at the workflow level and elevate per-job only where required:

```yaml
permissions:
  contents: read

jobs:
  run-agent:
    permissions:
      contents: read
      id-token: write           # for OIDC AWS authentication
```

2. Replace static `AWS_ACCESS_KEY_ID` with OIDC:

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@010d0da01d0b5a38af31e9c3470dbfdabdecca3a  # v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActionsS3PutOnly
    aws-region: us-east-1
```

3. Scope `ANTHROPIC_API_KEY` to the specific step that uses it, not the job-level `env:` block.

**Notes**

FP check: confirmed production workflow (not example). No OIDC configuration found. No permission boundary on the referenced IAM role in `infra/roles.tf`. Cross-link: if a literal key value is present in a `.env` or CI config file, see also `sast-hardcodedsecrets` finding HSEC-003.

---

### [AGENTID-002] ...
```

Also write `sast/agentidentity-results.json`:

```json
{
  "findings": [
    {
      "id": "agentidentity-001",
      "skill": "sast-agentidentity",
      "severity": "high",
      "title": "CI workflow uses write-all permissions with static AWS key at job scope",
      "description": ".github/workflows/agent.yml grants permissions: write-all to the GITHUB_TOKEN and injects AWS_ACCESS_KEY_ID as a static long-lived credential at job level, visible to all 5 steps. The workflow's task (DB migration + AI summarization + S3 upload) requires only contents: read, OIDC-issued S3 role, and ANTHROPIC_API_KEY scoped to the summarization step. A compromised step or third-party action gains write access to packages, deployments, and a long-lived AWS key.",
      "location": { "file": ".github/workflows/agent.yml", "line": 8, "column": 1 },
      "remediation": "Replace permissions: write-all with a scoped per-job permissions block. Replace static AWS credentials with GitHub Actions OIDC (id-token: write + aws-actions/configure-aws-credentials). Scope ANTHROPIC_API_KEY to the step env: block of the summarization step only.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "identity-secret-chain"
    }
  ]
}
```

If no findings, still write both files with `"findings": []` and an explanatory note in the markdown (`_No over-privileged agent identities detected across N surfaces scanned. Recommend running dedicated IAM scanners (tfsec, checkov, semgrep IAM ruleset) in CI for broader coverage._`).

---

## Important Reminders

- The central question is always **task vs. scope** — a wildcard alone is not a finding if a permission boundary or SCP constrains it, and a long action list is not a finding if the agent's task genuinely requires each action. State your reasoning explicitly.
- Short-lived OIDC credentials (TTL ≤ 1 h) eliminate the static credential risk but do not eliminate the role's scope risk — evaluate the IAM policy regardless.
- Severity is driven by blast radius: `AdministratorAccess` = account takeover potential = `critical`. `Action: *` on `Resource: *` with no boundary = same. Broad scope with a strong boundary = one level lower.
- Cross-link to `sast-hardcodedsecrets` if a literal key value appears in the same file — link the finding ID, do not re-report the secret value.
- Cross-link to `sast-iac` if the over-permissioned IAM role is defined in Terraform/CDK in the same repo — use `chain_id: "identity-iac-chain"`.
- Dev-only config (docker-compose.dev.yml, k8s/dev/, .env.local) found over-privileged: downgrade severity by one level and mark `environment: dev`.
- Always check whether the agent's code or documentation is present in the repo. An agent documented as "reads from S3 bucket A and writes to DynamoDB table B" should have a role that reflects exactly that — nothing more.
