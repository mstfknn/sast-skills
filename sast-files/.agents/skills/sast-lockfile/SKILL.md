---
name: sast-lockfile
description: >-
  Survey a codebase for missing, incomplete, or bypassed lockfile integrity
  controls — the mechanism that guarantees each install gets byte-identical
  packages pinned to a verified content hash. Applies a three-phase approach:
  recon (enumerate all ecosystem manifests, lockfiles, Dockerfiles, and CI
  install steps), batched verify (parallel subagents, 3 artefacts each, confirm
  whether a pinned hash or digest is provably absent), and merge (consolidate
  into sast/lockfile-results.md and sast/lockfile-results.json). Maps to
  OWASP Web25 A03 · CWE-494 (Download of Code Without Integrity Check).
  Use when asked to audit supply-chain hygiene, check for missing lockfiles,
  review dependency pinning, or scan for unverified installs.
version: 0.1.0
---

# Lockfile Integrity / Dependency Pinning Absent

**Prerequisites**: `sast/architecture.md` must exist (run `sast-analysis` first).

You are performing a supply-chain integrity review of a codebase. The goal is to enumerate every point in the repository where code is downloaded and installed at build, CI, or runtime, and then verify that each download is protected by a content-addressed hash or version digest that the package manager checks before executing the payload. A missing or bypassed lockfile hash means an attacker who compromises the registry, CDN, or a git host can silently substitute malicious code that runs the moment someone does `npm install` or `pip install`.

This skill is a **control-presence check**, not a CVE-lookup. You are not asking "is this package known-vulnerable?" — that is `sast-deps`. You are asking: "if the registry served a tampered tarball right now, would the install tool detect it and refuse?" If the answer is no, that is a finding here.

## What Counts as a Lockfile Integrity Failure

A finding exists when **all three** of the following hold:

1. **There is an install step that fetches external code.** An `npm install`, `pip install`, `gem install`, `go get`, `docker pull`, `RUN curl | sh`, GitHub Actions `uses:` step, or similar.
2. **The fetched code is not pinned to a content-addressed digest.** No `sha256:` hash in the lockfile entry, no `--hash=sha256:…` in the pip command, no `@sha256:` in a Docker `FROM`, no 40-character commit SHA in a GitHub Actions `uses:` line.
3. **The integrity check is not enforced elsewhere.** The install command does not pass `--require-hashes` (pip), `npm ci` is not used instead of `npm install --no-package-lock`, the lockfile is not committed, etc.

### What Lockfile Failures ARE

- A `requirements.txt` that lists `requests==2.31.0` without any `--hash=sha256:…` suffix, and no `uv.lock` / `poetry.lock` / `Pipfile.lock` is present in the repo.
- A `package.json` present but `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are all absent — or any of these appear in `.gitignore`.
- A CI step that runs `npm install` instead of `npm ci` (which enforces the lockfile and fails if it is out of date or absent).
- A `Dockerfile` with `RUN pip install -r requirements.txt` but no lockfile baked in and no `--require-hashes` flag.
- A `Dockerfile` with `RUN curl https://raw.githubusercontent.com/owner/repo/main/install.sh | bash` — fetches a mutable, unsigned script.
- A `Dockerfile` with `RUN npm install` (not `npm ci`) inside the image build layer.
- A GitHub Actions workflow step: `uses: actions/checkout@main` or `uses: owner/repo@v1` — both are mutable refs that can be force-pushed; only a full 40-character SHA (`uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`) is immutable.
- A `Gemfile` committed but `Gemfile.lock` absent or gitignored.
- `go.mod` present but `go.sum` absent or gitignored.
- `gem install mygem --git https://github.com/owner/mygem` without `:ref` pointing to a full commit SHA.
- `pip install git+https://github.com/owner/lib@main` — mutable branch ref.
- A lockfile present but with all `integrity` fields stripped or set to empty string.

### What Lockfile Failures are NOT

- A lockfile that is committed, has `integrity` / `sha256` hashes for every entry, and the CI uses `npm ci` / `pip install --require-hashes`. This is the desired state — no finding.
- A `uv.lock` or `poetry.lock` committed to the repo with hash entries — even if the `requirements.txt` is a plain pinned list, the lock file provides the hash verification layer. Not a finding.
- A monorepo workspace where the root-level lockfile covers all workspaces and the individual workspace `package.json` files have no separate lockfile by design.
- Dev-only tooling (`eslint`, `prettier`, `pytest`, etc.) where: (a) the package is not included in the production container/artefact, AND (b) the runtime artefact itself is independently signed and hash-verified (e.g. a pre-built binary downloaded separately with a checksum). Lower to info / observation if you cannot confirm dev-only exclusion from prod.
- `go get` during development (not in CI or Dockerfile) — the `go.sum` mechanism provides integrity when the lockfile is committed.

### Severity Calibration

| Condition | Severity |
|---|---|
| Lockfile absent or gitignored (no hash verification at all) | **high** |
| Lockfile present but `integrity` fields stripped / empty | **high** |
| CI uses `npm install` instead of `npm ci` (lockfile exists but not enforced) | **medium** |
| `pip install` without `--require-hashes` (lockfile covers some pkgs, not all) | **medium** |
| GitHub Actions `uses:` on a mutable tag (`@v3`, `@main`) | **medium** |
| `RUN curl … | sh` or `RUN wget … | bash` in a Dockerfile (no checksum) | **high** |
| Install from mutable git branch ref (not a SHA) | **high** |
| Missing lockfile for a package that has a `postinstall`/`prepare` script with broad FS/network access | **critical** — arbitrary code runs at install time |
| Dev-only tooling, not included in prod artefact (best-effort assessment) | **low** |

### Patterns That Mitigate or Eliminate Findings

When reading the project, note whether any of the following exist. Their presence may lower severity or eliminate a finding:

- **`npm ci`** in CI and Dockerfile (not `npm install`) — enforces `package-lock.json`.
- **`pip install --require-hashes -r requirements.txt`** or **`uv sync --frozen`** — enforces hash verification.
- **`cargo install --locked`** — enforces `Cargo.lock`.
- **GitHub Actions pinned to full 40-char SHA** — immutable.
- **`FROM image@sha256:<digest>`** in Dockerfile — immutable base image.
- **`go.sum` committed and `GONOSUMCHECK` not set** — Go's module proxy enforces hash verification.
- **Sigstore / cosign signatures** on published images.
- **Dependabot or Renovate** configured — indicates automated lockfile maintenance.
- **`prepublishOnly` / `preinstall` scripts absent** — reduces blast radius if the lockfile is missing.

## Vulnerable vs. Secure Examples

Below are concrete snippets that illustrate the boundary.

### Python — no hash verification

**Vulnerable (`requirements.txt`, no lockfile):**

```
requests==2.31.0
boto3==1.34.0
flask==3.0.2
```

No `--hash=sha256:…` suffix on any line. No `uv.lock`, `poetry.lock`, or `Pipfile.lock` in the repo. Running `pip install -r requirements.txt` fetches packages from PyPI without verifying content hashes — a compromised CDN mirror or a registry account takeover can serve a different tarball for the same version string.

**Secure (hash-pinned `requirements.txt`):**

```
requests==2.31.0 \
    --hash=sha256:58cd2187423d77b8d5e87d687a480f6d6e3c2d680ab60359069089b1b6d053f6 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
boto3==1.34.0 \
    --hash=sha256:...
```

Or, equivalently, a committed `uv.lock` / `poetry.lock` / `Pipfile.lock` that contains hash entries — `pip install --require-hashes -r requirements.txt` (or the lock tool's equivalent install command) will reject any tarball whose hash does not match.

---

### Node — lockfile absent or gitignored

**Vulnerable:**

```
# .gitignore
package-lock.json
node_modules/
```

```json
// package.json (no sibling lockfile in the repo)
{
  "dependencies": {
    "express": "^4.19.2",
    "axios": "^1.6.8"
  }
}
```

Each `npm install` resolves the `^` range fresh against the registry. No hash verification — the resolved version and tarball content can differ between runs or between developers.

**Secure:**

```
# .gitignore
node_modules/
# package-lock.json is NOT gitignored — it is committed
```

CI step:
```yaml
- run: npm ci    # enforces package-lock.json; fails if lockfile is missing or out of date
```

---

### Node — `npm install --no-package-lock`

**Vulnerable:**

```yaml
# .github/workflows/build.yml
- run: npm install --no-package-lock
```

The `--no-package-lock` flag explicitly prevents lockfile generation and hash enforcement — even if a `package-lock.json` is committed, this flag bypasses it.

**Secure:**

```yaml
- run: npm ci
```

---

### Docker — unverified install in image layer

**Vulnerable:**

```dockerfile
FROM python:3.11-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
```

No `--require-hashes`, no pinned base image digest, no lockfile baked in. The image build is non-reproducible and does not verify package content.

**Secure:**

```dockerfile
FROM python:3.11-slim@sha256:1234abcd...
COPY requirements.txt .
# requirements.txt must use --hash= entries; pip enforces them automatically
RUN pip install --require-hashes --no-deps -r requirements.txt
```

Or using `uv`:

```dockerfile
FROM python:3.11-slim@sha256:1234abcd...
COPY uv.lock pyproject.toml .
RUN pip install uv && uv sync --frozen --no-dev
```

---

### Docker — curl-piped install script

**Vulnerable:**

```dockerfile
RUN curl -sSL https://raw.githubusercontent.com/owner/repo/main/install.sh | bash
```

Downloads and executes an unsigned, mutable script over HTTPS. The URL resolves to whatever is on `main` at build time — not a pinned commit, not a signed release.

**Secure (if the script is truly needed):**

```dockerfile
# Pin to a specific commit SHA and verify checksum
RUN curl -sSL https://raw.githubusercontent.com/owner/repo/abc123def456.../install.sh \
      -o install.sh \
    && echo "sha256:expectedhash  install.sh" | sha256sum --check \
    && bash install.sh \
    && rm install.sh
```

Prefer vendoring the script into the repository instead.

---

### GitHub Actions — mutable `uses:` ref

**Vulnerable:**

```yaml
steps:
  - uses: actions/checkout@v4          # mutable tag — can be force-pushed
  - uses: actions/setup-node@main      # mutable branch
  - uses: owner/custom-action@v1       # mutable tag
```

A compromised `actions/checkout` release or a malicious force-push to `@v4` would immediately affect every workflow that references it.

**Secure (full SHA pinning):**

```yaml
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683      # v4.2.2
  - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af    # v4.1.0
  - uses: owner/custom-action@a1b2c3d4e5f6...                             # vX.Y.Z
```

Pin to the SHA of the tagged commit, and document the human-readable version in a comment.

---

### Go — `go.sum` absent

**Vulnerable:**

```
# .gitignore
go.sum
```

Go's module system uses `go.sum` as its content-address database. Gitignoring it means every `go build` or `go mod download` fetches modules without verifiable hashes — `GONOSUMCHECK` or `GONOSUMDB` settings may further disable the checksum database.

**Secure:**

```
# .gitignore
# go.sum is NOT listed here — it is committed
```

CI:
```yaml
- run: go mod verify    # verifies all modules in go.sum match their hashes
- run: go build ./...
```

---

### Ruby — `Gemfile.lock` absent

**Vulnerable:**

```
# .gitignore
Gemfile.lock
```

`bundle install` without a lockfile resolves gem versions fresh, with no hash pinning. Bundler does support `--frozen` (fail if lockfile is missing or outdated) but that has no effect if the lockfile is not committed.

**Secure:**

```
# .gitignore
# Gemfile.lock is NOT listed — it is committed
```

CI:
```yaml
- run: bundle install --frozen    # fails if Gemfile.lock is missing or changed
```

## Execution

### Phase 1: Recon — Enumerate Install Points

Read `sast/architecture.md` for the tech-stack context, then sweep the repository for every install point and every lockfile candidate. Cast a wide net — polyglot repositories often have more than one ecosystem.

**Artefacts to look for and what to record for each:**

| Ecosystem / Artefact | Look for | Flag when |
|---|---|---|
| **Python / pip** | `requirements.txt`, `requirements-*.txt`, `constraints.txt`, `setup.py`, `setup.cfg`, `pyproject.toml` (`[project.dependencies]`, `[tool.poetry.dependencies]`), `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock` | `requirements*.txt` present but none of `uv.lock` / `poetry.lock` / `Pipfile.lock` found; or lockfile absent; or `requirements.txt` entries lack `--hash=sha256:…` suffix AND no lock tool is used |
| **Python / install commands** | `pip install <url>`, `pip install git+https://…`, `pip install -r …` without `--require-hashes`; `uv add` / `uv sync` without `--frozen` in CI | Mutable URL or branch ref; missing `--require-hashes` when lockfile absent |
| **Node / npm** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`, workspace `package.json` | `package.json` present but no lockfile; lockfile in `.gitignore`; CI runs `npm install` instead of `npm ci`; `npm install --no-package-lock` |
| **Node / `integrity` fields** | Entries in `package-lock.json` with `"integrity": ""` or absent | `integrity` stripped from any entry |
| **Docker** | `Dockerfile`, `Containerfile`, `*.Dockerfile`, `docker-compose.yml` `FROM` lines; `RUN pip install`, `RUN npm install`, `RUN gem install`, `RUN curl … \| sh`, `RUN wget … \| bash` | No `@sha256:` on `FROM`; `pip install` without `--require-hashes`; `npm install` instead of `npm ci`; curl/wget piped to shell; unverified script download |
| **GitHub Actions** | `.github/workflows/*.yml`, `.github/workflows/*.yaml` — all `uses:` lines | `uses: owner/action@tag-or-branch` instead of full 40-char SHA |
| **Ruby** | `Gemfile`, `Gemfile.lock`, `*.gemspec` | `Gemfile` present but `Gemfile.lock` absent or gitignored; `gem install … --git …` without `:ref` SHA |
| **Go** | `go.mod`, `go.sum`, `vendor/modules.txt` | `go.mod` present but `go.sum` absent or gitignored; `GONOSUMCHECK` / `GONOSUMDB` / `GOFLAGS=-mod=mod` set in CI |
| **Rust** | `Cargo.toml`, `Cargo.lock` | For application crates: `Cargo.lock` absent or gitignored; `cargo install` without `--locked` in CI |
| **Java / JVM** | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | `gradle.lockfile` absent when `dependencyLocking {}` not enabled; Maven without checksum enforcement |
| **PHP** | `composer.json`, `composer.lock` | `composer.lock` absent or gitignored; CI runs `composer install` without `--no-dev --no-scripts` (scripts run at install time) |
| **.NET** | `*.csproj`, `packages.lock.json`, `NuGet.Config` | `packages.lock.json` absent; `RestoreLockedMode` not set in `NuGet.Config` |
| **CI / CD** | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `Makefile`, `scripts/*.sh` | Any install command that fetches from a mutable URL without checksum verification |

**Also check:**

- `.gitignore` for any lockfile being excluded from version control.
- `Makefile`, `scripts/`, `bin/` shell scripts for ad-hoc install commands.
- `Dockerfile` `COPY` sequences — does the image bake in a lockfile before running the install command?
- Presence (or absence) of `dependabot.yml` / `renovate.json` — indicates whether lockfile updates are automated.
- CI artifact caching configuration — caches keyed on a lockfile hash are evidence the lockfile is in use.

**Output of Phase 1**: write `sast/lockfile-recon.md`. For each candidate install point or manifest, record:
- File path and relevant line numbers.
- Ecosystem.
- Whether a corresponding lockfile exists, is committed, and contains hash entries.
- Preliminary verdict: `CANDIDATE_FINDING`, `SECURE`, or `NEEDS_VERIFY`.

### Phase 2: Verify — Confirm Missing Hash Enforcement (Batched)

Group the candidates from `sast/lockfile-recon.md` into batches of **3 artefacts per subagent** and run them in parallel. Each subagent gets:

- The specific files for its batch (manifest, lockfile if present, CI config excerpt, `.gitignore` excerpt).
- A copy of `sast/architecture.md` for context on which environments are production vs. dev-only.
- Instructions to produce a per-batch file `sast/lockfile-batch-<N>.md` with its raw findings.

For each candidate install point, the subagent answers:

**Core verify question**: Is there an install command, manifest, or CI step that fetches a dependency without a pinned content hash or version digest — such that a registry or CDN compromise could silently substitute a different payload?

**False-positive killers** (check each before marking a finding):

1. **Lockfile committed with hash entries?** Look for `package-lock.json` with `"integrity": "sha512-…"` on every entry, `poetry.lock` with `content-hash` and per-package `hash = "sha256:…"` lines, `uv.lock` with `wheels` hash arrays, `Pipfile.lock` with `hash` keys, `Cargo.lock` with `checksum` fields, `go.sum` with `h1:` hash lines. If all entries for all packages have a hash, and the CI tool enforces the lockfile, mark SECURE.
2. **`npm ci` used in CI and Dockerfile?** `npm ci` requires `package-lock.json`, fails if it is missing or out of date, and verifies the `integrity` field for every package. If `npm ci` is used consistently (not just in some steps), the node install is SECURE even if `npm install` also exists in local-dev documentation.
3. **`pip install --require-hashes`?** Pip enforces hash checking when this flag is present and every package in the requirements file has at least one `--hash=` suffix. If it is present, mark SECURE.
4. **`uv sync --frozen` / `uv run --frozen` in CI?** `uv` with `--frozen` enforces the `uv.lock` and refuses to install if the lock is stale. SECURE.
5. **GitHub Actions SHA vs. tag?** Count the characters after `@` in each `uses:` line. A 40-character hex string is a full commit SHA (immutable). A tag like `v4`, `v4.2`, or `main` is mutable. Mark mutable refs as findings.
6. **Docker `FROM` with `@sha256:`?** The digest after `@sha256:` is content-addressed; the tag alone is mutable. Note the full `FROM` line; if the digest is present, the base image is SECURE.
7. **`curl | sh` with no checksum?** There is no acceptable version of this unless the script is downloaded to a file, a checksum is verified against a published value, and then the file is executed. A one-liner pipe is always a finding regardless of whether the URL uses HTTPS.
8. **Mutable git ref in install URL?** `pip install git+https://github.com/owner/lib@main` or `gem install … --git https://github.com/…` without `:ref:` set to a full commit SHA. Only a full 40-character SHA in the ref is SECURE.
9. **Lockfile gitignored?** Even if the lockfile exists locally, excluding it from version control means CI runs without it. Check `.gitignore` explicitly. A gitignored lockfile is NOT a mitigation.
10. **Dev-only scope?** If a package is declared only in `devDependencies`, not shipped in the production container, and the CI job that installs dev dependencies is isolated from the production build, you may lower severity to `low` or `info`. Document the reasoning. When in doubt, use the higher severity — static analysis cannot always confirm prod/dev isolation.

For each confirmed finding, record:

- **File path and line number** of the manifest, lockfile absence, install command, or CI step.
- **Ecosystem**.
- **Specific failure**: missing lockfile / no hash entries / mutable ref / curl-pipe / `npm install` instead of `npm ci` / gitignored lockfile.
- **Severity** (per calibration table above).
- **Exploitability**: always `conditional` — the attack requires the registry, CDN, git host, or Actions runner supply chain to be compromised. The risk is real and historically exploited (npm registry hijacks, PyPI takeovers, GitHub Actions supply-chain attacks), but it is not direct code execution from untrusted user input.
- **Confidence**: `high` when the lockfile is provably absent from the repository (confirmed by `.gitignore` entry or no file at the expected path); `medium` when the lockfile exists but hash entries are partially absent or the CI step is ambiguous; `low` when the evidence is indirect (e.g., the lockfile exists but we cannot confirm whether CI uses `npm ci`).
- **chain_id**: `"supply-chain-risk"` — this finding chains with `sast-deps` findings because a lockfile without hash verification also means known-CVE detection is unreliable (you cannot confirm which version actually installed).

Batch files use this structure:

```markdown
## Batch N — Files: <list>

### Candidate: <file>:<line> (<ecosystem>)

**Verdict**: FINDING | FALSE_POSITIVE | NEEDS_MORE_INFO

**Evidence**: <quoted line or snippet>

**Failure**: <specific failure type>

**Severity**: critical | high | medium | low | info

**Exploitability**: conditional

**Confidence**: high | medium | low

**Notes**: <FP-killer analysis — which checks were applied and why each passed or failed>
```

### Phase 3: Merge — Consolidate Batch Results

After all batch subagents finish, read every `sast/lockfile-batch-*.md` and `sast/lockfile-recon.md`, de-duplicate (the same `.gitignore` excluding `package-lock.json` produces one finding, not one per workflow that calls `npm install`), and consolidate into the final outputs:

- `sast/lockfile-results.md` — human-readable report following the Findings template below, grouped by severity then by ecosystem.
- `sast/lockfile-results.json` — canonical JSON following the schema in the top-level `CLAUDE.md`.

After writing both files, **delete the intermediate `sast/lockfile-batch-*.md` and `sast/lockfile-recon.md`** so only the canonical outputs remain.

## Findings

Use this template in `sast/lockfile-results.md`. One entry per distinct install point or lockfile absence.

```markdown
### [SEVERITY] <ecosystem> — <short title>

- **Failure**: missing lockfile | lockfile gitignored | no hash entries | mutable git ref | curl-pipe | npm install instead of npm ci | missing --require-hashes | mutable Actions ref | unverified base image
- **File**: `path/to/file` (line N)
- **Evidence**: quote the offending line or manifest snippet
- **Exploitability**: conditional — requires compromise of the registry, CDN, or supply chain
- **Confidence**: high | medium | low
- **chain_id**: supply-chain-risk
- **Impact**: Describe what an attacker can do if they compromise the supply chain at this point (e.g. execute arbitrary code at install time via a postinstall script, inject malicious code into the production image at build time, etc.)
- **Remediation**:
  1. Specific corrective action.
  2. Additional hardening step.
  3. CI gate to enforce going forward.
- **References**:
  - https://cwe.mitre.org/data/definitions/494.html
  - Relevant ecosystem docs (pip hash-checking mode, npm ci, actions/checkout SHA pinning guide, etc.)
```

Conclude `sast/lockfile-results.md` with a **Summary** section:

1. Count by severity (critical / high / medium / low / info).
2. Count by ecosystem.
3. Recommended immediate actions, ordered by risk.
4. Observation about the control environment: presence/absence of `dependabot.yml` / `renovate.json`, whether any CI step already uses `npm ci`, whether any lockfile is committed with hashes.
5. Note the chain with `sast-deps`: where lockfile integrity is absent, CVE detection is also weakened — the installed version cannot be confirmed from the lockfile alone.

## Canonical JSON Output

`sast/lockfile-results.json` must follow this schema exactly (one object with a `findings` array; `[]` if no findings):

```json
{
  "findings": [
    {
      "id": "lockfile-1",
      "skill": "sast-lockfile",
      "severity": "high",
      "title": "requirements.txt has no hash entries and no lockfile is committed",
      "description": "The repository's requirements.txt pins package versions by name and version string only (e.g. requests==2.31.0). No --hash=sha256: suffixes are present, and no uv.lock, poetry.lock, or Pipfile.lock exists in the repository. Running pip install -r requirements.txt fetches tarballs from PyPI without verifying their content hash. A compromised PyPI mirror, CDN, or a registry account takeover can serve a different tarball for the same version string, installing malicious code at install time.",
      "location": { "file": "requirements.txt", "line": 1, "column": 1 },
      "remediation": "Option A: switch to uv (uv lock; uv sync --frozen in CI). Option B: add --hash=sha256: suffixes to every entry in requirements.txt and use pip install --require-hashes -r requirements.txt. Commit the lockfile and fail CI if it is out of date (uv lock --check or pip-compile --generate-hashes).",
      "exploitability": "conditional",
      "confidence": "high",
      "chain_id": "supply-chain-risk"
    }
  ]
}
```

Field notes:
- `id`: `lockfile-<sequential>`, starting from 1.
- `skill`: always `"sast-lockfile"`.
- `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`.
- `exploitability`: always `"conditional"` for this skill — the attack requires a registry or CDN compromise.
- `confidence`: `"high"` when the lockfile is provably absent (gitignored or not present); `"medium"` when hash fields are partially absent or the CI command is ambiguous; `"low"` when the evidence is indirect.
- `chain_id`: `"supply-chain-risk"` for all findings — this skill's findings chain with `sast-deps` findings (CWE-494 + known-vulnerable-component risk are co-dependent when lockfile integrity is absent).
- `location.line`: point to the first relevant line in the manifest, install command, CI step, or `.gitignore` entry. Use line `1` when the finding is about a file that should exist but does not (e.g. a missing `package-lock.json`; in that case `file` should be `package.json`).

## Chain IDs Defined by This Skill

| chain_id | Meaning |
|---|---|
| `supply-chain-risk` | The install point fetches code without content-hash verification. Chains with `sast-deps` findings: a codebase without lockfile hash enforcement cannot reliably determine which package version was actually installed, weakening any CVE cross-reference. |

## Test Fixtures

Use these to confirm the skill is calibrated correctly:

**True Positive (TP) — report, high, conditional, high confidence:**

```
# requirements.txt
requests==2.31.0
urllib3==2.2.2
```

No `uv.lock`, `poetry.lock`, or `Pipfile.lock` in the repository. No `--hash=` suffixes. Finding: `high`, `conditional`, `high`.

**True Negative (TN-1) — do NOT report:**

```
# requirements.txt
requests==2.31.0 \
    --hash=sha256:58cd2187423d77b8d5e87d687a480f6d6e3c2d680ab60359069089b1b6d053f6 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
urllib3==2.2.2 \
    --hash=sha256:...
```

All entries have `--hash=` suffixes. CI uses `pip install --require-hashes -r requirements.txt`. SECURE — no finding.

**True Negative (TN-2) — do NOT report:**

`uv.lock` is present in the repository root, contains `wheels` arrays with `hash = "sha256:…"` entries, and CI runs `uv sync --frozen`. SECURE — no finding even if `requirements.txt` exists without hash suffixes (the lockfile is the hash-verification layer).

**True Positive (TP-2) — report, medium, conditional, medium confidence:**

```yaml
# .github/workflows/ci.yml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
```

Both `uses:` lines reference mutable tags. Finding: `medium`, `conditional`, `medium` confidence (the exact SHA is not verifiable without network access, but the pattern is clearly a mutable ref).

Only the TP cases are flagged. The TN cases must produce no finding.
