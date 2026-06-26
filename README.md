<div align="center">

# 🛡️ sast-skills

**Turn your LLM coding assistant into a fully featured SAST scanner.**

Drop-in agent skills for **14 AI assistants** — Claude Code, OpenAI Codex CLI, Gemini CLI, GitHub Copilot, Cursor, Windsurf, OpenCode, Cline, Antigravity, Aider, Kilo Code, Augment Code, Hermes Agent, and Mistral Vibe.

[![npm version](https://img.shields.io/npm/v/sast-skills.svg?style=flat-square)](https://www.npmjs.com/package/sast-skills)
[![CI](https://github.com/mstfknn/sast-skills/actions/workflows/test.yml/badge.svg)](https://github.com/mstfknn/sast-skills/actions/workflows/test.yml)
[![tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mstfknn/sast-skills/badges/tests.json&style=flat-square)](https://github.com/mstfknn/sast-skills/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-339933.svg?style=flat-square&logo=node.js)](https://nodejs.org/)

</div>

> Claude Code with Opus is recommended for quality; any capable model works.

## ⚡ Quick start

```bash
npx sast-skills install   # pick your assistant(s) — ones found on your PATH are pre-enabled
```

Then open the project in your assistant and prompt:

> **Run vulnerability scan**

It runs all four phases and writes findings to `sast/`. Aggregate them with `npx sast-skills export --format sarif` for GitHub Code Scanning or CI.

---

## 📑 Table of contents

- [✨ Highlights](#-highlights)
- [🔄 Flow](#-flow)
- [🔍 What it detects](#-what-it-detects)
- [📦 Installation](#-installation)
- [🚀 Running a scan](#-running-a-scan)
- [🔌 CI integrations](#-ci-integrations)
- [🩺 Verify & troubleshoot](#-verify--troubleshoot)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Highlights

- **31 skills across 28 vulnerability classes** — injection, broken access control, weak crypto, file handling, supply chain, business logic, and LLM-specific risks (prompt injection, insecure output handling).
- **Four-phase orchestration** — reconnaissance → parallel detection → consolidated report → evidence-based triage, driven entirely from `CLAUDE.md` / `AGENTS.md`.
- **Idempotent & resumable** — each phase skips work whose output already exists; re-run after fixing issues to refresh only what's stale.
- **Machine-readable output** — every skill emits canonical JSON; `sast-skills export` aggregates to JSON, **SARIF 2.1.0**, or HTML for GitHub Code Scanning and CI.
- **Cross-assistant** — identical skills ship for Claude Code (`.claude/skills`) and every `AGENTS.md` assistant (`.agents/skills`).
- **Zero-config CLI** — `install` / `update` / `uninstall` / `doctor` / `export`, published from GitHub Actions with npm provenance (SLSA attestation).

---

## 🔄 Flow

The orchestrator executes four phases — reconnaissance, parallel detection, synthesis, and triage:

```mermaid
flowchart TD
    U(["User: Run vulnerability scan"]) --> R{"CLAUDE.md / AGENTS.md orchestrator"}
    R --> S1["Step 1 — sast-analysis<br/>codebase and architecture map"]
    S1 -->|sast/architecture.md| S2["Step 2 — parallel vulnerability scan<br/>28 skills: recon, batched verify, merge"]
    S2 -->|sast/*-results.md and *-results.json| S3["Step 3 — sast-report<br/>consolidate and rank"]
    S3 -->|sast/final-report.md| S4["Step 4 — sast-triage<br/>false-positive elimination,<br/>severity adjustment with evidence"]
    S4 -->|sast/final-report-triaged.md and triaged.json| EXP["npx sast-skills export<br/>JSON, SARIF, HTML"]
    EXP --> CS(["GitHub Code Scanning, CI, dashboards"])
```

Every step is **idempotent**: if its output file already exists, the orchestrator skips it. Re-run the scan after fixing issues to refresh only what's stale.

---

## 🔍 What it detects

All skills follow the same three-phase pattern: **recon** → **batched verify** (parallel subagents, 3 per batch) → **merge**. Each writes a human-readable markdown report and a canonical JSON findings file that `sast-skills export` aggregates.

### Reconnaissance & Synthesis

| Skill | Role |
|---|---|
| `sast-analysis` | Codebase recon, architecture mapping, threat model |
| `sast-report` | Consolidate per-class findings into a ranked report |
| `sast-triage` | Remove false positives and adjust severities with codebase evidence |

### Injection

| Skill | Vulnerability Class |
|---|---|
| `sast-sqli` | SQL injection |
| `sast-nosql` | NoSQL injection (Mongo, Firestore, DynamoDB) |
| `sast-ldap` | LDAP filter / DN injection |
| `sast-graphql` | Unsafe GraphQL document construction |
| `sast-xss` | Cross-Site Scripting |
| `sast-ssti` | Server-Side Template Injection |
| `sast-rce` | Remote Code Execution (command injection, eval, unsafe deserialization) |
| `sast-xxe` | XML External Entity |
| `sast-ssrf` | Server-Side Request Forgery |
| `sast-openredirect` | Open redirect (phishing / OAuth token theft) |

### Access control & Auth

| Skill | Vulnerability Class |
|---|---|
| `sast-idor` | Insecure Direct Object Reference |
| `sast-missingauth` | Missing auth / broken function-level authorization |
| `sast-jwt` | Insecure JWT implementations |
| `sast-csrf` | Cross-Site Request Forgery |
| `sast-cors` | CORS misconfiguration |

### Files, crypto & runtime

| Skill | Vulnerability Class |
|---|---|
| `sast-pathtraversal` | Path / directory traversal |
| `sast-fileupload` | Insecure file upload |
| `sast-crypto` | Weak primitives, bad modes, IV reuse, weak PRNG |
| `sast-prototype` | JavaScript prototype pollution |
| `sast-redos` | Catastrophic-backtracking regex DoS |
| `sast-race` | Race conditions and TOCTOU |

### Data exposure & supply chain

| Skill | Vulnerability Class |
|---|---|
| `sast-hardcodedsecrets` | API keys / tokens / credentials in client-facing code |
| `sast-pii` | PII and credential leakage to logs / telemetry / error pages |
| `sast-deps` | Known-vulnerable dependencies (CVE in lockfiles) |
| `sast-iac` | Insecure IaC (Dockerfile / Terraform / Kubernetes / GitHub Actions) |

### Business logic & LLM-specific

| Skill | Vulnerability Class |
|---|---|
| `sast-businesslogic` | Price manipulation, workflow bypass, reward abuse |
| `sast-promptinjection` | Untrusted text reaching an LLM prompt (OWASP LLM #1) |
| `sast-llmoutput` | Unvalidated LLM output reaching code / HTML / SQL / shell sinks (OWASP LLM #2) |

---

## 📦 Installation

```bash
npx sast-skills install
```

The installer shows a multi-select of all 14 supported assistants (plus **All of the above**) and asks whether to install into the current project or your user home directory (`project` / `global`). To skip prompts, pass a comma-separated list of assistant ids (or `all`):

```bash
npx sast-skills install --yes --assistant claude,cursor,copilot --scope project
```

> If your project already contains a `CLAUDE.md` or `AGENTS.md`, the installer refuses to clobber it by default — back it up or pass `--force`.

<details>
<summary><b>Manual install</b> (without <code>npx</code> / npm) — click to expand</summary>

<br>

Use this path if you can't run `npx` (corporate proxy, npm registry unreachable, offline environment) or if you want to pin to this fork's source rather than the published npm package. The CLI installer only does two things — drop the orchestrator entry file at the project root and mirror each skill's `SKILL.md` into the right hidden directory — so a plain `cp -R` reproduces it exactly.

### 1. Get the bundled files

```bash
git clone https://github.com/mstfknn/sast-skills.git
```

Everything you need lives under `sast-skills/sast-files/`:

```text
sast-files/
├── CLAUDE.md                       # Orchestrator entry for Claude Code
├── AGENTS.md                       # Orchestrator entry for Gemini CLI / Codex / OpenCode / Cursor
├── .claude/skills/sast-*/SKILL.md  # 31 skills in Claude Code format
└── .agents/skills/sast-*/SKILL.md  # Same 31 skills mirrored for AGENTS.md assistants
```

The two skill trees are kept in sync by `npm run sync` — content is identical, only the directory name differs.

### 2a. Install for Claude Code

Set `SAST_SRC` to the clone path so the commands below stay copy-pasteable:

```bash
export SAST_SRC=/absolute/path/to/sast-skills
cd /path/to/your-project
```

**Project scope** (recommended — versioned alongside your repo):

```bash
cp "$SAST_SRC/sast-files/CLAUDE.md" ./CLAUDE.md
cp -R "$SAST_SRC/sast-files/.claude" ./
```

> If you already use a project-level `CLAUDE.md`, **do not overwrite it** — Claude Code reads only one `CLAUDE.md` per project. Merge the orchestrator content (the four-phase flow) into your existing file instead.

**Global scope** (skills available in every project; orchestrator still copied per-project):

```bash
mkdir -p ~/.claude/skills
cp -R "$SAST_SRC/sast-files/.claude/skills/." ~/.claude/skills/
# Then in any project where you want the scan flow:
cp "$SAST_SRC/sast-files/CLAUDE.md" /path/to/your-project/CLAUDE.md
```

### 2b. Install for Gemini CLI (and other `AGENTS.md` assistants)

```bash
export SAST_SRC=/absolute/path/to/sast-skills
cd /path/to/your-project
cp "$SAST_SRC/sast-files/AGENTS.md" ./AGENTS.md
cp -R "$SAST_SRC/sast-files/.agents" ./
```

Gemini CLI reads `GEMINI.md`; the installer writes it for you when you pick Gemini.

### 3. Verify the install

```bash
# Project scope (Claude Code)
ls CLAUDE.md && ls .claude/skills/ | head

# Project scope (Gemini / AGENTS.md)
ls AGENTS.md && ls .agents/skills/ | head

# Global scope (Claude Code)
ls ~/.claude/skills/ | head
```

You should see all 31 `sast-*` skill directories. Open the project in your assistant and prompt **"Run vulnerability scan"** — the orchestrator inside `CLAUDE.md` / `AGENTS.md` drives the four phases from there.

### 4. Keeping a manual install up to date

```bash
cd "$SAST_SRC" && git pull
# Re-run the cp commands from Step 2a / 2b to refresh — they're idempotent.
```

If you keep the clone around, `cd "$SAST_SRC" && git pull && <rerun cp>` is the manual equivalent of `npx sast-skills update`.

</details>

### CLI commands

| Command | What it does |
|---|---|
| `npx sast-skills install` | Copy `CLAUDE.md` / `AGENTS.md` and the skill tree into your project or `$HOME` |
| `npx sast-skills update` | Refresh an existing install with the currently bundled skill files |
| `npx sast-skills uninstall` | Remove installed skills; refuses to drop a modified `CLAUDE.md` without `--force` |
| `npx sast-skills doctor` | Verify an install and report `OK` / `MISSING` / `MODIFIED` per file; exits non-zero on issues |
| `npx sast-skills export --input sast/ --format sarif --output report.sarif` | Aggregate `sast/*-results.json` into JSON, SARIF 2.1.0, or HTML |
| `npx sast-skills export --input sast/ --triaged --format sarif` | Prefer the triaged `sast/triaged.json` over raw per-skill results |
| `npx sast-skills --version` | Print the installed CLI version |

### Install-time flags

| Flag | Purpose |
|---|---|
| `--yes` | Non-interactive; required when stdin is not a TTY |
| `--assistant <ids>` | Comma-separated assistant ids (e.g. `claude,cursor,copilot`) or `all` |
| `--scope <project\|global>` | Install into `./.claude/skills/` or `$HOME/.claude/skills/` |
| `--target <path>` | Explicit install target (overrides `--scope`) |
| `--force` | Overwrite a pre-existing `CLAUDE.md` / `AGENTS.md` |
| `--dry-run` | Print the file plan without writing |

---

## 🚀 Running a scan

After installing, open the project in your AI assistant and ask:

> Run vulnerability scan

or

> Find vulnerabilities in this codebase

The orchestrator takes over. It runs all four phases automatically, respects idempotency (re-runs only pick up what's missing), and writes everything into `sast/` in your project root.

### Output files

| File | Description |
|---|---|
| `sast/architecture.md` | Technology stack, architecture, entry points, data flows |
| `sast/*-results.md` | Per-vulnerability-class findings (human-readable) |
| `sast/*-results.json` | Canonical machine-readable findings (fed to `sast-skills export`) |
| `sast/final-report.md` | Consolidated raw report ranked by severity |
| `sast/final-report-triaged.md` | Triaged report — false positives removed, severities adjusted with evidence |
| `sast/triaged.json` | Canonical triaged findings (preferred by `sast-skills export --triaged`) |

### Finding schema

Each skill writes `sast/<skill>-results.json` as a bare findings list:

```jsonc
{
  "findings": [
    {
      "id": "sast-sqli-0001",
      "skill": "sast-sqli",
      "severity": "critical|high|medium|low|info",
      "title": "SQL injection in /api/user",
      "description": "…",
      "location": { "file": "src/api/user.js", "line": 42, "column": 10 },
      "remediation": "…"
    }
  ]
}
```

`sast-skills export` aggregates those files into one document wrapped in a `run` envelope — `{ "run": { "tool": "sast-skills", "version": "<cli-version>" }, "findings": [...] }` — stamping the version of the CLI that produced the report. The triage step writes `sast/triaged.json` in that same enveloped shape.

Triaged findings add `triage_status` (`confirmed|upgraded|downgraded|false_positive`), `triage_original_severity` (when severity changed), and `triage_evidence` with concrete codebase citations.

---

## 🔌 CI integrations

### GitHub Code Scanning (SARIF)

Composite action at `.github/actions/scan/action.yml`:

```yaml
- uses: mstfknn/sast-skills/.github/actions/scan@main
  with:
    input: sast/
    output: sast-skills.sarif
```

This runs `sast-skills export --format sarif` and uploads the result to Code Scanning via `github/codeql-action/upload-sarif@v3`.

### Pre-commit hook

Copy [hooks/pre-commit](hooks/pre-commit) into `.git/hooks/pre-commit` to make `sast-skills doctor` gate every commit.

### Docker

```bash
docker build -t sast-skills .
docker run --rm -v "$PWD:/work" sast-skills export --input sast/ --format sarif --output report.sarif
```

The bundled `Dockerfile` is `node:20-alpine`-based with `sast-skills` set as the entrypoint.

---

## 🩺 Verify & troubleshoot

```bash
# Is the install in the expected shape?
npx sast-skills doctor --target . --assistant claude

# Version check
npx sast-skills --version
npm view sast-skills version    # latest on the registry

# Upgrade
npx sast-skills update
```

`doctor` exits `0` if every bundled file in the target matches the installed version's copy, and `1` if any file is `MISSING` or `MODIFIED`. `MODIFIED` means the file diverged from the bundled copy — expected if you edit the entry file, otherwise a signal to run `update`.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Developer loop:

```bash
npm install
npm test                                  # vitest suite (TDD-guard enabled; count shown in the tests badge)
npm run sync                              # mirror .claude/skills → .agents/skills
node scripts/scaffold-skill.js sast-foo   # stub a new skill in both trees
node scripts/register-skill.js sast-foo foo "Foo" "Foo injection description"
npm run lint:md                           # markdownlint
```

`prepublishOnly` runs `npm run sync && npm test` — a dirty mirror or a red test aborts `npm publish`.

- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Release history: [CHANGELOG.md](CHANGELOG.md)

---

## 📄 License

MIT — see [LICENSE](LICENSE).
