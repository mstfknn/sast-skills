# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] — 2026-06-27

### Added

- **Milestone 4 — LLM & agent runtime (6 new skills).** Semantic detection of LLM/agent runtime risks, each with an LLM-driven verify step. The `sast-stack` router now lists them so they are skipped on codebases with no LLM/agent SDK:
  - `sast-excessiveagency` — state-changing tools wired to the model with no human-in-the-loop approval (CWE-250).
  - `sast-toolcalling` — model output dispatched to a tool without an allow-list or argument validation (CWE-829).
  - `sast-ragleak` — RAG retrieval with no per-tenant ACL filter → cross-tenant leak and indirect injection (CWE-200).
  - `sast-systempromptleak` — secrets embedded in or leaked from system prompts via logs or responses (CWE-200).
  - `sast-memorypoison` — untrusted data persisted to agent memory and later trusted as authoritative (CWE-349).
  - `sast-llmdos` — missing `max_tokens` / agent iteration caps → denial-of-wallet (CWE-770).
- An "LLM & agent runtime" category in the README "What it detects" section.
- This completes the roadmap's main body (Milestones 0–4). Totals are now **62 skills across 58 vulnerability classes**.

## [0.6.0] — 2026-06-27

### Added

- **Milestone 3 — API & auth depth (7 new skills).** Framework-aware coverage of the authentication and API weaknesses that generic scanners over- or under-flag:
  - `sast-ratelimit` — missing rate limit on auth / expensive endpoints (CWE-770).
  - `sast-session` — session fixation and low-entropy session IDs (CWE-384 / CWE-330).
  - `sast-oauth` — OAuth / OIDC misconfiguration: unvalidated `redirect_uri`, missing `state`, missing PKCE (CWE-601 / CWE-352).
  - `sast-routeinventory` — shadow / debug / admin routes left registered and unauthenticated (CWE-1059).
  - `sast-unsafeconsumption` — third-party API responses flowing into a sink without validation, i.e. second-order injection (CWE-20).
  - `sast-cloudsdk` — cloud SDK misuse: public buckets, hardcoded credentials, over-broad IAM (CWE-732).
  - `sast-postmessage` — `postMessage` without origin check, cross-site WebSocket hijacking, and reverse-tabnabbing (CWE-346).
- Totals are now **56 skills across 52 vulnerability classes**.

## [0.5.0] — 2026-06-26

### Added

- **Milestone 2 — agentic-skills security (4 new skills).** A class most signature scanners miss: the threat surface is natural-language manipulation and misconfigured identity, so each skill pairs recon with an explicitly **LLM-driven** verify step.
  - `sast-skillaudit` — hidden instructions and shell-sink lifecycle hooks in untrusted `SKILL.md` / `AGENT.md` / agent-rule config (CWE-77).
  - `sast-mcpsec` — MCP tool-description poisoning and missing tool authentication on network-exposed transports (CWE-862).
  - `sast-configrce` — repository config (`CLAUDE.md`, `.mcp.json`, workflows) that auto-executes shell at project open or checkout (CWE-94, the CVE-2025-59536 class).
  - `sast-agentidentity` — agent / CI credentials and IAM roles scoped beyond the agent's task (CWE-269 / CWE-250).
- A dedicated **Agentic & MCP security** category in the README "What it detects" section.
- Totals are now **49 skills across 45 vulnerability classes**.

## [0.4.0] — 2026-06-26

### Added

- **Nine new Tier-A detection skills — Milestone 1 is complete.** Each ships the full recon → batched-verify → merge flow with per-language sink tables, FP-killers, and schema-v2 findings:
  - `sast-massassign` — mass assignment / overposting (privilege escalation via `is_admin` / `role` / `balance`).
  - `sast-excessivedata` — serializers returning the entire ORM object (password hashes, tokens) instead of an allow-list.
  - `sast-secheaders` — missing `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, and CDN SRI.
  - `sast-crlf` — CRLF / HTTP response splitting via untrusted input in headers, redirects, and logs.
  - `sast-zipslip` — archive-extraction path traversal (arbitrary file write → RCE).
  - `sast-pipelineinj` — untrusted CI event payloads interpolated into `run:` steps (resolves the dangling reference in `sast-stack`'s always-on set).
  - `sast-depconfusion` — internal packages shadowable from public registries + install-time lifecycle scripts.
  - `sast-dangerousapi` — inventory of `eval` / `exec` / reflection / native-bridge sinks for mandatory human review.
  - `sast-ssrfimds` — cloud metadata SSRF (IMDSv1 credential theft → account takeover).
- Totals are now **45 skills across 41 vulnerability classes**.

### Fixed

- `scripts/register-skill.js` placed new README rows past the License section (the table format changed to backtick'd rows during the visual overhaul, breaking its anchor). New rows now land inside a real detection-class table, and the script fails loudly rather than corrupting the file if no anchor row exists.

## [0.3.0] — 2026-06-26

### Added

- **Tech-stack router (`sast-stack`)** — detects the project's stack(s) and frameworks, then selects a targeted subset of detection skills (plus an always-on set) and attaches a framework profile to each, writing the decision to `sast/stack.md`. Step 2 of the assessment is now router-driven and falls back to running the full catalog when no stack map exists.
- **Framework-awareness profiles** — `django`, `spring`, `express`, `rails`, and `fastapi` fact sheets ship with the package and are copied into the install tree; detection skills read their assigned profile during verify to suppress framework-default false positives.
- **Four new Tier-A detection skills** — `sast-deser` (insecure deserialization), `sast-errorhandling` (fail-open logic and stack-trace / secret leaks), `sast-tls` (disabled certificate / hostname verification), and `sast-cookieflags` (missing HttpOnly / Secure / SameSite). Totals are now **36 skills across 32 vulnerability classes**.
- **Findings schema v2** — each finding may carry `exploitability` (reachable / conditional / unreachable / unknown), `confidence`, and `chain_id`. `sast-skills export` stamps the aggregated output with `run.schema: "2.0"` and maps the new fields to SARIF `properties`.

### Changed

- `sast-report` and `sast-triage` rank findings by exploitability and reconcile a `false_positive` verdict with an `unreachable` classification.

## [0.2.2] — 2026-06-26

### Changed

- Bolder block-style ASCII install banner.
- README polish: centered header block, a static **MIT** license badge, assistant names in their official form (e.g. "OpenAI Codex CLI", "Augment Code"), and the long manual-install section folded into a collapsible `<details>`.

## [0.2.1] — 2026-06-26

### Fixed

- The interactive install picker now shows each assistant's official name (e.g. "Gemini CLI", not `gemini`) with a "space to select · enter to confirm" hint, and requires at least one selection — so pressing enter without toggling no longer submits an empty list and errors with "No assistants selected".
- `update` now prints a "Refreshed …" summary on success; it previously refreshed silently and looked like it did nothing.

### Added

- The install picker probes your PATH for CLI-primary assistants (Claude Code, Codex, Gemini, OpenCode, Aider, Hermes, Augment) and disables the ones that aren't installed, so you pick what you actually have. Assistants without a dependable probe (Cursor, Windsurf, Copilot, Cline, Kilo Code, Antigravity, Mistral Vibe) stay selectable.

## [0.2.0] — 2026-06-26

### Added

- **14-assistant install.** `npx sast-skills install` now supports Claude Code, OpenAI Codex (CLI), Gemini CLI, GitHub Copilot, Cursor, Windsurf, OpenCode, Cline, Antigravity, Aider, Kilo Code, Augment, Hermes Agent, and Mistral Vibe — via an interactive multi-select (with an "All of the above" option) and a comma-separated `--assistant claude,cursor,copilot` flag. Each assistant gets the orchestrator written to its own convention's path (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.windsurf/rules/sast-skills.md`, `.clinerules/sast-skills.md`, `CONVENTIONS.md`) plus the matching skill tree, deduped across shared paths.
- An ASCII banner and a post-install summary (with an Aider `--read CONVENTIONS.md` hint) on interactive install.

### Changed

- `update` auto-detects an existing install (by orchestrator signature) and refreshes only what is present, without clobbering a user-authored entry file. `doctor` and `uninstall` are registry-aware and accept any assistant id (and the legacy `agents` alias).
- `--assistant` accepts a comma-separated id list; the legacy `claude` / `agents` / `all` values still work.

## [0.1.5] — 2026-06-26

### Security

- Updated dependencies to clear all 27 osv-scanner advisories (all dev-only/transitive). Bumped the runtime dependency `@clack/prompts` to `^1.6.0`, `vitest` to `^4.1.9`, and `markdownlint-cli2` to `^0.22.1`, and pinned fixed versions of vulnerable transitive dev deps (hono, vite, uuid, fast-uri, @anthropic-ai/sdk, js-yaml, markdown-it, smol-toml, qs, ip-address, brace-expansion) via `overrides`. `osv-scanner`: no issues found; `npm audit`: 0.

## [0.1.4] — 2026-06-26

### Fixed

- `sast-skills export` now stamps `run.version` with the actual CLI version instead of a hard-coded `0.1.0`, so SARIF/JSON reports label the correct tool version.

## [0.1.3] — 2026-06-26

### Changed

- The CLI prints a clean, actionable one-line message instead of a Node stack trace when a command fails. Re-running `install` on an already-installed project now points to `sast-skills update` (and still refuses to clobber an existing entry file without `--force`).

## [0.1.2] — 2026-06-26

### Changed

- Release pipeline now publishes via npm **OIDC trusted publishing** instead of a long-lived `NPM_TOKEN` secret, and gates `npm publish` behind a dedicated test job (`needs: test`) that also runs markdown lint.

### Fixed

- Corrected the GitHub Code Scanning example in the README to reference `mstfknn/sast-skills` (was the upstream `utkusen/sast-skills` path).

## [0.1.1] — 2026-06-26

### Fixed

- `install --scope global` now writes skills under `~/.claude/skills` instead of the current working directory. Global scope previously only skipped copying the `CLAUDE.md` / `AGENTS.md` entry file but still installed the skill tree into the cwd, so selecting "global" silently behaved like a project install.

### Changed

- Bumped CI actions to current majors (`actions/checkout@v7`, `actions/setup-node@v6`) — the prior `@v4` pins targeted the now-deprecated Node 20 action runtime.
- `register-skill` is now idempotent: re-registering an existing skill no longer appends duplicate skip lines or table rows to `CLAUDE.md` / `AGENTS.md` / `README.md`.

## [0.1.0] — 2026-04-21

Initial public release.

### Added

- **CLI** (`npx sast-skills`) with commands:
  - `install` — interactive install (clack prompts) or flag-driven (`--yes --assistant claude|agents|all --scope project|global [--force] [--dry-run]`).
  - `update` — refresh an existing install with the bundled skill files.
  - `uninstall` — remove installed skills; refuses to overwrite a modified `CLAUDE.md` without `--force`.
  - `doctor` — verify an install and report `OK` / `MISSING` / `MODIFIED` per file; exits non-zero on issues.
  - `export` — aggregate `sast/*-results.json` into canonical JSON, **SARIF 2.1.0**, or HTML; supports `--triaged` to prefer `sast/triaged.json`, `--output` to write to a file.
- **31 skills** following the canonical three-phase pattern (recon → batched verify → merge):
  - Reconnaissance: `sast-analysis`
  - Injection: `sast-sqli`, `sast-nosql`, `sast-ldap`, `sast-graphql`, `sast-xss`, `sast-ssti`, `sast-rce`, `sast-xxe`, `sast-ssrf`, `sast-openredirect`
  - Access control: `sast-idor`, `sast-missingauth`, `sast-jwt`, `sast-csrf`, `sast-cors`
  - File & path: `sast-pathtraversal`, `sast-fileupload`
  - Supply chain & infra: `sast-deps`, `sast-iac`, `sast-hardcodedsecrets`
  - Crypto & runtime: `sast-crypto`, `sast-prototype`, `sast-redos`, `sast-race`
  - Data exposure: `sast-pii`
  - LLM-specific: `sast-promptinjection`, `sast-llmoutput`
  - Business logic: `sast-businesslogic`
  - Synthesis: `sast-report`, `sast-triage`
- **Orchestration**: four-step flow in `CLAUDE.md` / `AGENTS.md` — analysis → parallel vulnerability scan → consolidated report → triage.
- **Canonical finding schema** in both orchestrator templates — each skill emits `sast/*-results.json` alongside markdown so the `export` CLI can produce SARIF/JSON/HTML.
- **Triage step (Step 4)** — `sast-triage` skill eliminates false positives and adjusts severities with codebase evidence, writing `sast/final-report-triaged.md` + `sast/triaged.json` without mutating the raw scan output.
- **CI integrations**:
  - Reusable composite GitHub Action at `.github/actions/scan/action.yml` (SARIF → Code Scanning).
  - Pre-commit hook template at `hooks/pre-commit`.
  - `Dockerfile` (node:20-alpine) + `.dockerignore`.
- **Developer tooling**:
  - `scripts/sync-skills.js` — mirror `.claude/skills` to `.agents/skills`.
  - `scripts/scaffold-skill.js` — generate a new skill stub in both trees.
  - `scripts/register-skill.js` — auto-patch `CLAUDE.md` / `AGENTS.md` / `README.md` when adding a new skill.
  - `prepublishOnly` runs sync + full test suite.
- **Test suite** — 64+ tests covering CLI behaviour, install / update / uninstall / doctor / export flows, orchestrator contract, skill frontmatter schema, `.claude/skills` ↔ `.agents/skills` drift, markdown lint, release readiness.
- **Documentation** — README, CONTRIBUTING, CHANGELOG, CODE_OF_CONDUCT.

### Known limitations

- Skill body prose is LLM-generated security guidance — production-grade, but detection quality depends on the model running the scan; complement with dedicated scanners (Semgrep, CodeQL, OSV-Scanner) where available.
- Paket sast-files tree'i hem `.claude/skills` hem `.agents/skills` altında taşır (mirror); paket boyutunu küçültmek ileriki sürümde hedeftir.

[Unreleased]: https://github.com/mstfknn/sast-skills/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/mstfknn/sast-skills/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/mstfknn/sast-skills/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mstfknn/sast-skills/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/mstfknn/sast-skills/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/mstfknn/sast-skills/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/mstfknn/sast-skills/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/mstfknn/sast-skills/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/mstfknn/sast-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mstfknn/sast-skills/releases/tag/v0.1.0
