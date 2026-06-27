# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`sast-skills` is a **content bundle wrapped in a Node CLI**. The product is 68 agent-skill
markdown files (`SKILL.md`) — 64 detection skills across 64 vulnerability classes plus 4
recon/synthesis skills — that turn an LLM coding assistant into a SAST scanner. The
JavaScript in `src/`, `bin/`, and `scripts/` only *installs*, *syncs*, and *aggregates* —
it never analyzes code itself. Most "features" are edits to the markdown skills, not the JS.

Two layers, kept deliberately separate:

- **Tooling** (`src/`, `bin/`, `scripts/`, `test/`) — Node ≥20, pure ESM (`"type": "module"`),
  no build step, tested with vitest under TDD-guard.
- **Skill content** (`sast-files/`) — the bundled orchestrator entry files + the skill trees
  that get copied into a user's project on `install`.

## Commands

```bash
npm install
npm test                              # vitest run (the canonical gate)
npm run test:watch                    # vitest watch
npx vitest run test/install.test.js   # single test file
npx vitest run -t "doctor reports"    # single test by name
npm run sync                          # mirror .claude/skills → .agents/skills (see below)
npm run lint:md                       # markdownlint-cli2 over markdown

# CLI under development (same entry the published bin exposes):
node bin/sast-skills.js install --yes --assistant claude,cursor --scope project
node bin/sast-skills.js update --yes --target .
node bin/sast-skills.js doctor --target . --assistant claude
node bin/sast-skills.js export --input sast/ --format sarif --output report.sarif

# Add a new vulnerability skill (run both, in order):
node scripts/scaffold-skill.js sast-foo                       # stub SKILL.md in BOTH trees
node scripts/register-skill.js sast-foo foo "Foo" "Foo desc"  # patch CLAUDE.md, AGENTS.md, README.md
npm run sync                                                   # then re-sync the mirror
```

There is no lint/format/typecheck for the JS beyond the tests — vitest *is* the gate. Plain
JS with JSDoc-free ESM; do not introduce a TypeScript or bundler step.

## Architecture

### The CLI (`src/cli.js`) and the assistant registry

`bin/sast-skills.js` parses `--version`/`--help` (and prints the ASCII banner from
`src/banner.js` before an interactive install/update), then dispatches to `run()` in
`src/cli.js`, which routes to one of **five** commands in `src/commands/`: `install`,
`update`, `uninstall`, `doctor`, `export`. Commands take an injected
`{ argv, cwd, packageRoot, stdout, stdin, prompt }` bag — there are **no direct reads of
`process`/`console` inside `src/`**, which is what makes them unit-testable. Interactive
prompts go through `src/prompts/clack.js` (a thin `@clack/prompts` wrapper), injected so
tests pass a fake.

**`src/agents.js` is the single source of truth** for supported assistants — a 14-entry
`AGENTS` registry (`{ id, label, entryFile, skillTree, cli? }`) plus `resolveAgents()`
(expands the `all` / legacy `agents` aliases, dedupes), `agentById()`, and `ENTRY_SOURCE`
(`.claude`→`CLAUDE.md`, `.agents`→`AGENTS.md`). `install` / `update` / `doctor` / `uninstall`
all consume it. There is no more `ASSISTANT_LAYOUT`.

- **`install`** resolves a selection (comma-list `--assistant claude,cursor,copilot`, or
  `all`, or an interactive multiselect) to a **deduped** set of entry files + skill trees, and
  writes each assistant's orchestrator to its own convention's path (`CLAUDE.md`, `AGENTS.md`,
  `GEMINI.md`, `.github/copilot-instructions.md`, `.windsurf/rules/sast-skills.md`,
  `.clinerules/sast-skills.md`, `CONVENTIONS.md`) plus the matching tree. It refuses to clobber
  an existing entry file without `--force`. The interactive picker uses `src/detect.js` (a
  dependency-free PATH scan) to disable CLI-primary assistants not found on PATH.
- **`update`** (its own command, `src/commands/update.js`) auto-detects an existing install by
  the orchestrator signature and refreshes only what's present, never clobbering a user-authored
  file; with `--assistant` it delegates to `install --force`.
- **`export`** reads canonical `sast/*-results.json` findings → JSON / SARIF 2.1.0 / HTML
  (`--triaged` prefers `sast/triaged.json`); the run version is stamped from `package.json`.

### The skill bundle (`sast-files/`)

- `CLAUDE.md` and `AGENTS.md` are the **bundled orchestrators** — the 4-phase scan driver
  shipped to users. **They are byte-identical except for skill-tree path names** and must
  stay that way. Do not confuse them with *this* repo's own dev CLAUDE.md (the file you're
  reading). Editing the product orchestrator means editing both.
- `.claude/skills/` is the **canonical** skill tree (68 dirs, one `SKILL.md` each).
- `.agents/skills/` is **generated** — `npm run sync` does `rm -rf` + `cp -R` from the
  canonical tree. Never hand-edit `.agents/skills/`; your change will be erased on next sync.

### Skill anatomy

Each `SKILL.md` has YAML frontmatter (`name`, `description`, `version`) where **`name` must
equal the directory name** (enforced by `test/skill-schema.test.js`), followed by a body that
defines the same three-phase pattern every detection skill uses:
**recon** (find candidate sink sites) → **batched verify** (parallel subagents, 3 candidates
each, taint analysis) → **merge** (consolidate into `sast/<skill>-results.md` +
`sast/<skill>-results.json`). The canonical finding JSON schema is documented in the
orchestrator and in the README under "Finding schema".

### Routing, schema v2, and framework profiles (the M0 layer)

- **Tech-stack router** — `sast-stack` (a recon/synthesis skill, not a detector) runs at the
  orchestrator's **Step 1b**, after `sast-analysis`. It reads the project's manifests and writes
  `sast/stack.md`: a JSON map of detected stacks → selected skills (+ per-skill `profile`) → an
  always-on set (`sast-hardcodedsecrets`, `sast-deps`, `sast-iac`, `sast-pipelineinj`,
  `sast-crypto`) → skipped skills with reasons. Step 2 runs only the selected subset; if
  `sast/stack.md` is absent it falls back to the full catalog. The router is what keeps a
  64-detector fan-out affordable and gates LLM/agent-only skills off non-LLM repos.
- **Framework profiles** — `sast-files/profiles/{django,spring,express,rails,fastapi}.md` are
  FP-killer fact sheets shipped via the package `files` allowlist; `install` copies them to
  `<tree>/profiles/`. A detection skill reads its assigned profile during verify to suppress
  framework-default false positives.
- **Findings schema v2** — every canonical finding may also carry `exploitability`
  (reachable|conditional|unreachable|unknown), `confidence` (high|medium|low), and `chain_id`
  (a stable id shared by findings that compose into one attack). These are optional; set them
  when verify can. `sast-skills export` stamps the aggregated output with `run.schema: "2.0"`
  and maps the three fields to SARIF `properties`.

## Critical invariants (the tests enforce these — they will fail loudly otherwise)

1. **The two skill trees must be identical** except for the `.claude`/`.agents` directory
   name. After editing anything under `.claude/skills/`, run `npm run sync`.
   `sync-skills.test.js` checks the mirror; `prepublishOnly` re-syncs before publish.
2. **Every bundled skill must be referenced in README.md, AGENTS.md, and the orchestrator
   CLAUDE.md** (`docs-completeness.test.js`). Adding a skill without registering it = red CI.
   Use `register-skill.js` rather than hand-patching, so the skip-line, orchestrator table
   row, and README table row all land in the right spots.
3. **`name` frontmatter == directory name** for every skill.
4. **Package `files` allowlist** (`package.json`) must include any new top-level path you want
   published — `package-contents.test.js` / `release-readiness.test.js` guard this.

## Adding a vulnerability skill (full loop)

1. `node scripts/scaffold-skill.js sast-foo` — stubs the dir in both trees.
2. `node scripts/register-skill.js sast-foo foo "Foo Label" "One-line description"` — patches
   `sast-files/CLAUDE.md`, `sast-files/AGENTS.md`, and `README.md`.
3. Write the real `SKILL.md` body in `sast-files/.claude/skills/sast-foo/` following the
   recon → batched-verify → merge structure of an existing skill (e.g. `sast-sqli`).
4. `npm run sync` to regenerate `.agents/skills/`.
5. `npm test` — the contract tests confirm sync, docs coverage, and frontmatter are all green.

## Conventions

- TDD-guard (`tdd-guard-vitest`) is wired in `vitest.config.js`; write the failing test first.
  Most tests here are **contract tests** over file layout, docs coverage, and CLI behavior
  rather than algorithmic unit tests — match that style.
- Keep `src/` side-effect-free and dependency-injected; route I/O through the passed-in bag.
- Idempotency is a product promise: `install`/`update`/`export` and the orchestrator's
  per-skill skip rules must be safely re-runnable.
- Releasing: bump `package.json` `version`, add a `CHANGELOG.md` entry, then push a `vX.Y.Z`
  tag. `.github/workflows/publish.yml` runs the test job, then publishes to npm via **OIDC
  trusted publishing** (no `NPM_TOKEN`) with provenance. Pushes to `main` auto-refresh a
  test-count badge on the `badges` branch.
