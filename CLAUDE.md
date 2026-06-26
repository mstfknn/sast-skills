# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`sast-skills` is a **content bundle wrapped in a Node CLI**. The product is 31 agent-skill
markdown files (`SKILL.md`) that turn an LLM coding assistant into a SAST scanner. The
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

### The CLI (`src/cli.js`)

`bin/sast-skills.js` parses `--version`/`--help` and dispatches everything else to
`run()` in `src/cli.js`, which routes to one of four commands in `src/commands/`:
`install`, `uninstall`, `doctor`, `export`. `update` is just `install` with `--force`
appended. Commands take an injected `{ argv, cwd, packageRoot, stdout, stdin, prompt }`
bag — there are **no direct reads of `process`/`console` inside `src/`**, which is what
makes them unit-testable. Interactive prompts go through `src/prompts/clack.js` (a thin
`@clack/prompts` wrapper) and are also injected, so tests pass a fake.

`install` copies the orchestrator entry file (`CLAUDE.md`/`AGENTS.md`) to the project root
and each `SKILL.md` into `.claude/skills/<name>/` or `.agents/skills/<name>/`, driven by the
`ASSISTANT_LAYOUT` map. `export` reads canonical `sast/*-results.json` findings and renders
JSON / SARIF 2.1.0 / HTML (`--triaged` prefers `sast/triaged.json`).

### The skill bundle (`sast-files/`)

- `CLAUDE.md` and `AGENTS.md` are the **bundled orchestrators** — the 4-phase scan driver
  shipped to users. **They are byte-identical except for skill-tree path names** and must
  stay that way. Do not confuse them with *this* repo's own dev CLAUDE.md (the file you're
  reading). Editing the product orchestrator means editing both.
- `.claude/skills/` is the **canonical** skill tree (31 dirs, one `SKILL.md` each).
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
