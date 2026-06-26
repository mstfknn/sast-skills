# Multi-Agent Install — Design

- **Status:** Proposed
- **Date:** 2026-06-26
- **Scope:** `npx sast-skills install` UX overhaul + support for 14 AI coding assistants

## Context and Problem

Today `npx sast-skills install` exposes a bare two-option choice (`--assistant claude|agents`)
and a plain prompt. Users want:

1. A proper **banner** (name, tagline, repo link, what the tool does).
2. A **prettier, clearer** interactive screen.
3. To pick from a **broad list of assistants** — and install for several at once.

Research (cited below) shows most modern assistants read either the cross-tool `AGENTS.md`
file and/or the open **Agent Skills** (`SKILL.md`) folder format. The existing two skill trees
(`.claude/skills/`, `.agents/skills/`) already cover a large fraction; what varies per
assistant is *where the orchestrator instruction file goes*.

## Goals

- Support **14 assistants** via an extensible registry.
- One interactive **multi-select** with an "All of the above" option; non-interactive
  `--assistant <comma-list>` flag.
- Keep the existing two skill trees; vary only the entry-file path per assistant.
- Preserve safety (never clobber a user-authored entry file without `--force`) and the clean
  one-line error output added earlier.
- `update` refreshes whatever is already installed (auto-detect).

## Non-Goals / Out of Scope

- **OpenClaw** — reads only its own home workspace (`~/.openclaw/workspace/`), never a target
  repo. Cannot be installed into a project; excluded.
- **Hermes home-skill auto-discovery** — Hermes reads repo-root `AGENTS.md` (supported here)
  but only auto-discovers skills from `~/.hermes/skills/`. We ship the `AGENTS.md` orchestrator;
  the home skills path is out of scope (skills are read on-demand by path via the orchestrator,
  same as Codex/Gemini).
- Native per-tool rules folders where `AGENTS.md` already suffices (e.g. `.cursor/rules/*.mdc`).

## Research Summary (sources)

| Assistant | AGENTS.md | Agent Skills | Source |
|---|:--:|:--:|---|
| Antigravity | yes | yes (`.agents/skills/`) | antigravity.google/docs/skills, /docs/rules-workflows |
| Kilo Code | yes | yes (`.kilo/skills/` + compat `.agents/`, `.claude/`) | kilo.ai/docs/customize/{agents-md,skills} |
| Augment | yes (+CLAUDE.md) | yes (compat `.claude/`, `.agents/`) | docs.augmentcode.com/{setup-augment/guidelines,cli/skills} |
| Mistral Vibe | yes | yes (`.vibe/skills/` or `.agents/skills/`) | docs.mistral.ai/vibe/code/cli/{agents,skills} |
| Hermes Agent | yes (repo root) | home-only | github.com/NousResearch/hermes-agent |
| OpenClaw | workspace-only | workspace-only | github.com/openclaw/openclaw (excluded) |

Mainstream tools confirmed from prior knowledge / project README: Codex (`AGENTS.md`),
Gemini CLI (`GEMINI.md`), OpenCode (`AGENTS.md`), Cursor (`AGENTS.md` + `.cursor/rules`),
GitHub Copilot (`.github/copilot-instructions.md`), Windsurf (`.windsurf/rules/`),
Cline (`.clinerules/`), Aider (`CONVENTIONS.md`, loaded via config).

## Architecture — Agent Registry

Replace the two-entry `ASSISTANT_LAYOUT` with an ordered `AGENTS` registry. Each entry:

```text
{ id, label, entryFile, skillTree }   // skillTree ∈ ".claude" | ".agents"
```

| id | label | entryFile | skillTree |
|---|---|---|---|
| `claude` | Claude Code | `CLAUDE.md` | `.claude` |
| `codex` | OpenAI Codex (CLI) | `AGENTS.md` | `.agents` |
| `gemini` | Gemini CLI | `GEMINI.md` | `.agents` |
| `copilot` | GitHub Copilot | `.github/copilot-instructions.md` | `.agents` |
| `cursor` | Cursor | `AGENTS.md` | `.agents` |
| `windsurf` | Windsurf | `.windsurf/rules/sast-skills.md` | `.agents` |
| `opencode` | OpenCode | `AGENTS.md` | `.agents` |
| `cline` | Cline | `.clinerules/sast-skills.md` | `.agents` |
| `antigravity` | Antigravity | `AGENTS.md` | `.agents` |
| `aider` | Aider | `CONVENTIONS.md` | `.agents` |
| `kilocode` | Kilo Code | `AGENTS.md` | `.agents` |
| `augment` | Augment | `AGENTS.md` | `.agents` |
| `hermes` | Hermes Agent | `AGENTS.md` | `.agents` |
| `mistralvibe` | Mistral Vibe | `AGENTS.md` | `.agents` |

**Content source:** the `.claude` entry (`CLAUDE.md`) is written from `sast-files/CLAUDE.md`;
every `.agents`-family entry file is written from `sast-files/AGENTS.md` (the same orchestrator).

**Backward-compat aliases:** `claude` (unchanged), `agents` (= generic `AGENTS.md` + `.agents`
target, equivalent to selecting any single AGENTS.md assistant), `all` (every registry id).

## Install Behavior

1. Resolve selection (flags or interactive) → a set of agent ids; `all` expands to every id.
2. Compute the **deduped** set of `(entryFile, contentSource)` pairs and the deduped set of
   skill trees. Selecting five `AGENTS.md` assistants writes `AGENTS.md` **once** and copies
   `.agents/skills/` **once**.
3. For each entry file: write the orchestrator content, honoring the **clobber guard** — if the
   file already exists and is not ours, refuse without `--force` (clean one-line message
   pointing to `update`/`--force`). Files in nested dirs (`.windsurf/rules/…`, `.clinerules/…`,
   `.github/…`) get their parent dirs created.
4. For each skill tree: copy every `SKILL.md` into `<tree>/skills/<name>/SKILL.md`.
5. **Scope:** `project` → `cwd`; `global` → `$HOME` for skill trees, entry files skipped
   (unchanged semantics; entry files remain project-scoped). `--target` overrides.

## CLI UX

ASCII wordmark banner (dependency-free; colors from clack's palette):

```text
 ___  _   ___ _____   ___ _  _____ _    _    ___
/ __|/_\ / __|_   _| / __| |/ /_ _| |  | |  / __|
\__ \ _ \\__ \ | |   \__ \ ' < | || |__| |__\__ \
|___/_/ \_\___/ |_|   |___/_|\_\___|____|____|___/
 Turn your AI coding assistant into a SAST scanner
 github.com/mstfknn/sast-skills · 31 skills, 28 classes
```

Flow:

1. Banner.
2. `intro("sast-skills installer vX.Y.Z")`.
3. `multiselect` — "Which assistants should sast-skills install for?" listing all 14 labels
   plus a final **"✨ All of the above"** option (selecting it expands to every agent).
4. `select` — scope: `This project (./)` / `Global (~)`.
5. `note` — the plan: deduped entry files + skill trees with counts.
6. `spinner` during copy.
7. `outro` — "Installed for N assistants. Prompt your assistant: 'Run vulnerability scan'."
   If Aider was selected, append: "Aider: add `--read CONVENTIONS.md` or set it in
   `.aider.conf.yml`."
8. Ctrl+C → `isCancel` → clean exit.

## Flag Interface (non-interactive)

- `--assistant <comma-list>` — agent ids, plus `all`, plus legacy `claude` / `agents`.
  Example: `--assistant claude,cursor,copilot`.
- Unknown id → clean validation error listing valid ids.
- `--scope`, `--target`, `--force`, `--dry-run`, `--yes` unchanged.

## `update` — Auto-Detect

`update` continues to delegate to `install --force`, but first **auto-detects** what is already
installed in the target and refreshes only that:

- An entry file is "installed" if it exists **and** its content carries the orchestrator
  signature (e.g. the `# SAST Security Assessment` header) — so a user-authored `AGENTS.md`
  that isn't ours is never clobbered.
- A skill tree is "installed" if `<tree>/skills/` contains `sast-*` skill dirs.
- Refresh every detected entry file + skill tree from the bundle.
- If nothing is detected → clean message: "No sast-skills install found here — run
  `npx sast-skills install`." (non-zero exit).
- `update --assistant <list>` still allows explicit targeting (skips auto-detect).

## doctor / uninstall

Both consume the same registry. `doctor --assistant <id>` verifies that agent's entry file and
skill tree against the bundle (`OK` / `MISSING` / `MODIFIED`). `uninstall --assistant <id>`
removes them, keeping the existing "won't drop a modified entry file without `--force`" rule.

## README / Docs

- Update the supported-assistants line to the 14 assistants.
- CLI flags table: `--assistant` is now a comma-list of ids.
- Manual-install section: drop the "rename AGENTS.md → GEMINI.md" hack (we write `GEMINI.md`).
- Keep `docs-completeness` / `release-readiness` README assertions green.

## Open Question / Refinement

The `AGENTS.md` orchestrator currently says "run the named skill". Assistants without skill
auto-discovery (Copilot, Windsurf, Cline) rely on reading the skill file by path. Consider
making the orchestrator reference `.agents/skills/<skill>/SKILL.md` explicitly so those
assistants can load skill detail deterministically. Tracked as a follow-up; not required for
the installer mechanics in this spec.

## Testing (TDD)

- **Registry:** every entry has non-empty `id`/`label`/`entryFile`/`skillTree`; ids unique.
- **Install:** single agent writes its entry + tree; multiple `AGENTS.md` agents dedupe to one
  `AGENTS.md` + one `.agents/skills/`; Copilot → `.github/copilot-instructions.md`; Gemini →
  `GEMINI.md`; `all` → every entry file + both trees; clobber guard per entry; entry content
  comes from the correct source (`CLAUDE.md` vs `AGENTS.md`).
- **Flags:** comma-list parsing; unknown id errors; backward-compat `agents` / `all` / `claude`.
- **Interactive:** multiselect renders 14 + "All of the above"; "All" expands to every agent.
- **update:** auto-detects an existing install and refreshes only it; leaves a user-authored
  non-ours `AGENTS.md` untouched; "nothing installed" message when empty; `--assistant` still
  targets explicitly.
- **doctor/uninstall:** registry-aware per the existing OK/MISSING/MODIFIED and refuse-to-clobber
  contracts.
