# Milestone 0 — Infra (detailed plan)

Prerequisite for the skill expansion. Three platform changes that are far cheaper to do
once, up front, than to retrofit across 35 new skills. See [../ROADMAP.md](../ROADMAP.md).

---

## 0.1 — Findings schema v2

### Scope

Add two cross-cutting fields every skill and the report/triage/export stages can use:
`exploitability` (is the sink reachable from untrusted input?) and `chain_id` (links findings
that compose into one attack). Bump the schema so consumers can tell v1 from v2.

### Schema delta (added to every finding)

| Field | Type | Values | Who sets it |
|---|---|---|---|
| `exploitability` | enum | `reachable` · `conditional` · `unreachable` · `unknown` | the detection skill's verify phase |
| `confidence` | enum | `high` · `medium` · `low` | the detection skill |
| `chain_id` | string \| null | stable id shared by findings in one chain | `sast-report` / `sast-triage` |

Run envelope: `run.schema` bumps to `"2.0"`; `run.tool`/`run.version` unchanged.

```jsonc
{
  "run": { "tool": "sast-skills", "version": "0.3.0", "schema": "2.0" },
  "findings": [
    {
      "id": "sast-sqli-0001", "skill": "sast-sqli", "severity": "high",
      "title": "...", "description": "...", "location": { "file": "...", "line": 42, "column": 10 },
      "remediation": "...",
      "exploitability": "reachable", "confidence": "high", "chain_id": null
    }
  ]
}
```

### Work items

- [ ] Update the canonical schema block in `sast-files/CLAUDE.md` and `sast-files/AGENTS.md` (the "Canonical JSON output" section) to v2; document the three new fields and that they are optional-but-recommended.
- [ ] `src/commands/export.js`: read `exploitability`/`confidence`/`chain_id` when present; emit `run.schema`; map `exploitability` to a SARIF property (`properties.exploitability`) and keep SARIF `level` from `severity`. Tolerate v1 inputs (missing fields → omit).
- [ ] `sast-files/.claude/skills/sast-report/SKILL.md` + `sast-triage`: rank by (severity × exploitability); a `triage_status` of `false_positive` should usually pair with `exploitability: unreachable`.
- [ ] Backward compatibility: v1 finding files (no new fields) still aggregate and export — fields are additive, never required.

### Tests

- [ ] `test/export.test.js`: a finding with `exploitability`/`chain_id` round-trips to JSON; SARIF carries `properties.exploitability`; `run.schema` is `"2.0"`.
- [ ] `test/export.test.js`: a v1 finding (no new fields) still exports cleanly (no crash, fields omitted).
- [ ] `test/orchestrator-json-output.test.js`: the orchestrator schema doc lists `exploitability`, `confidence`, `chain_id`.

---

## 0.2 — Tech-stack router

### Scope

An orchestration layer (NOT a vuln skill) that runs before Step 2, detects the project's
stack(s), and triggers only the relevant detection skills with a framework profile injected.
Turns the flat ~63-skill parallel fan-out into a targeted subset — the difference between a
cheap scan and an unusable one.

### Detection inputs (read-only, fast)

| Stack | Markers |
|---|---|
| Node/Express/Nest | `package.json` deps (`express`, `@nestjs/*`, `fastify`), `tsconfig.json` |
| Python/Django/Flask/FastAPI | `pyproject.toml` / `requirements.txt` (`django`, `flask`, `fastapi`), `manage.py`, `settings.py` |
| Java/Spring | `pom.xml` / `build.gradle` (`spring-boot`, `struts`), `application.yml` |
| Ruby/Rails | `Gemfile` (`rails`), `config/application.rb` |
| Go | `go.mod` |
| PHP/Laravel | `composer.json` (`laravel/framework`) |
| IaC / CI | `Dockerfile`, `*.tf`, `k8s` manifests, `.github/workflows/*` |
| LLM/agentic | deps (`openai`, `@anthropic-ai/sdk`, `langchain`, `llama-index`), `.mcp.json`, `CLAUDE.md`/`AGENTS.md` |

### Output → orchestrator

A `sast/stack.md` map: detected stacks, the skill set to run, and the profile id per skill.
The orchestrator's Step 2 reads it and **only** dispatches matching skills (e.g. skip
`sast-prototype` on a pure-Python repo; skip all LLM skills when no model SDK is present).

### Work items

- [ ] New recon skill `sast-stack` (or extend `sast-analysis`) that writes `sast/stack.md` with `{ stacks, skills, profiles }`.
- [ ] Restructure the orchestrator Step 2 in `CLAUDE.md`/`AGENTS.md`: replace the flat skill list with "run the skills named in `sast/stack.md`"; keep the idempotent skip-if-results-exist rule.
- [ ] Always-on skills (stack-independent): `sast-hardcodedsecrets`, `sast-deps`, `sast-iac`, `sast-pipelineinj`, `sast-crypto`.

### Tests

- [ ] A fixture repo with only `package.json` (express) yields a JS skill set and excludes Python-only skills.
- [ ] A repo with an LLM SDK includes the LLM/agentic skills; one without excludes them.
- [ ] `docs-completeness` still holds: every bundled skill is referenced (the router references the registry, not a hand list).

---

## 0.3 — Framework-awareness profiles

### Scope

Per-framework facts that let Tier-B skills suppress the false positives caused by safe
framework defaults. A profile is data, injected into a skill's verify phase — not new logic
per framework.

### Profile shape

`sast-files/profiles/<framework>.md` (mirrored to both trees, or a single shared `profiles/`):

```text
profiles/
├── django.md     # ORM parameterizes by default; `.raw()`/`.extra()` are the real SQLi sinks
├── spring.md     # Spring Data repositories are safe; `@Query` with concat is the sink
├── express.md    # helmet defaults set security headers; flag only when helmet is absent/overridden
├── rails.md      # strong params guard mass-assignment; flag models bypassing `permit`
└── fastapi.md    # Pydantic validates input; raw `Request.body()` parsing is the gap
```

Each profile lists, per relevant skill: **what the framework makes safe** (FP-killer) and
**what remains a real sink**.

### Work items

- [ ] Author the 5 starter profiles above; decide single shared `profiles/` vs per-tree mirror (prefer shared, add to `package.json` `files`).
- [ ] Teach `sast-analysis` / the router to record the active profile id per skill in `sast/stack.md`.
- [ ] Update Tier-B skill bodies (as they're authored) to read `sast/stack.md` and apply the profile in verify.

### Tests

- [ ] `package-contents.test.js`: profiles ship in the npm tarball.
- [ ] A profile doc exists for each framework the router can detect (parity test).

---

## Exit criteria for Milestone 0

- Schema v2 documented + `export`/`report`/`triage` consume the new fields; v1 still works.
- Router writes `sast/stack.md`; orchestrator Step 2 is router-driven; always-on set defined.
- 5 framework profiles ship and are wired into the router output.
- Full suite green; no skill bodies changed yet (that's M1+).
