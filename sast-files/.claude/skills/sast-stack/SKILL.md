---
name: sast-stack
description: >-
  Detect the project's technology stack(s) and frameworks, then decide which
  detection skills are worth running and which framework profile applies to
  each. Writes sast/stack.md — the routing map the orchestrator uses to run a
  targeted subset of skills instead of all of them. Run after sast-analysis and
  before the parallel vulnerability scan. Use to keep scans fast and to avoid
  running irrelevant skills (e.g. JS-only checks on a pure-Python repo).
version: 0.1.0
---

# sast-stack — Tech-stack router

The router turns a flat "run every skill" scan into a targeted one. It reads the
project's manifests, picks the detection skills that can actually find something in
this codebase, attaches the right framework profile to each, and records the decision
in `sast/stack.md`. The orchestrator's parallel scan then runs only the selected
skills.

## Why this exists

Running all ~60 detection skills on every repo is slow and noisy: prototype-pollution
checks on a Python repo, LLM-output checks with no model SDK present, JWT checks with no
tokens anywhere. The router avoids that work and raises precision by injecting
framework-default knowledge (a Django ORM parameterizes by default; Express with helmet
already sets security headers).

## Step 1: Detect stacks

Inventory the manifests and entry points (read-only, fast). Detect every stack present —
a repo can have several (a Python API + a React frontend + Terraform).

| Stack | Markers |
|-------|---------|
| Node / Express / Nest / Fastify | `package.json` deps, `tsconfig.json`, `*.ts`/`*.js` |
| Python / Django / Flask / FastAPI | `pyproject.toml`, `requirements.txt`, `manage.py`, `settings.py` |
| Java / Spring / Struts | `pom.xml`, `build.gradle`, `application.yml` |
| Ruby / Rails | `Gemfile`, `config/application.rb` |
| Go | `go.mod` |
| PHP / Laravel | `composer.json` |
| .NET | `*.csproj`, `*.sln` |
| IaC / containers | `Dockerfile`, `*.tf`, `*.yaml` k8s manifests, `docker-compose.yml` |
| CI/CD | `.github/workflows/*`, `.gitlab-ci.yml` |
| LLM / agentic | deps (`openai`, `@anthropic-ai/sdk`, `langchain`, `llama-index`), `.mcp.json`, `CLAUDE.md` / `AGENTS.md` |

## Step 2: Select skills

For each detected stack, include the detection skills that have a real sink surface in
that stack, and exclude the rest. Map the framework to a profile id when one exists
(`profiles/<framework>.md`).

**Always-on** (stack-independent — never skip): `sast-hardcodedsecrets`, `sast-deps`,
`sast-iac`, `sast-pipelineinj`, `sast-crypto`.

**Skip when absent**, for example:

- No LLM/agent SDK → skip every LLM/agentic skill (`sast-promptinjection`, `sast-llmoutput`, …).
- No JS/TS → skip `sast-prototype`.
- No XML parsing/serialization → de-prioritize `sast-xxe`.
- No JWT/session/cookie usage → de-prioritize `sast-jwt`, `sast-cors`, `sast-csrf`.

When in doubt, include the skill — a skipped skill finds nothing, but the goal is to
drop only the clearly-irrelevant ones.

## Step 3: Write `sast/stack.md`

Write a single machine-and-human-readable file the orchestrator reads:

```json
{
  "stacks": ["python-django", "iac-terraform"],
  "skills": [
    { "skill": "sast-sqli", "profile": "django" },
    { "skill": "sast-missingauth", "profile": "django" },
    { "skill": "sast-iac", "profile": null }
  ],
  "always_on": ["sast-hardcodedsecrets", "sast-deps", "sast-iac", "sast-pipelineinj", "sast-crypto"],
  "skipped": [
    { "skill": "sast-prototype", "reason": "no JS/TS in project" },
    { "skill": "sast-llmoutput", "reason": "no LLM SDK present" }
  ]
}
```

Record a one-line reason for every skipped skill so the decision is auditable — never
drop a skill silently.
