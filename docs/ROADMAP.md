# sast-skills Roadmap

> ✅ **Roadmap complete (v0.8.0).** All Milestones 0–4 and the Backlog have shipped — the
> bundle grew from **28 → 68 skills across 64 vulnerability classes**. The per-milestone
> sections below are kept as the historical plan with shipped-version markers.

Derived from the consolidated skill catalog. Started at **28 shipped skills**; delivered
**40 new detection skills** across 4 milestones plus the backlog, and **3 architecture
initiatives** (schema v2 · tech-stack router · framework profiles). Each skill is mapped to
an OWASP framework and a SAST-applicability **tier**:

- **A — clean static** (taint / AST / config-match, low false-positive). Reliable; build first.
- **B — static + framework-awareness** (needs framework defaults or false positives explode).
- **C — LLM-driven semantic** (needs natural-language reasoning; high FP, aggressive triage required).

Frameworks: `Web25` OWASP Top 10:2025 · `API23` API Security Top 10:2023 ·
`LLM25` LLM Apps 2025 · `ASI26` Agentic Apps 2026 · `Skills26` Agentic Skills Top 10.

## The per-skill task (repeat for every `sast-<x>`)

1. `node scripts/scaffold-skill.js sast-<x>` — stub in both trees.
2. `node scripts/register-skill.js sast-<x> <x> "<Label>" "<one-line description>"` — patches `sast-files/CLAUDE.md`, `sast-files/AGENTS.md`, `README.md`.
3. Write the real `SKILL.md` body (recon → batched verify → merge), framework-aware, using `sast-sqli` as the template. **This is the bulk of the work** — each body is a full detection spec.
4. `npm run sync` then `npm test` — the contract tests confirm the mirror, docs coverage, and frontmatter.

> Sub-detectors do **not** get their own skill (avoid fragmentation): weak PRNG / weak hash / ECB / IV reuse / key management stay inside `sast-crypto`; blind/internal/redirect SSRF stay inside `sast-ssrf`.

## Detailed milestone plans

Per-milestone specs (scope · sinks · verify · test) live under `roadmap/`:

- [Milestone 0 — Infra](roadmap/milestone-0-infra.md) (schema v2 · router · framework profiles) — ✅ shipped v0.3.0
- [Milestone 1 — Tier A](roadmap/milestone-1.md) (13 skills) — ✅ shipped v0.4.0
- [Milestone 2 — Agentic-skills security](roadmap/milestone-2.md) (4 skills) — ✅ shipped v0.5.0
- [Milestone 3 — API / auth depth](roadmap/milestone-3.md) (7 skills) — ✅ shipped v0.6.0
- [Milestone 4 — LLM / agentic semantic](roadmap/milestone-4.md) (6 skills) — ✅ shipped v0.7.0
- [Backlog](roadmap/milestone-backlog.md) (6 skills) — ✅ shipped v0.8.0

## Milestone 0 — Infra first (do before mass skill authoring)

Schema and orchestration changes are cheaper to do once, up front, than to retrofit across 35 skills.

- [x] **Findings schema v2** — add `exploitability` / `confidence` (is the sink reachable from untrusted input?) and `chain_id` to the canonical JSON. Bump `run.tool` schema, update `sast-skills export`, `sast-report`, `sast-triage`, and the orchestrator schema doc. — ✅ shipped v0.3.0
- [x] **Tech-stack router** — an orchestration layer (not a vuln skill) that detects the stack (Spring / Django / FastAPI / Express / Rails) and triggers only the relevant skills with a framework profile injected. **Prerequisite, not optional:** 28 → ~63 skills makes a flat parallel Step-2 fan-out cost- and latency-prohibitive. Restructure the orchestrator to be router-driven. — ✅ shipped v0.3.0
- [x] **Framework-awareness profiles** — Django ORM, Spring Data, Rails strong params, Express helmet defaults. Lifts precision of every Tier-B skill; eliminates most of their false positives. — ✅ shipped v0.3.0

## Milestone 1 — Clean static, high prevalence (Tier A, 13 skills)

| Skill | Class | Framework |
|---|---|---|
| `sast-errorhandling` | fail-open logic, stack-trace/secret leak, debug mode, swallowed catch | Web25 A10 |
| `sast-massassign` | mass assignment / overposting (`is_admin`) | API23 API3 |
| `sast-excessivedata` | serializer returns the whole object | API23 API3 |
| `sast-deser` | insecure deserialization (Java gadget, pickle, PHP, .NET, Ruby, unsafe YAML) | Web25 A05 |
| `sast-tls` | cert/hostname verification disabled (`verify=False`, `InsecureSkipVerify`) | Web25 A02/A04 |
| `sast-cookieflags` | missing HttpOnly / Secure / SameSite | Web25 A02 |
| `sast-secheaders` | CSP / HSTS / X-Frame-Options / SRI; clickjacking | Web25 A02 |
| `sast-crlf` | CRLF / response splitting / header & host-header injection | Web25 A05 |
| `sast-zipslip` | archive-extraction path traversal | Web25 A01 |
| `sast-pipelineinj` | poisoned pipeline execution (`github.event.*` into `run:`) | Web25 A03 |
| `sast-depconfusion` | dependency confusion / typosquat / malicious install-script | Web25 A03 |
| `sast-dangerousapi` | eval / reflection / native / process-spawn sink inventory | Web25 A05 |
| `sast-ssrfimds` | cloud-metadata SSRF + IMDSv1 + cloud-context detection | Web25 A01 / API23 API7 |

- [x] Author all 13 (each = the per-skill task). `sast-deps` + `sast-depconfusion` + `sast-pipelineinj` together close Web25 **A03** — the highest-incidence, lowest-CVE-coverage category and the blind spot of signature scanners. — ✅ all 13 shipped (v0.3.0: `sast-deser` · `sast-errorhandling` · `sast-tls` · `sast-cookieflags`; v0.4.0: the remaining 9)

## Milestone 2 — Agentic-skills security (the niche; no standard scanner exists)

This surface is uniquely yours because the product *is* skills. Under active attack in 2026 Q1 (skill-registry poisoning; config-file RCE, e.g. CVE-2025-59536). Pattern-matching scanners miss most of this — **author with LLM-driven verify; pure regex gives false confidence.**

| Skill | Class | Framework | Tier |
|---|---|---|---|
| `sast-skillaudit` | hidden instructions / NL manipulation / shell sink in untrusted skill/agent config | Skills26 | C |
| `sast-mcpsec` | MCP tool poisoning, missing auth, over-permissioned tool schema | LLM25 / ASI26 / Skills26 | C |
| `sast-configrce` | repo-controlled config → execution layer (`CLAUDE.md`, `.mcp.json`, Actions) | Skills26 | B |
| `sast-agentidentity` | agent NHI (service account / token / key) over-scoped | ASI26 ASI03 | B |

- [x] Author all 4. — ✅ shipped v0.5.0

## Milestone 3 — API / auth depth (Tier B, framework-awareness needed)

| Skill | Class | Framework |
|---|---|---|
| `sast-ratelimit` | no route/framework-level rate limit (brute-force / DoS) | API23 API4 |
| `sast-session` | session fixation, predictable session id | Web25 A07 |
| `sast-oauth` | redirect_uri validation, missing state/PKCE, implicit flow | API23 API2 / Web25 A07 |
| `sast-routeinventory` | shadow/deprecated endpoint, exposed debug/admin route | API23 API9 |
| `sast-unsafeconsumption` | third-party API response reaching a sink unvalidated | API23 API10 |
| `sast-cloudsdk` | cloud SDK misuse, public bucket, hardcoded IAM credential | Web25 A02 |
| `sast-postmessage` | postMessage origin missing, CSWSH, tabnabbing | Web25 A01 |

- [x] Author all 7 (depends on Milestone 0 framework profiles for acceptable FP). — ✅ shipped v0.6.0

## Milestone 4 — LLM / agentic semantic (Tier C, heavy triage)

| Skill | Class | Framework |
|---|---|---|
| `sast-excessiveagency` | write/delete tool authority without human-in-the-loop; over-exposed tools | LLM25 LLM06 / ASI26 ASI02 |
| `sast-ragleak` | access-control-free doc into LLM context; indirect prompt injection | LLM25 LLM08 / LLM01 |
| `sast-systempromptleak` | secret in system prompt; prompt leaking to log/response | LLM25 LLM07 |
| `sast-toolcalling` | unsafe function/tool calling; over-permissioned tool schema | LLM25 LLM06 / ASI26 ASI02 |
| `sast-memorypoison` | untrusted data written to persistent agent memory | ASI26 ASI06 |
| `sast-llmdos` | no `max_tokens`, recursive agent loop, denial-of-wallet | LLM25 LLM10 |

- [x] Author all 6. Consider gating these behind the router so they never run on non-LLM codebases. — ✅ shipped v0.7.0 (`sast-stack` lists all six in its LLM/agent-skip set)

## Backlog — catalogued, lower priority

| Skill | Class | Framework | Tier |
|---|---|---|---|
| `sast-xpath` | XPath injection | Web25 A05 | A |
| `sast-csvinj` | formula / CSV injection (export flows) | Web25 A05 | A |
| `sast-xmlbomb` | XML entity-expansion DoS (billion laughs) | Web25 A10 | A |
| `sast-elinj` | EL / OGNL / SpEL expression injection | Web25 A05 | A |
| `sast-lockfile` | lockfile integrity / pinning / unverified source | Web25 A03 | A |
| `sast-paymentlogic` | e-commerce payment/coupon/wallet/refund abuse | API23 API6 | C |

- [x] Pull into a milestone when capacity allows. `sast-paymentlogic` is the *only* business-logic split worth making — keep everything else inside `sast-businesslogic` with domain heuristics (the 6-way payment/coupon/wallet/refund/loyalty/race split is over-fragmentation). — ✅ all 6 shipped v0.8.0 (`sast-xpath`, `sast-csvinj`, `sast-xmlbomb`, `sast-elinj`, `sast-lockfile`, `sast-paymentlogic`)

## Cross-skill correlation (export, after schema v2)

With `chain_id` in the schema, `sast-report` / `export` can surface attack chains:

- `sast-ssrfimds` + `sast-cloudsdk` → cloud takeover
- `sast-routeinventory` (API9) + `sast-ratelimit` (API4) → scraping / brute-force
- `sast-idor` + `sast-missingauth` → chained authz bypass
- `sast-toolcalling` (ASI02) + `sast-agentidentity` (ASI03) → agent privilege escalation

## Engineering notes & risks

- **Fan-out cost is the headline risk.** A flat 63-skill parallel Step 2 is unsustainable per scan — Milestone 0's router gates it. Sequence the router early, not "in parallel".
- **Tier C is triage-heavy.** Budget for aggressive `sast-triage`; these skills produce high FP and must justify exploitability before surfacing.
- **Contract tests stay green throughout.** `register-skill.js` handles the orchestrator/README boilerplate; the two-tree sync + `docs-completeness` + `skill-schema` tests enforce consistency. Re-run `npm run sync` after every skill.
- **No sub-detector skills.** Crypto and SSRF variants stay inside their parent skill — enforce by simply not scaffolding them.
- **Schema bump touches everything.** Doing `exploitability`/`chain_id` in Milestone 0 avoids retrofitting 35 skills' JSON output later.

## Suggested order

Milestone 0 (infra) → Milestone 1 (Tier A value) → Milestone 2 (niche differentiation) →
Milestone 3 (Tier B) → Milestone 4 (Tier C) → Backlog. Architecture initiatives in Milestone 0
unblock the rest.
