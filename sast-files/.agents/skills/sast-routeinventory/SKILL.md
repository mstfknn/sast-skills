---
name: sast-routeinventory
description: >-
  Detect shadow, debug, and admin routes that are registered in the running
  application but absent from the published API specification, marked deprecated
  yet still active, or reachable without authentication from a public network.
  Uses a three-phase approach: recon (enumerate every registered route and its
  auth posture), batched verify (parallel subagents, 3 routes each, confirm
  reachability and spec coverage), and merge (consolidate into
  sast/routeinventory-results.md and sast/routeinventory-results.json). Covers
  Express, Django, Spring Boot, FastAPI, and Rails. Maps to API9:2023 and
  CWE-1059. Run after sast-missingauth for maximum chain coverage.
version: 0.1.0
---

# Shadow / Debug / Admin Route Inventory

You are performing a focused security assessment to find **undocumented, deprecated-but-active, and unauthenticated debug or admin routes** registered in the application. These routes are a recurring source of information disclosure and unauthorized access: they exist in running code but are invisible to API consumers, security reviewers, and automated scanners that only look at the published OpenAPI specification.

This skill uses a three-phase approach with subagents: **recon** (enumerate every registered route and note its auth posture and spec coverage), **batched verify** (check reachability and true risk in parallel batches of 3 routes each), and **merge** (consolidate batch results into the final human report and canonical JSON output).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it does not.

---

## What This Skill Covers

### Shadow Routes
Routes registered in the application router but **absent from the published OpenAPI / Swagger specification**. Consumers, pentesters, and security tooling that walk the spec never see these routes. They may expose internal APIs, admin panels, or debug tooling.

### Debug / Internal Routes Left in Production
Routes whose path, handler name, or surrounding comment signals that they were intended for development only (`/debug`, `/_internal`, `/test`, `/actuator`, `/console`, `/__inspect__`). Shipping them to production creates a persistent attack surface.

### Deprecated Routes Still Returning Data
Routes flagged with a code comment (`// TODO: remove`, `# deprecated`, `@Deprecated`) or a documentation annotation (`x-deprecated: true`) but still fully operational. Deprecation without removal is not a security control.

### What This Skill Is NOT

Do not flag:

- Intentionally public health probes (`/health`, `/ping`, `/status`) that are explicitly documented or exempted by a network policy.
- Admin routes correctly protected by authentication middleware **and** IP allowlist **and** present in the OpenAPI spec (even with `x-internal: true`).
- Routes present in the spec with a documented deprecation notice **and** a concrete removal timeline.
- Routes whose only reachability is via an internal Kubernetes `ClusterIP` service blocked by a NetworkPolicy documented in IaC.

---

## Vulnerability Classes

### Class 1: Unauthenticated Debug / Admin Route
A route whose path or handler signals privileged or internal use (`/debug`, `/admin`, `/internal`, `/actuator`) that requires **no authentication whatsoever**. Any anonymous HTTP request can reach it.

```
GET /debug/users         → returns full DB dump, no token required
GET /actuator/env        → returns all environment variables including secrets
GET /rails/info/properties → returns Ruby and Rails version, installed gems
```

### Class 2: Shadow Route (Not in OpenAPI Spec)
A route registered in the router that does **not appear in the published API specification**. The route may or may not require authentication — the risk is invisibility: it cannot be audited, fuzzed, or rate-limited by tooling that reads the spec.

```
GET /internal/metrics    → registered in Express but absent from openapi.yaml
POST /admin/impersonate  → registered in Spring Boot but not in the Swagger spec
DELETE /_debug/flush     → registered in FastAPI but not under any APIRouter with include_in_schema=True
```

### Class 3: Deprecated Route Still Active
A route annotated or commented as removed or deprecated but still returning real data. The annotation creates a false sense of security in code review; the route is live in production.

```javascript
// TODO: remove this before launch
app.get('/debug/users', (req, res) => res.json(db.users.findAll()));
```

```python
# DEPRECATED — remove in Q2
@app.get('/internal/jobs', include_in_schema=False)
async def list_jobs(): ...
```

### Class 4: Overly-Exposed Actuator / Management Endpoints
Spring Boot Actuator (and equivalents) endpoints enabled with a wildcard exposure rule, making endpoints like `/actuator/env`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/shutdown` publicly reachable.

```yaml
# application.yml — VULNERABLE
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

---

## Patterns That PREVENT Vulnerabilities

When you see these patterns, the route is likely **not vulnerable**:

**1. Auth middleware on the route group, admin path already in spec**
```javascript
// Express — entire /admin group is protected and documented
router.use('/admin', auth, requireRole('admin'));
// openapi.yaml has /admin/stats with securitySchemes: [bearerAuth]
```

**2. Build-time guard removes the route in production**
```javascript
if (process.env.NODE_ENV !== 'production') {
  app.use('/debug', debugRouter);
}
```

**3. `include_in_schema=False` + `Depends(require_admin)` (FastAPI)**
```python
@router.get('/internal/metrics', include_in_schema=False, dependencies=[Depends(require_admin)])
async def internal_metrics(): ...
# Not in spec (intentional), but protected — internal-only, acceptable
```

**4. Spring Boot Actuator scoped exposure**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    health:
      show-details: never
```

**5. Rails route with `constraints` IP restriction**
```ruby
get '/sidekiq', to: Sidekiq::Web, constraints: ->(req) { req.ip == '127.0.0.1' }
```

**6. Route present in OpenAPI spec with `x-internal: true` and removal milestone**
```yaml
paths:
  /internal/report:
    get:
      x-internal: true
      x-deprecated-removal: "2026-Q3"
      security:
        - bearerAuth: [admin]
```

---

## Vulnerable vs. Secure Examples

### Node.js — Express

```javascript
// VULNERABLE: debug route, no auth, no build guard, not in spec
app.get('/debug/users', (req, res) => res.json(db.users.findAll()));

// VULNERABLE: deprecated comment but still live
// TODO: remove before production deploy
app.get('/internal/config', (req, res) => res.json(process.env));

// SECURE: guarded by build-time env check
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug/users', (req, res) => res.json(db.users.findAll()));
}

// SECURE: admin route present in spec and behind auth + role middleware
router.use('/admin', auth, requireRole('admin'));
router.get('/admin/stats', statsHandler); // documented in openapi.yaml
```

### Python — FastAPI

```python
# VULNERABLE: debug router included unconditionally
from debug import debug_router
app.include_router(debug_router)  # no settings.debug guard

# VULNERABLE: internal route, no Depends, not in schema
@app.get('/internal/jobs')
async def list_jobs():
    return await db.jobs.all()

# SECURE: conditional inclusion
if settings.debug:
    app.include_router(debug_router)

# SECURE: protected + excluded from spec (intentionally internal)
@router.get('/internal/metrics', include_in_schema=False, dependencies=[Depends(require_admin)])
async def internal_metrics():
    return await collect_metrics()
```

### Python — Django

```python
# VULNERABLE: debug view in production URL config
# urls.py
if True:  # BUG: was `settings.DEBUG` but got hardcoded
    urlpatterns += [path('debug/sql/', views.debug_sql)]

# VULNERABLE: internal admin view, no staff check
def internal_admin(request):
    return JsonResponse({'users': list(User.objects.values())})

# SECURE: guard with settings.DEBUG
if settings.DEBUG:
    urlpatterns += [path('debug/sql/', views.debug_sql)]

# SECURE: staff-only admin view
@login_required
def internal_admin(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    return JsonResponse({'users': list(User.objects.values())})
```

### Java — Spring Boot

```java
// VULNERABLE: actuator wildcard exposure
// application.yml: management.endpoints.web.exposure.include=*
// Result: /actuator/env, /actuator/heapdump, /actuator/shutdown all public

// VULNERABLE: debug controller, no PreAuthorize
@RestController
@RequestMapping("/debug")
public class DebugController {
    @GetMapping("/threads")
    public Map<Thread, StackTraceElement[]> dumpThreads() {
        return Thread.getAllStackTraces();
    }
}

// SECURE: Actuator scoped exposure
// application.yml:
// management.endpoints.web.exposure.include=health,info

// SECURE: admin controller with role annotation
@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("/stats")
    public StatsDto getStats() { return statsService.collect(); }
}
```

### Ruby on Rails

```ruby
# VULNERABLE: Sidekiq Web UI mounted without auth
mount Sidekiq::Web => '/sidekiq'

# VULNERABLE: letter_opener mounted in non-development config
# config/routes.rb (production)
mount LetterOpenerWeb::Engine, at: '/letter-opener'

# VULNERABLE: admin route without authenticate_admin!
get '/admin/reports', to: 'admin/reports#index'

# SECURE: Sidekiq behind Devise admin auth
authenticate :admin_user do
  mount Sidekiq::Web => '/sidekiq'
end

# SECURE: letter_opener only in development
if Rails.env.development?
  mount LetterOpenerWeb::Engine, at: '/letter-opener'
end

# SECURE: admin route with before_action
namespace :admin do
  before_action :authenticate_admin!
  resources :reports, only: [:index]
end
```

---

## Severity Guidance

| Scenario | Default Severity |
|---|---|
| Debug/admin route with no auth, returns config or secrets | **critical** |
| Spring Boot `/actuator/env` or `/actuator/heapdump` unauthenticated | **critical** |
| Rails `/sidekiq`, `/rails/info`, `/letter-opener` unauthenticated | **critical** |
| Shadow route allows data mutation without auth | **high** |
| Debug route returns internal data (stack traces, DB rows) without auth | **high** |
| Shadow route present but read-only and behind auth | **medium** |
| Deprecated route still active, returns non-sensitive data | **medium** |
| Route missing from spec but protected and read-only | **low** |
| Route in spec with `x-internal` but no removal timeline | **info** |

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Enumerate Routes and OpenAPI Coverage

Launch a subagent with the following instructions:

> **Goal**: Build a complete inventory of every registered HTTP route in the application, note its authentication posture, and cross-reference each against the published OpenAPI / Swagger specification. Write results to `sast/routeinventory-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, router entry points, OpenAPI spec location, and auth strategy.
>
> **Step A — Locate the OpenAPI specification** (do this first):
> Look for: `openapi.yaml`, `openapi.json`, `swagger.yaml`, `swagger.json`, `docs/openapi*`, `static/swagger*`, `src/openapi*`. If using FastAPI, the spec is auto-generated at `/openapi.json`; note the router configuration to infer what is included. If no spec exists, note its absence — that itself makes all routes "shadow routes" by definition.
>
> **Step B — Enumerate all registered routes**:
>
> Search for route registration patterns per framework:
>
> - **Express / Node.js**:
>   - `app.get(`, `app.post(`, `app.put(`, `app.delete(`, `app.patch(`, `app.use(`
>   - `router.get(`, `router.post(`, `router.delete(`, `router.use(`
>   - `app.use('/prefix', router)` — trace the prefix chain
>   - Paths matching: `/debug`, `/admin`, `/internal`, `/test`, `/_`, `/actuator`, `/console`, `/health`, `/metrics`, `/inspect`
>   - Comments near route definition: `// TODO`, `// deprecated`, `// remove`, `// temp`, `// FIXME`
>
> - **Django**:
>   - `urlpatterns` lists in `urls.py`
>   - `path()`, `re_path()`, `include()` — trace `include()` chains recursively
>   - URL names containing `debug`, `admin`, `internal`, `test` (excluding `django.contrib.admin`)
>   - Views decorated with nothing (no `@login_required`) that map to sensitive-looking URLs
>   - `DEBUG=True` in `settings.py` and any URL patterns conditionally registered on it (note if the guard was accidentally removed)
>
> - **Spring Boot**:
>   - `@GetMapping`, `@PostMapping`, `@PutMapping`, `@DeleteMapping`, `@PatchMapping`, `@RequestMapping`
>   - `@RestController` classes with path prefixes `/debug/**`, `/admin/**`, `/internal/**`, `/actuator/**`
>   - `application.yml` / `application.properties`: `management.endpoints.web.exposure.include` — note if `*` or a large list
>   - `@Deprecated` on controller methods that are still mapped
>
> - **FastAPI**:
>   - `@app.get(`, `@app.post(`, `@app.delete(`, `@app.put(`
>   - `router.include_router(`, `app.include_router(` — note if inside `if settings.debug:` or unconditional
>   - `include_in_schema=False` — these routes are intentionally hidden from the spec; note whether they also have `Depends(require_admin)` or similar
>   - Path prefixes `/internal/`, `/debug/`, `/admin/`
>
> - **Rails**:
>   - `routes.rb`: `get`, `post`, `resources`, `resource`, `namespace`, `scope`, `mount`, `draw`
>   - `mount` targets: Sidekiq::Web, LetterOpenerWeb::Engine, PgHero::Engine, Blazer::Engine, RailsAdmin::Engine
>   - Routes missing `before_action :authenticate_user!` or `before_action :authenticate_admin!`
>   - Routes missing `constraints(host:)` or `constraints(ip:)` restrictions
>
> **Step C — Cross-reference against the OpenAPI spec**:
>
> For each route found in Step B, check whether the path + HTTP method appears in the OpenAPI spec:
>
> - If no spec exists: mark ALL routes as "absent from spec"
> - If a spec exists: compare normalized paths (strip trailing slashes, normalize `{id}` vs `:id` vs `<int:pk>` to `{param}`)
> - Mark each route: **in-spec**, **absent-from-spec**, or **deprecated-in-spec**
>
> **Step D — Note authentication posture for each route**:
>
> - Is there an auth middleware, decorator, or guard applied?
> - Is there a role/permission check?
> - Does the path or handler name suggest it is a debug/admin/internal endpoint?
>
> **Output format** — write to `sast/routeinventory-recon.md`:
>
> ```markdown
> # Route Inventory Recon: [Project Name]
>
> ## OpenAPI Spec
> - Location: [path or "NOT FOUND"]
> - Total paths in spec: [N]
>
> ## Route Inventory
>
> ### 1. [Route description]
> - **File**: `path/to/routes.ext` (line X)
> - **Route**: `METHOD /path/to/route`
> - **Handler**: `ControllerName#action` or `handlerFunctionName`
> - **In OpenAPI spec**: yes | no | deprecated
> - **Auth present**: yes | no | partial
> - **Role check present**: yes | no
> - **Debug/admin path**: yes | no
> - **Deprecation comment / annotation**: [quote the comment, or "none"]
> - **Risk signals**: [list: no-auth + admin-path, TODO-remove comment, actuator wildcard, etc.]
> - **Code snippet**:
>   ```
>   [route registration line + auth middleware chain]
>   ```
>
> [Repeat for each suspicious route. Skip routes that are: in-spec + auth-present + no debug signal.]
> ```

### Phase 2: Verify — Confirm Reachability and True Risk (Batched)

After Phase 1 completes, read `sast/routeinventory-recon.md` and split the route inventory into **batches of up to 3 routes each** (each numbered `### N.` under **Route Inventory**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned routes and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/routeinventory-recon.md` and count the numbered route sections under **Route Inventory** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 7 routes → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those route sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned routes.
5. Each subagent writes to `sast/routeinventory-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and include only the matching "Vulnerable vs. Secure Examples" section in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: Verify the following routes for shadow, debug, or unauthenticated admin route vulnerabilities. Write results to `sast/routeinventory-batch-[N].md`.
>
> **Your assigned routes** (from the recon phase):
>
> [Paste the full text of the assigned route sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand middleware ordering, auth strategy, build guards, and IaC network restrictions.
>
> **What to verify for each route**:
>
> **1. Is the route reachable unauthenticated from an external network?**
> - Is there an auth middleware / decorator / guard applied **before** the handler?
> - Trace the middleware chain: is auth applied to the route group or only some routes within it?
> - Check for build-time guards: `if (process.env.NODE_ENV !== 'production')`, `if settings.DEBUG:`, `if Rails.env.development?` — if present and correct, the route is a true negative
> - Check for network-level restrictions: `constraints(host: /internal\./)`, IP allowlists in nginx/Caddy config, k8s NetworkPolicy in IaC — if present and correctly scoped, the route is a true negative
>
> **2. Is the route absent from the OpenAPI specification?**
> - The recon phase already flagged this; confirm by checking the spec file if needed
> - A route with `include_in_schema=False` (FastAPI) is intentionally excluded; it is a true negative ONLY if it also has `Depends(require_admin)` or equivalent
> - A route present in the spec as `deprecated: true` with a removal milestone is a true negative
>
> **3. Does the route expose sensitive data or privileged actions?**
> - Path signals: `/debug`, `/admin`, `/internal`, `/actuator`, `/_`, `/console`, `/test`, `/inspect`, `/monitor`
> - Handler signals: `dumpThreads`, `debugSql`, `listAllUsers`, `envVars`, `flushCache`, `impersonate`
> - Does it return environment variables, secrets, stack traces, DB row dumps, user lists, or credentials?
> - Does it allow writes/deletes that affect other users or system configuration?
>
> **FP-killers — treat as NOT VULNERABLE if ALL apply**:
> - Auth middleware **confirmed** on this route or its parent group AND it runs before the handler
> - Role/permission check present (`@PreAuthorize("hasRole('ADMIN')")`, `Depends(require_admin)`, `before_action :authenticate_admin!`, `requireRole('admin')`)
> - Route present in OpenAPI spec (or intentionally excluded with `include_in_schema=False`) AND sensitive status is documented
> - Network-level restriction documented in IaC (NetworkPolicy, IP allowlist)
>
> **Severity assignment**:
> - `critical`: unauthenticated access to env vars, secrets, heap dump, thread dump, full admin console, shutdown endpoint, or user impersonation
> - `high`: unauthenticated debug route returning DB rows, internal config, or allowing mutation; authenticated shadow route allowing privileged mutation
> - `medium`: deprecated route still returning real data; shadow route present but read-only and behind auth
> - `low`: route in spec but missing deprecation timeline; route hidden from spec with proper auth
> - `info`: route in spec with `x-internal: true` but no removal milestone
>
> **Exploitability**:
> - `reachable`: route responds without credentials in a test/staging environment
> - `conditional`: route is accessible but only under conditions the attacker may or may not meet (e.g., requires knowledge of the path, no public documentation)
> - `unreachable`: route is network-restricted or guarded by a build-time check that is verified correct
> - `unknown`: cannot determine without runtime testing
>
> **Confidence**:
> - `high`: debug/admin in path, no auth decorator found anywhere in the chain, confirmed by reading the full middleware setup
> - `medium`: deprecated comment present and route is live, but auth status is partially ambiguous; or shadow route confirmed absent from spec but auth is present
> - `low`: middleware chain is complex and may have dynamic auth not visible in static analysis
>
> **Chain IDs**:
> - Use `"unauthenticated-admin"` when this route is also caught by sast-missingauth (no auth on admin/debug route)
> - Use `"data-exposure-debug"` when this route returns internal object data also caught by sast-excessivedata
> - Use `null` when no chain applies
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Output format** — write to `sast/routeinventory-batch-[N].md`:
>
> ```markdown
> # Route Inventory Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Route description
> - **File**: `path/to/file.ext` (line X)
> - **Route**: `METHOD /path`
> - **In OpenAPI spec**: yes | no | deprecated-no-timeline
> - **Auth present**: no | partial
> - **Severity**: critical | high | medium | low | info
> - **Issue**: [Shadow route / Unauthenticated debug route / Deprecated-but-active route / Actuator overexposure]
> - **Impact**: [What an external attacker can do — be specific: "returns all environment variables including DATABASE_URL and SECRET_KEY", "allows creating admin accounts without authentication"]
> - **Proof**:
>   ```
>   [route definition + handler code showing the vulnerability — highlight the missing auth or spec gap]
>   ```
> - **Remediation**: [Specific fix — add build guard, add auth middleware, add to spec, restrict actuator exposure]
> - **Dynamic Test**:
>   ```
>   # Confirm route is unauthenticated (replace <HOST> with the app's base URL):
>   curl -s -o /dev/null -w "%{http_code}" http://<HOST>/debug/users
>   # Expected for vulnerable: 200
>   # Expected for fixed: 401 or 404
>   ```
>
> ### [LIKELY VULNERABLE] Route description
> - **File**: `path/to/file.ext` (line X)
> - **Route**: `METHOD /path`
> - **In OpenAPI spec**: yes | no
> - **Auth present**: partial
> - **Severity**: high | medium
> - **Issue**: [What is incomplete — e.g., auth middleware present but role check missing; deprecated annotation but route still active]
> - **Concern**: [Why this might still be exploitable despite partial protection]
> - **Proof**:
>   ```
>   [code path showing the partial or bypassable check]
>   ```
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl command or step-by-step to confirm on the live app]
>   ```
>
> ### [NOT VULNERABLE] Route description
> - **File**: `path/to/file.ext` (line X)
> - **Route**: `METHOD /path`
> - **Protection**: [How it is protected — build guard confirmed / auth + role check / network-restricted / spec-documented with removal timeline]
>
> ### [NEEDS MANUAL REVIEW] Route description
> - **File**: `path/to/file.ext` (line X)
> - **Route**: `METHOD /path`
> - **Uncertainty**: [Why static analysis cannot determine the status — e.g., dynamic route registration, auth injected via DI container, middleware loaded from external config]
> - **Suggestion**: [What to check manually — e.g., trace the DI binding, check the k8s NetworkPolicy, test the endpoint in staging]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/routeinventory-batch-*.md` file and merge them into `sast/routeinventory-results.md` (human-readable) and `sast/routeinventory-results.json` (canonical schema). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/routeinventory-batch-1.md`, `sast/routeinventory-batch-2.md`, ... files.
2. Collect all findings from each batch, preserving all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human report to `sast/routeinventory-results.md`:

```markdown
# Route Inventory Analysis Results: [Project Name]

## Executive Summary
- Routes analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- OpenAPI spec found: yes | no

## Findings

[All findings grouped: VULNERABLE first (by severity, critical → high → medium → low → info),
 then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical JSON output to `sast/routeinventory-results.json`. If no findings, write `{"findings": []}`. For each finding, use the exact schema:

```json
{
  "findings": [
    {
      "id": "routeinventory-1",
      "skill": "sast-routeinventory",
      "severity": "critical",
      "title": "Unauthenticated /debug/users route exposes full user database",
      "description": "The route GET /debug/users is registered unconditionally in app.js with no auth middleware and no build-time guard. It returns the result of db.users.findAll() including hashed passwords, email addresses, and role flags. The route is absent from the OpenAPI specification. Any unauthenticated HTTP client can retrieve the full user table.",
      "location": { "file": "src/app.js", "line": 42, "column": 1 },
      "remediation": "Wrap the route registration in `if (process.env.NODE_ENV !== 'production') { ... }` or remove it entirely. If a debug endpoint is required in non-production environments, ensure it returns mock data only and is listed in the spec.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "unauthenticated-admin"
    }
  ]
}
```

6. After writing both result files, **delete all intermediate files**: `sast/routeinventory-recon.md` and all `sast/routeinventory-batch-*.md` files.

---

## Chain ID Reference

| chain_id | Meaning | Co-occurring skill |
|---|---|---|
| `unauthenticated-admin` | Route is a shadow/debug/admin route with no authentication | sast-missingauth |
| `data-exposure-debug` | Route returns internal object data (env vars, DB rows, stack traces) | sast-excessivedata |
| `null` | Finding does not compose with another skill's finding | — |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 routes per subagent**. If there are 1–3 routes total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned route sections, not the entire recon file.
- The OpenAPI spec is the source of truth for "is this route documented". No spec = all routes are shadow routes.
- Build-time guards (`if (process.env.NODE_ENV !== 'production')`) are a valid mitigation — confirm the guard is present and correct before marking as NOT VULNERABLE.
- Middleware order matters: a guard registered after the route handler will NOT protect the route.
- A comment saying `// deprecated` does not remove a route. Only a removed route registration is a true negative.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Spring Boot Actuator with `management.endpoints.web.exposure.include=*` is always **critical** unless all actuator endpoints are behind Spring Security with an `ADMIN` role requirement.
- Rails engines (`Sidekiq::Web`, `PgHero::Engine`, `Blazer::Engine`, `LetterOpenerWeb::Engine`) mounted without authentication are **critical** findings.
- Always emit `sast/routeinventory-results.json` even when there are zero findings — write `{"findings": []}` so the `sast-skills export` aggregator can verify the scan ran.
- Clean up intermediate files: delete `sast/routeinventory-recon.md` and all `sast/routeinventory-batch-*.md` after writing the final results.
