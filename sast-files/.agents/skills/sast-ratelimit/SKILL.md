---
name: sast-ratelimit
description: >-
  Detect missing rate limits on authentication and resource-intensive endpoints
  (login, password-reset, token-refresh, OTP verify, search, bulk-export) that
  are reachable without a framework- or gateway-level request cap, enabling
  brute-force credential attacks and resource-exhaustion DoS (CWE-770, API4,
  API23). Uses a three-phase approach: recon (map sensitive endpoints and their
  middleware chains), batched verify (parallel subagents, 3 candidates each,
  confirm no per-IP or per-user rate cap exists at any enforced layer), and merge
  (consolidate into sast/ratelimit-results.md + sast/ratelimit-results.json).
  Run after sast-analysis to use sast/architecture.md for stack routing. Use
  when asked to find brute-force exposure, missing throttling, or credential
  stuffing vectors.
version: 0.1.0
---

# Missing Rate Limit Detection (Auth & Expensive Endpoints)

You are performing a focused security assessment to find missing rate limits on authentication and resource-intensive endpoints. This skill uses a three-phase approach with subagents: **recon** (identify sensitive endpoints and audit their middleware chains for rate-limiting controls), **batched verify** (confirm exploitation in parallel batches of 3 candidates each), and **merge** (consolidate batch results into the final report and JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What This Skill Covers

### Missing Rate Limit on Auth Endpoints
An endpoint handles login, password reset, token refresh, OTP/MFA verification, or account registration and accepts **unlimited repeated requests from any single IP or user** — enabling brute-force attacks, credential stuffing, and MFA bypass.

### Missing Rate Limit on Expensive Endpoints
An endpoint performs heavy computation, large data retrieval, or bulk operations (search, export, report generation, file conversion) with **no per-user or per-IP quota** — enabling resource-exhaustion DoS that degrades or takes down the service for legitimate users.

### What This Skill Is NOT

Do not conflate with:
- **Missing authentication**: No login required at all (covered by sast-missingauth). This skill applies whether or not authentication is present — rate limiting and authentication are independent controls.
- **JWT crypto bugs**: Weak signing or verification (covered by sast-jwt).
- **Session management flaws**: No regeneration after login, session fixation (covered by sast-session).
- **Injection or input validation**: SQLi, XSS, etc. — not in scope here.

---

## Vulnerability Classes

### Class 1: Uncapped Login / Credential Endpoint
The login, password-reset, or account-unlock endpoint accepts repeated attempts with no back-off, lockout, or request cap.

```
POST /api/auth/login         → unlimited password guesses per IP
POST /api/auth/password-reset → account enumeration + unlimited resets
POST /api/auth/token/refresh  → unlimited refresh attempts
```

### Class 2: Uncapped OTP / MFA Verification
The OTP or MFA code submission endpoint has no attempt limit. With a 6-digit TOTP, brute force of the valid window requires at most 1,000,000 guesses; at 100 req/s this is ~3 hours — often less if TOTP windows are wide.

```
POST /api/auth/otp/verify     → trivially brute-forceable MFA
POST /api/auth/mfa            → 6-digit code, no cap, MFA is bypassed
```

### Class 3: Uncapped Search / Bulk Export
Heavy endpoints with no per-user quota allow a single attacker to exhaust CPU, memory, or database connections.

```
GET  /api/search?q=*&limit=10000   → full-table scan, unlimited calls
POST /api/reports/export            → spawns large background job, unlimited
GET  /api/data/bulk?ids=1,2,...,9999 → N+1 risk + DoS vector
```

---

## Rate-Limiting Controls That PREVENT Vulnerabilities

When you see the following patterns applied **before** the route handler and **covering the specific path**, the endpoint is **not vulnerable**:

**1. Express — express-rate-limit on specific route or prefix**
```javascript
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 10,                    // 10 attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
});

// Applied directly to the route — protects only /login
app.post('/login', loginLimiter, loginHandler);

// Applied to a prefix — protects all /auth/* routes
app.use('/auth', loginLimiter, authRouter);

// Applied globally before route registration — protects everything
app.use(rateLimit({ windowMs: 60000, max: 100 }));
app.post('/login', loginHandler);  // covered by global limiter above
```

**2. Express — express-slow-down (progressive delay)**
```javascript
import slowDown from 'express-slow-down';

const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 5,
    delayMs: 500,
});
app.post('/login', speedLimiter, loginHandler);
```

**3. Django — django-ratelimit decorator**
```python
from ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', block=True)
def login_view(request):
    ...

@ratelimit(key='user', rate='10/h', block=True)
def password_reset(request):
    ...
```

**4. Django REST Framework — DEFAULT_THROTTLE_CLASSES in settings**
```python
# settings.py — applies globally to all DRF views
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/min',
        'user': '100/min',
    }
}
```

**5. FastAPI — slowapi limiter dependency**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post('/login')
@limiter.limit('10/minute')
async def login(request: Request, credentials: LoginSchema):
    ...

# Or as a Depends() injection
async def rate_limit_dep(request: Request):
    await limiter.check(request, '10/minute')

@router.post('/otp/verify', dependencies=[Depends(rate_limit_dep)])
async def verify_otp(body: OTPSchema):
    ...
```

**6. Spring Boot — Resilience4j @RateLimiter annotation**
```java
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;

@PostMapping("/auth/login")
@RateLimiter(name = "loginEndpoint", fallbackMethod = "loginFallback")
public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest req) {
    ...
}
```

**7. Spring Boot — Bucket4j filter applied to path pattern**
```java
// Bucket4j filter configured to apply to /api/auth/**
@Bean
public FilterRegistrationBean<Bucket4jFilter> bucket4jFilter() {
    Bucket4jFilter filter = new Bucket4jFilter(bucket4jProperties);
    FilterRegistrationBean<Bucket4jFilter> bean = new FilterRegistrationBean<>(filter);
    bean.addUrlPatterns("/api/auth/*");
    return bean;
}
```

**8. Rails — Rack::Attack throttle block**
```ruby
# config/initializers/rack_attack.rb
Rack::Attack.throttle('logins/ip', limit: 5, period: 60.seconds) do |req|
    req.ip if req.path == '/users/sign_in' && req.post?
end

Rack::Attack.throttle('logins/email', limit: 10, period: 3600.seconds) do |req|
    if req.path == '/users/sign_in' && req.post?
        req.params['user']&.dig('email')&.downcase&.gsub(/\s+/, '')
    end
end

# Wildcard — covers all paths (check if auth path is included)
Rack::Attack.throttle('all_requests/ip', limit: 300, period: 5.minutes) do |req|
    req.ip
end
```

**9. Upstream gateway evidence (True Negative — do not flag)**
Upstream controls that definitively protect all traffic:
- Kong rate-limiting plugin applied to a service or route covering the auth path
- AWS API Gateway Usage Plan with throttle settings on the stage
- Cloudflare Rate Limiting rule matching the login path pattern
- nginx `limit_req_zone` / `limit_req` directive in a location block
- IaC (Terraform, CloudFormation, Pulumi) or gateway config files in the repo confirming coverage

---

## Vulnerable vs. Secure Examples

### Node.js — Express

```javascript
// VULNERABLE: No rate-limit middleware anywhere in the chain
const express = require('express');
const app = express();
const { loginHandler } = require('./handlers/auth');

app.post('/api/auth/login', loginHandler);  // ← unlimited retries
app.post('/api/auth/password-reset', passwordResetHandler);  // ← account enumeration

// VULNERABLE: express-rate-limit imported but never applied to auth routes
import rateLimit from 'express-rate-limit';
const apiLimiter = rateLimit({ windowMs: 60000, max: 100 });
app.use('/api/public', apiLimiter);  // ← only /api/public is covered
app.post('/api/auth/login', loginHandler);  // ← /api/auth is NOT covered

// SECURE: limiter on the specific route
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post('/api/auth/login', loginLimiter, loginHandler);

// SECURE: limiter on the parent prefix
app.use('/api/auth', rateLimit({ windowMs: 60000, max: 20 }));
app.post('/api/auth/login', loginHandler);  // covered by above use()
```

### Python — Django

```python
# VULNERABLE: view handles login with no throttle decorator or mixin
from django.contrib.auth import authenticate, login
from django.http import JsonResponse

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({'status': 'ok'})
        return JsonResponse({'error': 'invalid credentials'}, status=401)

# VULNERABLE: DRF view without throttle classes — no DEFAULT_THROTTLE_CLASSES set
from rest_framework.views import APIView
from rest_framework.response import Response

class LoginView(APIView):
    permission_classes = []
    # No throttle_classes attribute; DEFAULT_THROTTLE_CLASSES also absent in settings

    def post(self, request):
        ...
        return Response({'token': token})

# SECURE: django-ratelimit decorator
from ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', block=True)
def login_view(request):
    ...

# SECURE: DRF throttle_classes on the view
from rest_framework.throttling import AnonRateThrottle

class LoginView(APIView):
    permission_classes = []
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        ...
```

### Python — FastAPI

```python
# VULNERABLE: auth router with no Depends(RateLimiter) or @limiter.limit
from fastapi import APIRouter, Depends
from .schemas import LoginSchema, OTPSchema

router = APIRouter(prefix='/auth', tags=['auth'])

@router.post('/login')
async def login(credentials: LoginSchema):
    ...  # ← no rate limit

@router.post('/otp/verify')
async def verify_otp(body: OTPSchema):
    ...  # ← no rate limit, OTP brute-forceable

# SECURE: slowapi limiter
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

limiter = Limiter(key_func=get_remote_address)

@router.post('/login')
@limiter.limit('10/minute')
async def login(request: Request, credentials: LoginSchema):
    ...
```

### Java — Spring Boot

```java
// VULNERABLE: @PostMapping on auth path with no @RateLimiter or Bucket4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest req) {
        // No rate limiting — unlimited attempts per IP
        ...
    }

    @PostMapping("/otp")
    public ResponseEntity<OTPResponse> verifyOtp(@RequestBody @Valid OTPRequest req) {
        // No attempt cap — MFA is trivially brute-forceable
        ...
    }
}

// SECURE: Resilience4j annotation
@PostMapping("/login")
@RateLimiter(name = "loginEndpoint", fallbackMethod = "tooManyRequests")
public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest req) {
    ...
}

public ResponseEntity<AuthResponse> tooManyRequests(LoginRequest req, Throwable t) {
    return ResponseEntity.status(429).build();
}
```

### Ruby on Rails

```ruby
# VULNERABLE: sessions#create with no before_action throttle and no Rack::Attack block
class SessionsController < ApplicationController
    skip_before_action :authenticate_user!, only: [:create]

    def create
        user = User.find_by(email: params[:email])
        if user&.authenticate(params[:password])
            session[:user_id] = user.id
            render json: { token: user.generate_token }
        else
            render json: { error: 'invalid' }, status: :unauthorized
        end
    end
    # No rack-attack initializer file or the throttle block does not match this path
end

# SECURE: Rack::Attack initializer covers /users/sign_in
# config/initializers/rack_attack.rb
Rack::Attack.throttle('logins/ip', limit: 5, period: 60.seconds) do |req|
    req.ip if req.path == '/users/sign_in' && req.post?
end
```

### PHP — Laravel

```php
// VULNERABLE: login route with no middleware throttle or manual rate limit
Route::post('/login', [AuthController::class, 'login']);  // no throttle

// VULNERABLE: throttle middleware applied to wrong group
Route::middleware(['auth', 'throttle:60,1'])->group(function () {
    Route::post('/api/data/export', [ExportController::class, 'create']);
});
Route::post('/login', [AuthController::class, 'login']);  // ← outside throttled group

// SECURE: Laravel built-in throttle middleware on auth routes
Route::middleware('throttle:10,1')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/forgot-password', [PasswordController::class, 'send']);
});
```

### Go

```go
// VULNERABLE: no rate-limit middleware on auth route
r := chi.NewRouter()
r.Post("/api/auth/login", loginHandler)  // ← unthrottled

// VULNERABLE: rate limiter exists but is scoped only to /api/v1/
r.Use(httpRateLimit.New(httpRateLimit.Config{
    RequestsPerSecond: 10,
}))
r.Route("/api/v1", func(r chi.Router) {
    r.Get("/users", listUsers)
})
r.Post("/api/auth/login", loginHandler)  // ← outside the rate-limited group

// SECURE: rate limiter wrapping the auth group
r.Route("/api/auth", func(r chi.Router) {
    r.Use(httpRateLimitMiddleware(5, 60*time.Second))  // 5 req/min per IP
    r.Post("/login", loginHandler)
    r.Post("/otp/verify", otpVerifyHandler)
})
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Map Sensitive Endpoints and Rate-Limit Controls

Launch a subagent with the following instructions:

> **Goal**: Build a complete map of (1) all auth and resource-intensive endpoints and (2) any rate-limiting controls visible in the codebase. Write results to `sast/ratelimit-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, route definitions, and any middleware configuration.
>
> **What to search for**:
>
> 1. **All auth-related route/endpoint definitions** — collect every handler matching these criteria:
>    - Path contains: `login`, `signin`, `sign-in`, `authenticate`, `token`, `refresh`, `password`, `reset`, `forgot`, `otp`, `mfa`, `2fa`, `verify`, `register`, `signup`, `sign-up`
>    - Express/Koa: `app.post('/login')`, `router.post('/auth/...')`, `app.use('/auth', authRouter)`
>    - Django: `urlpatterns` entries pointing to views calling `authenticate()`, `login()`, `password_reset()`; DRF `AuthToken`, `TokenObtainPairView`, `PasswordResetView`
>    - FastAPI: `@router.post` on paths containing `login`/`token`/`otp`/`reset`/`verify`
>    - Spring Boot: `@PostMapping` on paths containing `login`/`token`/`otp`/`reset`/`password`
>    - Rails: `sessions#create`, `passwords#create`, `registrations#create` in `routes.rb`
>    - Laravel: `Route::post('/login')`, `Route::post('/password/email')`
>
> 2. **All resource-intensive route/endpoint definitions** — collect every handler matching:
>    - Path contains: `search`, `export`, `report`, `bulk`, `batch`, `download`, `generate`, `convert`
>    - Large data return: endpoints with `limit`, `page`, `offset` that can request thousands of records
>    - Background job triggers: endpoints that enqueue heavy jobs (Celery, Sidekiq, BullMQ, etc.)
>
> 3. **Rate-limiting middleware and configuration** present in the codebase:
>    - `express-rate-limit`: imports of `rateLimit` from `express-rate-limit`; `app.use(rateLimit(...))` or `router.use(rateLimit(...))`; `rateLimit({...})` middleware injected in a route array
>    - `express-slow-down`: `slowDown({...})` middleware
>    - `django-ratelimit`: `@ratelimit(...)` decorator; `RateLimitMixin`
>    - DRF throttle: `DEFAULT_THROTTLE_CLASSES` in `settings.py`; `throttle_classes` on any view
>    - `slowapi` / `fastapi-limiter`: `@limiter.limit(...)` decorator; `Depends(RateLimiter(...))`
>    - `Resilience4j`: `@RateLimiter(...)` annotation; `Bucket4j` filter registration
>    - `rack-attack`: `Rack::Attack.throttle(...)` blocks; `throttle_or_track`
>    - Laravel `throttle`: `Route::middleware('throttle:...')` or `throttle:rate,period`
>    - Go rate limiters: `golang.org/x/time/rate`, `github.com/didip/tollbooth`, any custom middleware named `rateLimit`, `throttle`, `limiter`
>    - Nginx/Caddy/Traefik config files: `limit_req`, `rate_limit`, `rateLimit` directives
>    - IaC evidence: Terraform `aws_api_gateway_usage_plan`, Kong plugin resources, Cloudflare rate-limiting rules
>
> 4. **For each candidate endpoint, note**:
>    - File path and line numbers
>    - HTTP method and path pattern
>    - Whether any rate-limit middleware/decorator is visible in the file or its parent router file
>    - Middleware chain order — confirm rate limiter runs BEFORE the handler
>    - Whether a global rate limiter exists and demonstrably covers this route's prefix
>    - Whether IaC/gateway config provides an upstream limit
>
> **What to ignore**:
> - Health check / liveness probe endpoints: `/health`, `/ping`, `/status`, `/ready`, `/alive`
> - Static asset serving, public read endpoints with no auth requirement and no sensitive data
> - Endpoints already protected by a global `app.use(rateLimit({...}))` placed BEFORE all route registrations (mark as TN in recon)
>
> **Output format** — write to `sast/ratelimit-recon.md`:
>
> ```markdown
> # Rate Limit Recon: [Project Name]
>
> ## Rate-Limiting Infrastructure Summary
> - Libraries / middleware found: [list e.g. express-rate-limit v7.x, rack-attack gem]
> - Global limiter present: [yes/no — if yes, does it cover all auth paths?]
> - Upstream gateway evidence: [yes/no — describe if yes]
>
> ## Candidate Endpoints
>
> ### 1. [Endpoint name / description]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Category**: [auth / expensive]
> - **Rate limit found**: [yes / no / partial — describe middleware chain]
> - **Gateway evidence**: [yes / no]
> - **Code snippet**:
>   ```
>   [route registration + any middleware in the chain]
>   ```
>
> [Repeat for each candidate]
> ```

### Phase 2: Verify — Confirm Missing Rate Limits (Batched)

After Phase 1 completes, read `sast/ratelimit-recon.md` and split the candidate inventory into **batches of up to 3 endpoints each** (each numbered `### N.` under **Candidate Endpoints**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/ratelimit-recon.md` and count the numbered sections under **Candidate Endpoints** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 9 candidates → 3 batches (1–3, 4–6, 7–9).
3. For each batch, extract the full text of those sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/ratelimit-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include those examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: Verify the following endpoints for missing rate limits. Write results to `sast/ratelimit-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the middleware ordering, rate-limit library usage, and any gateway configuration.
>
> **What to verify — the core question**:
> Is this endpoint reachable from the public internet with no per-IP or per-user request cap enforced at the application layer or a verified upstream gateway?
>
> **False-positive killers — if ANY of the following are true, the endpoint is NOT vulnerable**:
>
> 1. A `rateLimit({...})` / `slowDown({...})` / `throttle(...)` middleware is registered with `app.use(prefix, ...)` or `router.use(prefix, ...)` where the prefix covers this endpoint's path, AND it is registered BEFORE this route's registration in the same file or parent router.
> 2. A global `app.use(rateLimit({...}))` is placed at the top of the main app file (or before any route registration) and ALL routes including this one pass through it — verify the registration order carefully.
> 3. `DEFAULT_THROTTLE_CLASSES` is set in Django/DRF `settings.py` AND this view does not override `throttle_classes = []`.
> 4. A `Rack::Attack.throttle(...)` block exists that matches this path and method.
> 5. A Bucket4j or Resilience4j filter is applied to a URL pattern that covers this path.
> 6. A `Depends(RateLimiter(...))` or `@limiter.limit(...)` is present on this specific endpoint.
> 7. IaC or gateway configuration in the repository confirms an upstream rate-limiting rule covers ALL traffic to this service (not just some routes).
>
> **Middleware ordering is critical**: A rate-limit middleware registered AFTER the route handler does NOT protect the route. Verify the call order in the source.
>
> **Severity guidance**:
> - **critical**: OTP or MFA verification endpoint with no attempt cap (MFA is trivially bypassed)
> - **high**: Login, password-reset, or token-refresh with no cap (credential brute-force / account takeover)
> - **medium**: Expensive endpoint (search, export, bulk) with no quota (DoS risk, no direct credential theft)
> - Lower to **medium** when the endpoint is internal-only (non-public network boundary evidenced in code or IaC)
>
> **Chain IDs**:
> - Auth endpoint also lacks authentication entirely → `chain_id: "auth-bypass"` (chains with sast-missingauth)
> - Login endpoint has no rate limit AND no session regeneration after auth → `chain_id: "credential-stuffing"` (chains with sast-session)
> - OTP/MFA endpoint with no rate limit → `chain_id: "mfa-bypass"`
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned candidate, evaluate**:
>
> 1. **Direct rate-limit control** — is there a rate-limit middleware, decorator, or annotation on this exact route or on a parent group that demonstrably covers this path?
>    - Trace the middleware chain from app/router root to the handler
>    - Confirm the limiter executes BEFORE the handler (registration order)
>    - Confirm the path pattern of the limiter covers this endpoint's path
>
> 2. **Global coverage** — does a global limiter (app-level `use()`, `DEFAULT_THROTTLE_CLASSES`, Rack::Attack wildcard) cover this endpoint?
>    - Is it registered before this route?
>    - Is this endpoint excluded (e.g., in `except` list, path not matched by the limiter's key function)?
>
> 3. **Gateway coverage** — is there IaC or config evidence that an upstream service rate-limits all traffic to this endpoint?
>    - Look for: Kong rate-limiting plugin JSON/YAML in the repo, AWS API Gateway Terraform resources with throttle settings, Cloudflare rate-limiting rule definitions, nginx `limit_req` directives in a location that covers this path
>
> 4. **Exploitability assessment**:
>    - Is the endpoint on a public-facing service (no VPN or internal-only network restriction evident)?
>    - Does it perform a sensitive action (authenticate, verify OTP, trigger expensive work)?
>    - Could an attacker meaningfully exploit this within a realistic time window?
>
> **Classification**:
> - **VULNERABLE**: No rate limit at any layer (application or gateway); endpoint is reachable and handles sensitive/expensive operations.
> - **LIKELY VULNERABLE**: Rate limit exists but is misapplied (wrong path prefix, registered after the handler, or covers only a subset of methods).
> - **NOT VULNERABLE**: Rate limit is in place at the application layer or a verified gateway, and covers this endpoint.
> - **NEEDS MANUAL REVIEW**: Cannot determine with confidence (e.g., rate limit may come from a gateway config not in the repo, or complex dynamic middleware registration).
>
> **Output format** — write to `sast/ratelimit-batch-[N].md`:
>
> ```markdown
> # Rate Limit Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Category**: [auth / expensive]
> - **Severity**: [critical / high / medium]
> - **Issue**: [No rate limit at application or gateway layer]
> - **Impact**: [What an attacker can do — brute-force credentials / bypass MFA / exhaust resources]
> - **Proof**: [Show the route definition and middleware chain — highlight the absence of any limiter]
> - **Chain IDs**: [auth-bypass / credential-stuffing / mfa-bypass / null]
> - **Remediation**: [Specific fix — exact middleware to add, where to register it, recommended limits]
> - **Dynamic Test**:
>   ```
>   # Confirm no rate limit by sending rapid requests:
>   for i in $(seq 1 50); do
>     curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<HOST>/api/auth/login \
>       -H "Content-Type: application/json" \
>       -d '{"username":"victim@example.com","password":"wrong'$i'"}';
>   done
>   # Expected with rate limit: 429 after N attempts
>   # Vulnerable: all 200/401 responses, no 429
>   ```
>
> ### [LIKELY VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Category**: [auth / expensive]
> - **Severity**: [critical / high / medium]
> - **Issue**: [Rate limit present but misapplied — describe the flaw]
> - **Concern**: [Why the existing limiter does not protect this endpoint]
> - **Proof**: [Show the rate-limit registration and why it misses this route]
> - **Chain IDs**: [auth-bypass / credential-stuffing / mfa-bypass / null]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [curl commands or steps to confirm the limiter is not triggering]
>   ```
>
> ### [NOT VULNERABLE] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Protection**: [How it's protected — which middleware/decorator/gateway, line references]
>
> ### [NEEDS MANUAL REVIEW] Endpoint name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint**: `METHOD /path`
> - **Uncertainty**: [Why automated analysis couldn't determine the status]
> - **Suggestion**: [What to look at manually — e.g., check the upstream gateway config]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/ratelimit-batch-*.md` file and merge them. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/ratelimit-batch-1.md`, `sast/ratelimit-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them, preserving all fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/ratelimit-results.md` using this format:

```markdown
# Rate Limit Analysis Results: [Project Name]

## Executive Summary
- Endpoints analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- Critical (OTP/MFA bypass): [N]
- High (auth brute-force): [N]
- Medium (DoS / expensive endpoint): [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write `sast/ratelimit-results.json` using the canonical schema. One entry per VULNERABLE or LIKELY VULNERABLE finding. Use `"findings": []` if no vulnerabilities were found.

```json
{
  "findings": [
    {
      "id": "ratelimit-1",
      "skill": "sast-ratelimit",
      "severity": "high",
      "title": "No rate limit on POST /api/auth/login",
      "description": "The login endpoint accepts unlimited requests per IP with no back-off or lockout. An attacker can brute-force credentials or conduct credential stuffing without any throttling. No application-layer or gateway-layer rate limit was found in the middleware chain.",
      "location": { "file": "src/routes/auth.js", "line": 12, "column": 1 },
      "remediation": "Add express-rate-limit middleware scoped to /api/auth: `const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }); router.use(loginLimiter);` Place this before route handler registration. Consider exponential back-off or account lockout after 5 failures.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "credential-stuffing"
    }
  ]
}
```

**Canonical field values for this skill**:
- `id`: `ratelimit-<N>` (sequential, 1-based)
- `skill`: `"sast-ratelimit"`
- `severity`: `"critical"` (OTP/MFA no cap) | `"high"` (login/reset/token no cap) | `"medium"` (expensive endpoint DoS)
- `exploitability`: `"reachable"` when no limit at any layer and endpoint is public; `"conditional"` when internal-only or partial protection; `"unknown"` for NEEDS MANUAL REVIEW
- `confidence`: `"high"` when direct route-with-no-middleware evidence; `"medium"` when gateway config is external to the repo or middleware chain is complex
- `chain_id`: `"auth-bypass"` | `"credential-stuffing"` | `"mfa-bypass"` | `null`

6. After writing both output files, **delete all intermediate files**: `sast/ratelimit-recon.md` and `sast/ratelimit-batch-*.md`.

---

## Chain IDs Reference

| chain_id | Description | Co-occurring skill |
|---|---|---|
| `auth-bypass` | Endpoint has no rate limit AND no authentication check | sast-missingauth |
| `credential-stuffing` | Login endpoint has no rate limit AND no session regeneration post-auth | sast-session |
| `mfa-bypass` | OTP/MFA verification endpoint has no attempt cap, allowing brute-force of time-limited codes | — |

A finding with `chain_id` set indicates the vulnerability is more severe when combined with the co-occurring finding. The triage and report skills use `chain_id` to correlate and elevate grouped findings.

---

## Test Fixture Reference

When calibrating detection, apply these as ground-truth cases:

**True Positive** — must be flagged, `exploitability: reachable`, `severity: high`:
```javascript
// Express — no rate-limit middleware anywhere in the chain
const express = require('express');
const app = express();
app.post('/login', (req, res) => { /* loginHandler */ });
```

**True Negative** — must NOT be flagged:
```javascript
// Express — limiter applied to route directly
import rateLimit from 'express-rate-limit';
const loginLimiter = rateLimit({ windowMs: 60000, max: 10 });
app.post('/login', loginLimiter, loginHandler);
```

**True Negative** — must NOT be flagged:
```python
# Django — @ratelimit decorator on the login view
from ratelimit.decorators import ratelimit

@ratelimit(key='ip', rate='5/m', block=True)
def login_view(request):
    ...
```

**True Negative — only the TP is flagged, reachable, high.**

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1–3 candidates total, use a single subagent.
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file.
- **Middleware ordering is the most common source of false negatives**: a rate-limit middleware registered after route handlers does not protect those routes. Always verify the order.
- **Prefix matching matters**: `app.use('/api/public', rateLimit(...))` does NOT cover `/api/auth/login`. Verify the prefix aligns with the candidate path.
- Rate limiting and authentication are independent controls. An authenticated endpoint can still lack a rate limit, and an unauthenticated endpoint can have one. Check both separately.
- OTP/MFA endpoints with no attempt cap should be elevated to **critical** — a 6-digit TOTP code has 1,000,000 combinations and a 30-second window; at 100 req/s an attacker can brute-force the current window in ~3 hours without any throttle.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". Gateway-level controls not committed to the repo cannot be verified statically.
- Always emit `sast/ratelimit-results.json` even when no findings exist (`"findings": []`) so the aggregator can confirm the scan ran.
- Clean up intermediate files: delete `sast/ratelimit-recon.md` and all `sast/ratelimit-batch-*.md` files after both output files are written.
