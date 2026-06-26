---
name: sast-errorhandling
description: >-
  Detect security error-handling vulnerabilities using a three-phase approach:
  recon (find fail-open handlers, stack-trace leaks, debug flags, and swallowed
  security exceptions), batched verify (taint-trace each candidate in parallel
  subagents, 3 sites each — confirm untrusted-caller reachability, apply
  FP-killers, set exploitability / confidence), and merge (consolidate batch
  reports into sast/errorhandling-results.md and sast/errorhandling-results.json).
  Covers CWE-209 (Information Exposure Through Error Message) and CWE-636
  (Not Failing Securely). Targets Python/Django/Flask, Java/Spring,
  Node/Express, .NET/ASP.NET, PHP, and Ruby/Rails. Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/errorhandling-results.md and sast/errorhandling-results.json.
  Use when asked to find information-disclosure via error messages, debug-mode
  leaks, fail-open logic, or swallowed security exceptions.
version: 0.1.0
---

# Security Error Handling Detection

You are performing a focused security assessment to find error-handling vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find vulnerable handler patterns), **batched verify** (confirm exploitability in parallel batches of 3), and **merge** (consolidate batch reports into two output files).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a Security Error-Handling Vulnerability

Security error-handling vulnerabilities occur when exception or error management code:

1. **Leaks internal details** — stack traces, SQL errors, file paths, environment variables, or secret values reach an untrusted caller through an HTTP response, API payload, or rendered HTML page.
2. **Fails open** — a catch block that silently swallows a security-critical exception (authentication failure, authorization check, input validation rejection) allows the program to continue as if the operation succeeded, granting access that should have been denied.
3. **Enables debug mode in production** — framework debug flags that expose detailed error pages, stack traces, SQL queries, or loaded module paths to anyone who can trigger an error.

The core pattern: *internal diagnostic detail or security-exception outcomes reach untrusted callers, or security checks are silenced instead of failing safely.*

### What Security Error Handling IS

- **Stack-trace leakage**: `traceback.format_exc()` or `e.printStackTrace()` written directly into an HTTP response body or JSON payload returned to the client
- **Debug mode in production**: `DEBUG = True` in Django settings, `app.run(debug=True)` in Flask, `server.error.include-stacktrace=always` in Spring Boot, `customErrors mode="Off"` or `<compilation debug="true">` in ASP.NET, `display_errors = On` in PHP — when these can be reached in a production execution path
- **Fail-open catch blocks**: bare `except: pass` (Python), empty `catch (Exception e) {}` (Java), empty `.catch(() => {})` (Node) — especially when wrapping authentication, authorization, input validation, or cryptographic operations; the program proceeds as if the operation succeeded
- **Secret values in error responses**: exception messages that include database credentials, API keys, private key material, or tokens embedded in the error detail returned to the client
- **Overly broad exception catches that discard security context**: catching `Exception` / `Throwable` on a path that includes a permission check and returning a generic success response instead of failing safely

### What Security Error Handling is NOT

Do not flag these patterns:

- **Logging-only error handlers**: `except Exception as e: logger.error(e); return jsonify({"error": "Internal server error"})` — the detail goes only to a server-side structured log, not to the client response
- **Debug flags scoped to test or development files only**: `DEBUG=True` inside a file that is provably never loaded in production (e.g., `settings/local.py`, `config/test.rb`, `.env.test`), when the production config overrides it
- **Re-raising after logging**: a catch that logs then re-raises (`raise` / `throw`) does not fail open and does not expose detail to the client
- **Explicit audit-event handlers**: a catch block that records a security audit event (login failure, access denied) and then returns a safe 403 or 401 — this is correct fail-closed behavior
- **Admin-only error endpoints**: detailed error pages or stack traces accessible only to authenticated administrators behind an access-control check (lower to medium, not high)
- **Generic status-code-only error responses**: returning `{"error": "Bad request"}` or HTTP 500 with no body detail is not a vulnerability
- **Benign I/O cleanup catches**: `except IOError: pass` in file-cleanup code that has no authentication or authorization consequence

### Patterns That Prevent Security Error-Handling Vulnerabilities

**1. Generic client response with server-side detail logging**
```python
# Python / Flask
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error("Unhandled exception: %s", e, exc_info=True)
    return jsonify({"error": "Internal server error"}), 500
```

**2. Correlation ID pattern — link log to response without exposing detail**
```python
import uuid
@app.errorhandler(Exception)
def handle_error(e):
    error_id = str(uuid.uuid4())
    app.logger.error("error_id=%s: %s", error_id, e, exc_info=True)
    return jsonify({"error": "Internal server error", "error_id": error_id}), 500
```

**3. Fail-closed after security exception**
```java
// Java / Spring — authentication filter
try {
    jwtService.verify(token);
} catch (JwtException e) {
    log.warn("Token verification failed: {}", e.getMessage());
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    return;  // halt the filter chain — fail closed
}
```

**4. Production debug mode disabled**
```python
# Django — settings/production.py
DEBUG = False
ALLOWED_HOSTS = ['api.example.com']
```

```yaml
# Spring Boot — application-production.yaml
server:
  error:
    include-stacktrace: never
    include-message: never
```

**5. Specific exception catching — not swallowing**
```javascript
// Node / Express — specific exception, re-raises after logging
app.use((err, req, res, next) => {
  if (err instanceof ValidationError) {
    return res.status(400).json({ error: err.message });
  }
  logger.error({ err, requestId: req.id }, 'Unhandled error');
  res.status(500).json({ error: 'Internal server error' });
});
```

---

## Vulnerable vs. Secure Examples

### Python — Flask (stack-trace leakage)

```python
# VULNERABLE: full traceback in API response
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict())
    except Exception as e:
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500

# SECURE: log detail server-side, return opaque error to client
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict())
    except Exception as e:
        app.logger.exception("get_user failed for user_id=%s", user_id)
        return jsonify({"error": "Internal server error"}), 500
```

### Python — Django (DEBUG mode)

```python
# VULNERABLE: in settings.py or settings/base.py without production override
DEBUG = True
# Any 500 error now renders a full Django debug page with:
# - full traceback, local variables, SQL queries
# - request headers, cookies, and session data

# SECURE: production settings always override
# settings/production.py
DEBUG = False
ALLOWED_HOSTS = ['api.example.com']

# settings/base.py — default safe, dev overrides it
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'
```

### Python — Fail-open authentication (bare except)

```python
# VULNERABLE: authentication exception swallowed — caller proceeds unauthenticated
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').split(' ')[1]
            user = verify_jwt(token)
            g.user = user
        except:
            pass  # FAIL OPEN — no authentication enforced
        return f(*args, **kwargs)
    return decorated

# SECURE: fail closed on any authentication exception
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('Authorization', '').split(' ')[1]
            user = verify_jwt(token)
            g.user = user
        except Exception as e:
            app.logger.warning("Auth failed: %s", e)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
```

### Java — Spring Boot (stack trace in response body)

```java
// VULNERABLE: e.printStackTrace() output sent directly to response
@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(userService.findById(id));
        } catch (Exception e) {
            e.printStackTrace();  // goes to stdout but also leaks context
            // And the exception propagates — Spring's default error page
            // may include the message in JSON if include-message=always
            throw e;
        }
    }
}

// application.properties — VULNERABLE Spring Boot config
server.error.include-stacktrace=always
server.error.include-message=always
server.error.include-exception=true

// SECURE: server-side logging, no stack trace in response
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(Exception e, HttpServletRequest req) {
        String errorId = UUID.randomUUID().toString();
        log.error("errorId={} path={}", errorId, req.getRequestURI(), e);
        return ResponseEntity.status(500)
            .body(new ErrorResponse("Internal server error", errorId));
    }
}

// application-production.properties — SECURE
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-exception=false
```

### Java — Empty catch swallowing security check

```java
// VULNERABLE: authorization exception swallowed — user proceeds with elevated access
public void deleteRecord(Long recordId, User user) {
    try {
        authorizationService.checkOwnership(recordId, user);
        recordRepository.deleteById(recordId);
    } catch (AccessDeniedException e) {
        // swallowed — deletion proceeds anyway
    }
}

// SECURE: fail closed — re-throw or return failure
public void deleteRecord(Long recordId, User user) {
    try {
        authorizationService.checkOwnership(recordId, user);
        recordRepository.deleteById(recordId);
    } catch (AccessDeniedException e) {
        log.warn("Unauthorized delete attempt: recordId={} userId={}", recordId, user.getId());
        throw e;  // fail closed — propagates to 403 handler
    }
}
```

### Node.js — Express (err.stack in response)

```javascript
// VULNERABLE: stack trace serialized into the API response
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,          // full stack trace to client
    detail: err.toString()
  });
});

// VULNERABLE: unhandled promise rejection sends stack
app.get('/search', async (req, res) => {
  const results = await db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`);
  res.json(results);
  // If db.query rejects, Express default handler exposes the error
});

// SECURE: structured server-side log, opaque client response
app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  logger.error({ err, errorId, path: req.path }, 'Unhandled error');
  res.status(500).json({ error: 'Internal server error', errorId });
});

// SECURE: explicit catch with fail-closed behavior
app.get('/search', async (req, res, next) => {
  try {
    const results = await db.query('SELECT * FROM items WHERE name = $1', [req.query.q]);
    res.json(results);
  } catch (err) {
    next(err);  // delegates to the centralized handler above
  }
});
```

### Node.js — Empty promise catch (fail-open)

```javascript
// VULNERABLE: authentication result swallowed — all callers proceed
async function authMiddleware(req, res, next) {
  verifyToken(req.headers.authorization)
    .then(user => { req.user = user; next(); })
    .catch(() => {});  // swallowed — next() is never called, but neither is a 401
                       // depending on Express version, this can hang or silently pass
}

// SECURE: explicit fail-closed in catch
async function authMiddleware(req, res, next) {
  try {
    req.user = await verifyToken(req.headers.authorization);
    next();
  } catch (err) {
    logger.warn({ err }, 'Token verification failed');
    res.status(401).json({ error: 'Unauthorized' });
  }
}
```

### .NET / ASP.NET (customErrors and compilation debug)

```xml
<!-- VULNERABLE: Web.config with detailed errors enabled -->
<system.web>
  <customErrors mode="Off" />  <!-- shows full YSOD with stack trace -->
  <compilation debug="true" targetFramework="4.8" />
</system.web>

<!-- SECURE: Web.config production settings -->
<system.web>
  <customErrors mode="On" defaultRedirect="/error" />
  <compilation debug="false" targetFramework="4.8" />
</system.web>
```

```csharp
// VULNERABLE: swallowed security exception in ASP.NET Core middleware
public async Task InvokeAsync(HttpContext context) {
    try {
        await ValidateApiKey(context);
        await _next(context);
    } catch (Exception) {
        // swallowed — request pipeline continues without auth
        await _next(context);
    }
}

// SECURE: fail closed
public async Task InvokeAsync(HttpContext context) {
    try {
        await ValidateApiKey(context);
        await _next(context);
    } catch (UnauthorizedAccessException ex) {
        _logger.LogWarning(ex, "API key validation failed for {Path}", context.Request.Path);
        context.Response.StatusCode = 401;
        await context.Response.WriteAsJsonAsync(new { error = "Unauthorized" });
    } catch (Exception ex) {
        _logger.LogError(ex, "Unhandled error in auth middleware");
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
    }
}
```

### PHP (display_errors)

```php
<?php
// VULNERABLE: display_errors in production PHP
ini_set('display_errors', '1');
error_reporting(E_ALL);

// Any PHP notice, warning, or fatal error now renders on-screen including:
// - file paths (/var/www/html/app/models/User.php)
// - database credentials embedded in PDO connection errors
// - stack traces with local variable values

// SECURE: errors logged to file, not displayed
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/app/php_errors.log');
error_reporting(E_ALL);
```

```php
<?php
// VULNERABLE: empty catch swallows authentication failure
function authenticate(string $token): ?User {
    try {
        return JwtService::verify($token);
    } catch (\Exception $e) {
        // swallowed — returns null, but callers may not check null
        return null;
    }
}

// In the caller:
$user = authenticate($token);
// No null check — proceeds as unauthenticated user silently

// SECURE: fail explicitly, caller gets a typed exception or false
function authenticate(string $token): User {
    try {
        return JwtService::verify($token);
    } catch (\Exception $e) {
        error_log('Auth failure: ' . $e->getMessage());
        throw new AuthenticationException('Authentication failed', 0, $e);
    }
}
```

### Ruby / Rails (consider_all_requests_local)

```ruby
# VULNERABLE: config/environments/production.rb
config.consider_all_requests_local = true
# This causes Rails to render the full exception page (with stack, params,
# session, environment variables) for every error — identical to the dev page

# SECURE: production.rb
config.consider_all_requests_local = false
config.exceptions_app = self.routes  # routes /500, /404 to custom pages

# VULNERABLE: rescue returning nil — fail open
class ApplicationController < ActionController::Base
  def authorize_user!
    authorize! :manage, current_resource
  rescue CanCan::AccessDenied
    nil  # swallowed — action continues as if authorized
  end
end

# SECURE: rescue renders an error response
class ApplicationController < ActionController::Base
  rescue_from CanCan::AccessDenied do |exception|
    Rails.logger.warn "Access denied: #{exception.message} for #{current_user&.id}"
    render json: { error: 'Forbidden' }, status: :forbidden
  end
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Error-Handling Vulnerability Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where error handling is implemented in a potentially dangerous way — stack-trace leakage to clients, debug flags, fail-open catches, or swallowed security exceptions. Write results to `sast/errorhandling-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, exception-handling patterns, and response serialization paths.
>
> **What to search for — four vulnerability classes**:
>
> **Class 1 — Stack trace or internal detail in response**
>
> Flag any location where exception detail, traceback text, SQL error strings, file paths, or environment variable values are serialized into an HTTP response body, template render, JSON payload, or any other channel that reaches the client.
>
> - Python/Flask: `traceback.format_exc()` / `traceback.print_exc()` assigned to a response variable; `str(e)` or `repr(e)` in a `jsonify(...)` or `render_template(...)` call within an except block; Flask debug mode `app.run(debug=True)`
> - Python/Django: `DEBUG = True` in any settings file that may be loaded in production; exception detail included in `JsonResponse({"error": str(e)})` or `HttpResponse(traceback.format_exc())`
> - Java/Spring: `e.printStackTrace()` inside a request handler or response-building method; `server.error.include-stacktrace=always`; `server.error.include-message=always`; `server.error.include-exception=true` in `application.properties` / `application.yml`
> - Node/Express: `err.stack` / `error.stack` / `e.stack` included in `res.json()`, `res.send()`, or `res.render()` within an error handler; `err.message` sent directly in a JSON response with no sanitization
> - .NET/ASP.NET: `<customErrors mode="Off" />` in Web.config; `<compilation debug="true" />` in Web.config; `UseDeveloperExceptionPage()` not gated on an environment check in Startup.cs / Program.cs
> - PHP: `ini_set('display_errors', '1')` or `display_errors = On` in php.ini or runtime config; exception `getMessage()` or `getTrace()` echoed into the response
> - Ruby/Rails: `config.consider_all_requests_local = true` in `config/environments/production.rb`; rescuing and rendering `exception.message` or `exception.backtrace` in a response
>
> **Class 2 — Fail-open catch blocks**
>
> Flag any catch/rescue/except block that catches an exception class involved in authentication, authorization, input validation, CSRF protection, or cryptographic operations, and then allows execution to continue without enforcing the security control.
>
> - Python: `except: pass`, `except Exception: pass`, `except Exception as e: continue` — especially when the try block contains authentication checks, JWT verification, permission checks, CSRF validation, or cryptographic operations
> - Java: `catch (Exception e) {}` or `catch (Throwable t) {}` (empty body) when the try block contains `authenticate(...)`, `authorize(...)`, `checkPermission(...)`, `verifyToken(...)`, or similar
> - Node: `.catch(() => {})` or `.catch(err => {})` (no response, no re-throw) on a promise chain containing auth middleware, token verification, or access control; `try { ... } catch (e) {}` with empty catch body on security paths
> - .NET: `catch (Exception) { }` (empty) or `catch (Exception) { /* ignored */ }` on authentication or authorization paths
> - PHP: `catch (\Exception $e) {}` or `catch (\Throwable $e) {}` (empty or returning `null`) in authentication/authorization methods
> - Ruby: `rescue => e` or `rescue StandardError` with `nil` / no raise / silent return inside controller actions or Devise/CanCan authentication hooks
>
> **Class 3 — Debug mode enabled**
>
> Flag any framework-level debug configuration that is not demonstrably scoped to a non-production environment file.
>
> - `DEBUG = True` in Python (Django / Flask)
> - `app.run(debug=True)` in Flask
> - `server.error.include-stacktrace=always` in Spring Boot
> - `<customErrors mode="Off">` or `<compilation debug="true">` in ASP.NET Web.config
> - `display_errors = On` or `ini_set('display_errors', '1')` in PHP
> - `config.consider_all_requests_local = true` in Rails production config
> - `NODE_ENV` not set to `production` in an Express app with verbose error middleware
>
> **Class 4 — Secret or credential in error response**
>
> Flag any error handler or exception serializer that may embed a secret, credential, connection string, private key, or token from the exception message into the response. Common triggers:
>
> - Database connection errors that include credentials in the JDBC URL or DSN: `sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) FATAL: password authentication failed for user "dbuser"` serialized into the response
> - `str(e)` on a PDO connection exception that embeds the connection string
> - Exception chaining (`from e`) where the root exception contains an API key or token
>
> **What to skip** (these are safe and should not be flagged in recon):
> - Logging-only error handlers where exception detail is sent only to `logger.*` / `app.logger.*` / structured logging, not to the response variable or template context
> - Debug flags inside files with names indicating test or development scope: `settings/local.py`, `settings/development.py`, `config/environments/development.rb`, `*.test.*`, `.env.test`, `appsettings.Development.json`
> - Catch blocks that re-raise or call `next(err)` after logging — they are not fail-open
> - Catch blocks that explicitly call `response.sendError()`, `res.status(4xx).json(...)`, `abort(4xx)`, or `render ... status: :forbidden` — these are fail-closed
>
> **Output format** — write to `sast/errorhandling-recon.md`:
>
> ```markdown
> # Error Handling Recon: [Project Name]
>
> ## Summary
> Found [N] potential error-handling vulnerability sites across [M] vulnerability classes.
>
> ## Candidate Sites
>
> ### 1. [Descriptive name — e.g., "traceback.format_exc() in users API error handler"]
> - **Class**: [stack-trace-leak / fail-open / debug-mode / secret-in-error]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint / config key**: [function name, route, or config key]
> - **Framework**: [Django / Flask / Spring / Express / ASP.NET / PHP / Rails]
> - **Pattern found**: [bare `except: pass` / `err.stack in res.json` / `DEBUG = True` / etc.]
> - **Security context**: [authentication / authorization / CSRF / generic unhandled / debug config / etc.]
> - **Code snippet**:
>   ```
>   [the vulnerable handler / config line]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/errorhandling-recon.md`. If the recon found **zero candidate sites** (the summary reports "Found 0" or the "Candidate Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to both output files and stop:

`sast/errorhandling-results.md`:
```markdown
# Error Handling Analysis Results

No vulnerabilities found.
```

`sast/errorhandling-results.json`:
```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one candidate site.

### Phase 2: Verify — Exploitability Analysis (Batched)

After Phase 1 completes, read `sast/errorhandling-recon.md` and split the candidate sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent verifies exploitability only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/errorhandling-recon.md` and count the numbered site sections under "Candidate Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/errorhandling-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned error-handling candidate site, verify whether the vulnerability is genuinely exploitable by an untrusted caller, and apply FP-killers to eliminate false positives. Write results to `sast/errorhandling-batch-[N].md`.
>
> **Your assigned candidate sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand authentication architecture, request routing, environment variable management, and response serialization.
>
> **Verification questions — answer for each site**:
>
> **For stack-trace-leak sites:**
> 1. Does the exception detail (message, traceback, SQL, path) reach a variable that is subsequently written into an HTTP response body, JSON payload, or rendered template returned to the client?
> 2. Is the response endpoint reachable without authentication, or reachable by any authenticated user (not just admins)?
> 3. What category of internal information is exposed? (stack trace only / SQL query with table names / file paths / credential or secret values)
>
> **For fail-open catch sites:**
> 1. What security operation does the try block perform? (authentication / authorization / CSRF check / input validation / cryptographic verification / rate limit check)
> 2. If the exception is thrown, does execution continue to a code path that should have been gated by that security operation? (i.e., does the resource get accessed, the record deleted, the privileged action executed, despite the failed check?)
> 3. Is there a secondary security check elsewhere that would catch the failure even if this catch is fail-open?
>
> **For debug-mode sites:**
> 1. Is the debug flag in a file that is loaded in production? Check for: import chains, environment-specific config loading, deployment scripts, Dockerfile CMD, or CI/CD environment setup.
> 2. Does the framework debug mode expose stack traces, SQL queries, or request context in error responses, or only in a separate developer tool?
> 3. Is the flag overridden by a production config that loads later?
>
> **For secret-in-error sites:**
> 1. Does the exception message chain (including `__cause__`, chained exceptions, or `getCause()`) contain a string that matches a secret pattern (password, token, key, connection string with credentials)?
> 2. Does that message reach the response payload?
>
> **FP-killers** (if any of these apply, downgrade or mark as Not Vulnerable):
> - Stack trace is sent only to a structured logger (`logger.exception`, `log.error`, `Rails.logger.error`) and is NOT assigned to any response variable or template context — **Not Vulnerable**
> - Debug flag is inside a file that the production config demonstrably does not load (`settings/local.py`, `appsettings.Development.json`, `config/environments/development.rb`) AND the production config sets the flag to the safe value — **Not Vulnerable** (downgrade to info if production override is not confirmed)
> - Catch block calls `res.status(4xx).json(...)`, `abort(4xx)`, `render status: :forbidden`, `response.sendError(401)`, or re-raises the exception — **Not Vulnerable** (fail-closed)
> - Catch block records an explicit security audit event (writes to an audit log, emits a security metric) and returns a safe failure response — **Not Vulnerable**
> - Detailed error page is only accessible after passing an `[Authorize(Roles="Admin")]` / `@PreAuthorize("hasRole('ADMIN')")` / `before_action :require_admin` check — downgrade severity to **medium** (admin-only exposure)
> - Secret in the exception message is a placeholder or is masked (e.g., `password=***`) — **Not Vulnerable**
>
> **Setting exploitability and confidence**:
>
> `exploitability`:
> - `reachable` — the vulnerable error output is sent through an HTTP response that an unauthenticated or low-privilege user can trigger and receive
> - `conditional` — the error response is only reachable after authentication or only under specific conditions (e.g., specific input, race condition, or admin path)
> - `unreachable` — the error detail stays server-side (log only) or the code path can never be triggered from the network
> - `unknown` — cannot determine reachability without runtime information
>
> `confidence`:
> - `high` — direct evidence: `err.stack` / `traceback.format_exc()` in a response variable in a named endpoint; `DEBUG = True` in a file whose name does not indicate dev/test scope; empty `catch {}` on a clearly named auth method
> - `medium` — indirect: stack trace reaches a response via an intermediate helper; debug flag whose production load path is ambiguous; fail-open catch on a method whose security relevance requires reading the callee
> - `low` — possible but requires runtime confirmation; the suspicious pattern is present but its connection to a security operation is speculative
>
> **Severity** (default and adjustments):
> - Default: **high** (information disclosure enabling further attacks — CWE-209, or fail-open enabling unauthorized access — CWE-636)
> - Raise to **critical** when: the error response contains a secret, credential, or private key material; OR when a fail-open catch on an authentication or global authorization middleware allows unauthenticated access to the entire application
> - Lower to **medium** when: stack trace is only reachable behind an authenticated admin endpoint; fail-open catch is on a non-critical secondary check with other defenses present
> - Lower to **low** when: only a generic error code or HTTP status is exposed with no internal detail
>
> **chain_id assignment**:
> - Set `chain_id: "error-secret-leak"` when the error response contains or may contain a secret, credential, token, or private key (chains with `sast-hardcodedsecrets`)
> - Set `chain_id: null` for all other findings
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: The site demonstrably exposes internal detail to untrusted callers, fails open on a security operation, or enables debug mode in production.
> - **Likely Vulnerable**: The vulnerable pattern is present but reachability or security context requires deeper tracing (indirect flow, ambiguous config loading).
> - **Not Vulnerable**: FP-killer applies — detail is log-only, debug flag is dev-scoped, catch is fail-closed.
> - **Needs Manual Review**: Cannot determine production reachability or security context with confidence.
>
> **Output format** — write to `sast/errorhandling-batch-[N].md`:
>
> ```markdown
> # Error Handling Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / config**: [route, function name, or config key]
> - **Vulnerability class**: [stack-trace-leak / fail-open / debug-mode / secret-in-error]
> - **CWE**: CWE-209 (stack-trace-leak / debug-mode / secret-in-error) or CWE-636 (fail-open)
> - **Issue**: [e.g., "traceback.format_exc() assigned to JSON response body in unauthenticated endpoint"]
> - **Reachability**: [how an attacker triggers the error and receives the response]
> - **Impact**: [what the attacker learns or gains — stack trace content, credentials exposed, access granted]
> - **Exploitability**: reachable|conditional|unreachable|unknown
> - **Confidence**: high|medium|low
> - **Severity**: critical|high|medium|low
> - **chain_id**: "error-secret-leak" or null
> - **Remediation**: [specific fix — return opaque error, log server-side, disable debug, fail closed]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / config**: [route, function name, or config key]
> - **Vulnerability class**: [stack-trace-leak / fail-open / debug-mode / secret-in-error]
> - **CWE**: CWE-209 or CWE-636
> - **Issue**: [e.g., "Fail-open catch on verifyToken — requires tracing callee to confirm security relevance"]
> - **Concern**: [why it remains a risk]
> - **Exploitability**: reachable|conditional|unknown
> - **Confidence**: medium|low
> - **Severity**: high|medium
> - **chain_id**: "error-secret-leak" or null
> - **Remediation**: [specific fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / config**: [route, function name, or config key]
> - **Reason**: [which FP-killer applies and why]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function / config**: [route, function name, or config key]
> - **Uncertainty**: [what cannot be determined statically]
> - **Suggestion**: [what to inspect or test to confirm]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/errorhandling-batch-*.md` file and merge them into the two canonical output files. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/errorhandling-batch-1.md`, `sast/errorhandling-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving every field.
3. Count totals across all batches for the executive summary.
4. Assign sequential IDs to every Vulnerable and Likely Vulnerable finding: `errorhandling-1`, `errorhandling-2`, etc.
5. Write the merged markdown report to `sast/errorhandling-results.md`:

```markdown
# Error Handling Analysis Results: [Project Name]

## Executive Summary
- Candidate sites analyzed: [total sites from recon that were batched]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

6. Write the canonical JSON file to `sast/errorhandling-results.json` using exactly the schema below. Include **only** Vulnerable and Likely Vulnerable findings in the JSON (not Not Vulnerable or Needs Manual Review):

```json
{
  "findings": [
    {
      "id": "errorhandling-1",
      "skill": "sast-errorhandling",
      "severity": "high",
      "title": "Stack trace exposed in API error response",
      "description": "traceback.format_exc() is assigned to the 'trace' key of the JSON response body returned by the /api/users endpoint. Any error in the endpoint handler — including database errors, type errors, or unhandled exceptions — sends the full Python stack trace to the unauthenticated caller, revealing internal file paths, function names, SQL query strings, and framework version information.",
      "location": { "file": "app/views/users.py", "line": 42, "column": 16 },
      "remediation": "Return a generic error message to clients. Log the full detail server-side with a correlation ID using app.logger.exception(). Example: return jsonify({'error': 'Internal server error', 'error_id': error_id}), 500",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    }
  ]
}
```

Schema field reference:
- `id`: `"errorhandling-<sequential-number>"` — unique per finding, sequential across all batches
- `skill`: always `"sast-errorhandling"`
- `severity`: `"critical"` | `"high"` | `"medium"` | `"low"` | `"info"`
- `title`: short one-line description of the specific finding (not the class name)
- `description`: full explanation including what is exposed, to whom, and the attack scenario
- `location.file`: relative path from the project root
- `location.line`: the most specific line number (the response write, the debug flag assignment, or the empty catch)
- `location.column`: column offset if determinable; omit or set to 0 if not
- `remediation`: the specific fix for this finding instance
- `exploitability`: `"reachable"` | `"conditional"` | `"unreachable"` | `"unknown"` (schema v2)
- `confidence`: `"high"` | `"medium"` | `"low"` (schema v2)
- `chain_id`: `"error-secret-leak"` when the finding chains with `sast-hardcodedsecrets`; `null` otherwise (schema v2)

7. After writing both output files, **delete all intermediate files**: `sast/errorhandling-recon.md` and all `sast/errorhandling-batch-*.md`.

---

## Chains and Severity Escalation

### chain_id: "error-secret-leak"

This chain is set when an error response contains or may contain secret material. It composes with the `sast-hardcodedsecrets` skill:

- If `sast-hardcodedsecrets` found a hardcoded credential (API key, database password, token) in the same codebase AND that credential appears in code paths that can throw exceptions whose messages include the credential, the combined severity is **critical**.
- The chain allows the `sast-report` aggregator to present one merged finding: "Hardcoded credential surfaces in error response" rather than two separate findings.
- Set `chain_id: "error-secret-leak"` in both the `sast-errorhandling` finding and (if present) the related `sast-hardcodedsecrets` finding so the aggregator can join them.

### Severity adjustment table

| Condition | Severity |
|---|---|
| Error response contains a secret, credential, or private key | **critical** |
| Fail-open on global authentication middleware (all routes unprotected) | **critical** |
| Stack trace leakage to unauthenticated callers | **high** (default) |
| Fail-open on per-resource authorization check | **high** (default) |
| Debug mode enabled in production (no secret in response) | **high** |
| Stack trace behind authenticated (non-admin) endpoint | **medium** |
| Fail-open on a secondary check with another defense present | **medium** |
| Debug page reachable only by admins | **medium** |
| Only generic error code exposed (no message, no trace) | **low** |

---

## Test Fixtures

The following fixtures define the minimum true-positive / false-negative contract for this skill.

### Fixture 1 — Stack-trace leak (Python/Flask)

**True Positive** (must be flagged, `reachable`, `high`):
```python
@app.route('/api/data')
def get_data():
    try:
        return jsonify(fetch_data())
    except Exception as e:
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500
```

**True Negative** (must NOT be flagged):
```python
@app.route('/api/data')
def get_data():
    try:
        return jsonify(fetch_data())
    except Exception as e:
        app.logger.exception("get_data failed")
        return jsonify({"error": "Internal server error"}), 500
```

Assert: only the TP is flagged; TN produces no finding.

### Fixture 2 — Fail-open authentication (Python)

**True Positive** (must be flagged, `reachable`, `high`):
```python
def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            user = verify_session(session.get('token'))
            g.user = user
        except:
            pass  # fail open
        return f(*args, **kwargs)
    return wrapper
```

**True Negative** (must NOT be flagged):
```python
def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            user = verify_session(session.get('token'))
            g.user = user
        except Exception as e:
            app.logger.warning("Session invalid: %s", e)
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper
```

Assert: only the TP is flagged; TN produces no finding.

### Fixture 3 — Debug mode (Django)

**True Positive** (must be flagged, `high`):
```python
# myproject/settings.py — no indication this is dev-only
DEBUG = True
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'HOST': 'db.internal',
    }
}
```

**True Negative** (must NOT be flagged):
```python
# myproject/settings/development.py
DEBUG = True
```
```python
# myproject/settings/production.py
DEBUG = False
```

Assert: only the TP (in a non-dev-scoped settings file without a production override) is flagged.

### Fixture 4 — Secret in error response (chain_id: error-secret-leak)

**True Positive** (must be flagged, `critical`, `chain_id: "error-secret-leak"`):
```python
DATABASE_URL = "postgresql://admin:s3cr3tpassword@db.internal/prod"

@app.route('/health')
def health():
    try:
        db.execute("SELECT 1")
        return jsonify({"status": "ok"})
    except Exception as e:
        # OperationalError message includes the DATABASE_URL with credentials
        return jsonify({"error": str(e)}), 500
```

**True Negative** (must NOT be flagged):
```python
DATABASE_URL = os.environ.get("DATABASE_URL")

@app.route('/health')
def health():
    try:
        db.execute("SELECT 1")
        return jsonify({"status": "ok"})
    except Exception as e:
        app.logger.exception("DB health check failed")
        return jsonify({"error": "Database unavailable"}), 503
```

Assert: TP is flagged as critical with `chain_id: "error-secret-leak"`; TN produces no finding.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidate sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **Phase 1 is structural**: flag any of the four vulnerability-class patterns regardless of whether you can fully trace the reachability chain. Do not trace exploitation paths in Phase 1 — that is Phase 2's job.
- **Phase 2 is exploitability analysis**: for each assigned site, answer the verification questions, apply FP-killers, and set `exploitability` / `confidence` / `severity`.
- A debug flag in `settings/local.py` or `config/environments/development.rb` is a **True Negative** only when the production config provably overrides it. If you cannot confirm the production config loads after the dev config, classify as **Likely Vulnerable** with `confidence: medium`.
- Empty catch blocks are only a vulnerability when the try block includes a security operation (authentication, authorization, CSRF, cryptographic verification). An empty catch on `except IOError: pass` in file cleanup code is not in scope.
- A `str(e)` return in a JSON response is a **high** finding when `e` can contain SQL error text, file paths, or framework internals. It is a **critical** finding when the exception message chain can include a credential or secret.
- `chain_id: "error-secret-leak"` links this finding to the `sast-hardcodedsecrets` skill. Set it whenever the error response can contain secret material, even if the hardcoded-secrets skill did not find a specific finding — the chain annotation allows manual correlation.
- Both output files are required: `sast/errorhandling-results.md` (human-readable) and `sast/errorhandling-results.json` (machine-readable, canonical schema v2). Write both before deleting intermediate files.
- Clean up all intermediate files after writing both output files: delete `sast/errorhandling-recon.md` and all `sast/errorhandling-batch-*.md`.
- When in doubt about whether a catch block is fail-open, classify as **Needs Manual Review** rather than **Not Vulnerable**. A missed fail-open on an authentication path is far more dangerous than a false positive.
- `sast-skills export` expects `sast/errorhandling-results.json` with `"schema": "2.0"` fields (`exploitability`, `confidence`, `chain_id`) set on every finding. Always populate these — never omit them.
