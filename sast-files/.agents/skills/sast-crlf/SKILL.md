---
name: sast-crlf
description: >-
  Detect CRLF injection and HTTP response splitting vulnerabilities using a
  three-phase approach: recon (find header-write, redirect, and log sinks that
  accept unsanitized input), batched verify (trace user-controlled values to
  those sinks in parallel subagents, 3 sites each, checking for CR/LF stripping
  gaps), and merge (consolidate batch results). Covers all major web frameworks
  and languages. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/crlf-results.md and sast/crlf-results.json. Use when
  asked to find header injection, response splitting, or log poisoning bugs.
version: 0.1.0
---

# CRLF Injection / HTTP Response Splitting Detection

You are performing a focused security assessment to find CRLF injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find header-write, redirect, and log sinks that accept any variable), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file and one JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is CRLF Injection / HTTP Response Splitting

CRLF injection occurs when user-supplied input containing carriage-return (`\r`, `%0d`) and/or line-feed (`\n`, `%0a`) characters is written into an HTTP response header, `Location` redirect target, `Set-Cookie` value, or log line without those characters being stripped or encoded first.

Because HTTP headers are delimited by `\r\n` sequences, injecting those bytes lets an attacker:

- **Inject arbitrary response headers** — e.g., `Set-Cookie: admin=1`, `Content-Type: text/html`
- **Split the HTTP response into two** — the second half becomes attacker-controlled content delivered to the client (response splitting → reflected XSS or cache poisoning)
- **Poison log files** — inject fake log entries that make audit trails misleading
- **Chain with open-redirect** — a `\r\n` in a redirect `Location` can inject a second header into an otherwise-valid redirect

The core pattern: *unvalidated user input containing CR or LF characters reaches an HTTP header write, redirect, cookie set, or raw log call.*

### What CRLF Injection IS

- Writing a request parameter directly into a response header value: `response.headers['X-Name'] = request.args['name']`
- Passing user-supplied URL to a redirect without stripping CR/LF: `redirect(request.args['next'])`
- Calling `header("Location: " . $_GET['url'])` in PHP without sanitizing the URL
- Passing user strings into log calls via raw string interpolation: `logging.info(f"User: {username}")`
- Setting a cookie value from user input: `resp.set_cookie('session', request.args['token'])`
- Building a raw HTTP response string with user data and writing it to a socket

### What CRLF Injection is NOT

Do not flag these as CRLF injection:

- **Input written only to the response body** — the attack surface requires header context; body output without header injection is XSS, not CRLF
- **Redirect targets validated against an explicit allowlist** that the allowlist check enforces before any CR/LF can survive — even if CR/LF is not stripped explicitly
- **Structured loggers** (Python `logging` with a formatter that serializes to JSON, Node.js `pino`, Java Log4j2 in JSON layout) where the user value is serialized as a JSON string field — the quotes and escaping prevent log poisoning
- **Header values set to hardcoded or server-controlled constants** with no user input reaching them
- **Frameworks that automatically percent-encode header values** (e.g., modern versions of Python's `http.server` / `werkzeug >=2.1` for `Location` headers) — note this as a mitigating context but verify it is actually in use

### Patterns That Prevent CRLF Injection

When you see these, the code is likely **not vulnerable**:

**1. Explicit CR/LF stripping before the header write**
```python
# Python — manual strip
safe = value.replace('\r', '').replace('\n', '')
response.headers['X-Data'] = safe

# Python — percent-encoding via urllib
from urllib.parse import quote
response.headers['Location'] = quote(user_url, safe=':/?#[]@!$&\'()*+,;=')
```

**2. Allowlist-based redirect validation**
```python
# Flask — only allow paths starting with /dashboard
ALLOWED_PREFIXES = ('/dashboard/', '/profile/')
next_url = request.args.get('next', '/')
if not any(next_url.startswith(p) for p in ALLOWED_PREFIXES):
    next_url = '/'
return redirect(next_url)
```

**3. Structured logging (value serialized, not interpolated raw)**
```python
# Python logging — structured dict, not raw f-string
import structlog
log = structlog.get_logger()
log.info("user_login", username=username)  # username is a field, not a string fragment

# Node.js — pino structured logger
logger.info({ username }, "user login");   # username is a JSON value
```

**4. Framework-level header sanitization**
```java
// Spring's ResponseEntity — sanitizes header values before writing
return ResponseEntity.ok()
    .header("X-User", sanitizedValue)
    .build();
```

**5. Rails redirect_to with allow_other_host: false (the default) and no raw string construction**
```ruby
# Safe — Rails validates host, does not allow arbitrary LF injection
redirect_to params[:url]  # safe ONLY if no \n can survive host validation
```

---

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: request param written directly into response header
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    resp = make_response(f"Hello, {name}")
    resp.headers['X-Greeting-For'] = name   # name may contain \r\n
    return resp

# VULNERABLE: redirect without CR/LF stripping
@app.route('/go')
def go():
    target = request.args.get('next', '/')
    return redirect(target)   # attacker sends ?next=http://evil.com%0d%0aSet-Cookie:+admin=1

# SECURE: strip before header assignment
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World').replace('\r', '').replace('\n', '')
    resp = make_response(f"Hello, {name}")
    resp.headers['X-Greeting-For'] = name
    return resp

# SECURE: allowlist redirect
@app.route('/go')
def go():
    target = request.args.get('next', '/')
    if not target.startswith('/'):
        target = '/'
    return redirect(target)
```

### Python — Django

```python
# VULNERABLE: HttpResponse with user-controlled header
def set_lang(request):
    lang = request.GET.get('lang', 'en')
    response = HttpResponse("OK")
    response['Content-Language'] = lang   # CRLF injectable
    return response

# VULNERABLE: raw log interpolation
import logging
logger = logging.getLogger(__name__)

def login_view(request):
    username = request.POST.get('username', '')
    logger.info(f"Login attempt by: {username}")   # log poisoning if username has \n
    ...

# SECURE: strip CR/LF from header value
def set_lang(request):
    lang = request.GET.get('lang', 'en').replace('\r', '').replace('\n', '')
    response = HttpResponse("OK")
    response['Content-Language'] = lang
    return response

# SECURE: structured log with named field
def login_view(request):
    username = request.POST.get('username', '')
    logger.info("Login attempt", extra={"username": username})
```

### Node.js — Express

```javascript
// VULNERABLE: query param into setHeader
app.get('/track', (req, res) => {
  const userId = req.query.uid;
  res.setHeader('X-Tracked-User', userId);   // CRLF if uid = "foo\r\nSet-Cookie: admin=1"
  res.send('Tracked');
});

// VULNERABLE: redirect with unsanitized URL
app.get('/jump', (req, res) => {
  res.redirect(req.query.url);   // attacker: ?url=http://x%0d%0aSet-Cookie:+s=1
});

// VULNERABLE: raw log with user input
app.post('/login', (req, res) => {
  console.log(`Login: ${req.body.username}`);   // log poisoning
  ...
});

// SECURE: strip before setHeader
app.get('/track', (req, res) => {
  const userId = (req.query.uid || '').replace(/[\r\n]/g, '');
  res.setHeader('X-Tracked-User', userId);
  res.send('Tracked');
});

// SECURE: allowlist redirect
app.get('/jump', (req, res) => {
  const ALLOWED = ['https://app.example.com', 'https://docs.example.com'];
  const target = ALLOWED.includes(req.query.url) ? req.query.url : '/';
  res.redirect(target);
});

// SECURE: structured logger
const pino = require('pino');
const logger = pino();
app.post('/login', (req, res) => {
  logger.info({ username: req.body.username }, 'Login attempt');
});
```

### Java — Servlet / Spring MVC

```java
// VULNERABLE: setHeader with user input
@GetMapping("/user-info")
public void userInfo(HttpServletResponse response,
                     @RequestParam String name) throws IOException {
    response.setHeader("X-User-Name", name);   // CRLF injectable
    response.getWriter().write("OK");
}

// VULNERABLE: sendRedirect with user URL
@GetMapping("/jump")
public void jump(HttpServletResponse response,
                 @RequestParam String url) throws IOException {
    response.sendRedirect(url);   // attacker injects \r\n into url
}

// VULNERABLE: log concatenation
private static final Logger log = LoggerFactory.getLogger(LoginController.class);

@PostMapping("/login")
public ResponseEntity<String> login(@RequestParam String username) {
    log.info("Login attempt by: " + username);   // log poisoning
    ...
}

// SECURE: strip before setHeader
@GetMapping("/user-info")
public void userInfo(HttpServletResponse response,
                     @RequestParam String name) throws IOException {
    String safe = name.replaceAll("[\r\n]", "");
    response.setHeader("X-User-Name", safe);
    response.getWriter().write("OK");
}

// SECURE: allowlist redirect
@GetMapping("/jump")
public void jump(HttpServletResponse response,
                 @RequestParam String url) throws IOException {
    List<String> allowed = List.of("https://app.example.com", "https://docs.example.com");
    String target = allowed.contains(url) ? url : "/";
    response.sendRedirect(target);
}

// SECURE: structured logging (SLF4J parameterized — value is not interpolated as raw string)
@PostMapping("/login")
public ResponseEntity<String> login(@RequestParam String username) {
    log.info("Login attempt by: {}", username);   // {} binding, not concatenation
    ...
}
```

### PHP

```php
// VULNERABLE: header with user-supplied value
<?php
$lang = $_GET['lang'];
header("Content-Language: " . $lang);   // attacker: ?lang=en%0d%0aSet-Cookie:+admin=1
echo "OK";

// VULNERABLE: Location redirect
$url = $_GET['next'];
header("Location: " . $url);
exit;

// SECURE: strip CR/LF before header
$lang = str_replace(["\r", "\n"], '', $_GET['lang'] ?? 'en');
header("Content-Language: " . $lang);

// SECURE: allowlist-validated redirect
$allowed = ['/dashboard', '/profile'];
$url = $_GET['next'] ?? '/';
if (!in_array(parse_url($url, PHP_URL_PATH), $allowed)) {
    $url = '/';
}
header("Location: " . $url);
exit;
```

### Go — net/http

```go
// VULNERABLE: Header().Set with user input
func trackHandler(w http.ResponseWriter, r *http.Request) {
    uid := r.URL.Query().Get("uid")
    w.Header().Set("X-Tracked-User", uid)   // CRLF if uid = "foo\r\nSet-Cookie: admin=1"
    w.Write([]byte("Tracked"))
}

// VULNERABLE: http.Redirect with user URL
func jumpHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    http.Redirect(w, r, target, http.StatusFound)   // CRLF injectable
}

// Note: Go's net/http >=1.6 rejects header values containing \r or \n at the
// http.Header.Set level, returning an error — but older code or custom transports
// may bypass this. Always verify the Go version and that errors are checked.

// SECURE: strip and validate
func trackHandler(w http.ResponseWriter, r *http.Request) {
    uid := strings.NewReplacer("\r", "", "\n", "").Replace(r.URL.Query().Get("uid"))
    w.Header().Set("X-Tracked-User", uid)
    w.Write([]byte("Tracked"))
}

func jumpHandler(w http.ResponseWriter, r *http.Request) {
    allowed := map[string]bool{
        "https://app.example.com":  true,
        "https://docs.example.com": true,
    }
    target := r.URL.Query().Get("url")
    if !allowed[target] {
        target = "/"
    }
    http.Redirect(w, r, target, http.StatusFound)
}
```

### Ruby / Rails

```ruby
# VULNERABLE: response.headers with user value
def set_locale
  response.headers['Content-Language'] = params[:lang]   # CRLF injectable
  render plain: "OK"
end

# VULNERABLE: redirect_to with user URL and allow_other_host: true
def jump
  redirect_to params[:url], allow_other_host: true   # bypasses host check
end

# VULNERABLE: logger with string interpolation
def login
  Rails.logger.info("Login by: #{params[:username]}")   # log poisoning
  ...
end

# SECURE: strip in header assignment
def set_locale
  lang = params[:lang].to_s.gsub(/[\r\n]/, '')
  response.headers['Content-Language'] = lang
  render plain: "OK"
end

# SECURE: redirect_to without allow_other_host (default Rails behaviour validates host)
def jump
  redirect_to params[:url]   # safe if host validation prevents \n traversal; add allowlist for path
end

# SECURE: structured logger
def login
  Rails.logger.tagged("login") { Rails.logger.info({ username: params[:username] }.to_json) }
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Header-Write, Redirect, and Log Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a response header value, redirect target, cookie value, or raw log line is constructed using any variable (regardless of where that variable comes from). Write results to `sast/crlf-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, web framework, logging library, and response-building patterns.
>
> **What to search for — CRLF-injectable sink patterns**:
>
> Flag ANY sink call where a variable is passed as a header value, redirect URL, cookie content, or raw log string. You are not yet tracing whether the variable is user-controlled; that is Phase 2's job. Flag the site if ANY variable appears — even if it looks like it might be safe.
>
> **1. Direct response header writes**:
>
> Python (Flask/Django/FastAPI/AIOHTTP):
> - `response.headers[key] = value` (any dict-style header assignment)
> - `response['Header-Name'] = variable`
> - `make_response(...)` followed by `.headers[...] = variable`
> - `HttpResponse(...)` followed by `response[key] = variable`
> - `Response(headers={key: variable})`
>
> Java (Servlet/Spring/JAX-RS):
> - `response.setHeader(name, value)`
> - `response.addHeader(name, value)`
> - `HttpHeaders` object with `.set(name, value)` or `.add(name, value)` when value is a variable
> - `ResponseEntity.header(name, variable)`
>
> Node.js (Express/Fastify/Koa/http):
> - `res.setHeader(name, value)` where value is a variable
> - `res.header(name, value)`
> - `res.set(name, value)`
> - `ctx.set(name, value)` (Koa)
> - `reply.header(name, value)` (Fastify)
>
> PHP:
> - `header("Name: " . $variable)` or `header($variable . ": " . $val)` or `header("Location: $variable")`
> - `header_remove` is not a sink but note adjacent `header()` calls
>
> Go:
> - `w.Header().Set(name, variable)`
> - `w.Header().Add(name, variable)`
> - `w.Header()[name] = []string{variable}`
>
> Ruby/Rails:
> - `response.headers[key] = variable`
> - `headers[key] = variable` (inside a controller action)
>
> C# (ASP.NET):
> - `Response.Headers.Add(name, variable)`
> - `Response.Headers[name] = variable`
> - `context.Response.Headers.Append(name, variable)`
>
> **2. Redirect sinks** (user-supplied URL as redirect target):
>
> - Python Flask: `redirect(variable)`, `return redirect(url_for(..., **kwargs))` where kwargs include user input
> - Django: `HttpResponseRedirect(variable)`, `redirect(variable)`
> - FastAPI: `RedirectResponse(url=variable)`
> - Node.js: `res.redirect(variable)`, `res.redirect(statusCode, variable)`
> - Java Servlet: `response.sendRedirect(variable)`
> - Spring: `return "redirect:" + variable` in a controller method, `RedirectView(variable)`
> - PHP: `header("Location: " . $variable)` — already covered above
> - Go: `http.Redirect(w, r, variable, statusCode)`
> - Rails: `redirect_to variable` or `redirect_to variable, allow_other_host: true`
> - ASP.NET: `Response.Redirect(variable)`, `return Redirect(variable)`
>
> **3. Cookie value sinks** (user value placed in a Set-Cookie header):
>
> - Python: `response.set_cookie(name, value=variable)` where variable comes from a parameter
> - Node.js: `res.cookie(name, variable)`
> - Java: `new Cookie(name, variable)` followed by `response.addCookie()`
> - PHP: `setcookie(name, $variable)`
> - Go: `http.SetCookie(w, &http.Cookie{Name: name, Value: variable})`
> - Rails: `cookies[name] = variable`
>
> **4. Raw log string interpolation** (user value embedded directly in a log message string):
>
> - Python: `logging.info(f"... {variable}")`, `logger.warning("text" + variable)`, `print(f"... {variable}")` inside request handlers
> - Node.js: `console.log("User: " + variable)`, `logger.info("Login: " + variable)`, `` logger.info(`Login: ${variable}`) ``
> - Java: `log.info("User: " + variable)` (string concatenation — **not** `log.info("User: {}", variable)` which is a bound parameter and safe)
> - PHP: `error_log("User: " . $variable)`
> - Go: `log.Printf("User: %s", variable)`, `fmt.Println("User: " + variable)`
> - Ruby: `Rails.logger.info("Login by: #{variable}")`, `logger.info("User: " + variable)`
>
> **What to skip** (these are safe construction patterns — do not flag):
> - Hardcoded literal header values: `response.headers['Content-Type'] = 'application/json'`
> - Structured log calls where the variable is a named field, not raw string fragment: `log.info("event", extra={"username": variable})`, `logger.info({ username: variable }, "msg")`, `log.info("msg: {}", variable)` (SLF4J / Logback bound param)
> - Responses where the only dynamic content is in the body, not in any header value
>
> **Output format** — write to `sast/crlf-recon.md`:
>
> ```markdown
> # CRLF Recon: [Project Name]
>
> ## Summary
> Found [N] locations where a response header, redirect target, cookie value, or log line is constructed with a variable.
>
> ## Sink Sites
>
> ### 1. [Descriptive name — e.g., "Header write in /greet route"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Sink type**: [header-write / redirect / cookie / log]
> - **Sink call**: [the specific API call — e.g., `response.headers['X-User'] = name`]
> - **Interpolated variable(s)**: `var_name` — [brief note: looks like a request param, unknown origin, etc.]
> - **Code snippet**:
>   ```
>   [the sink call with surrounding 2-3 lines of context]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/crlf-recon.md`. If the recon found **zero sink sites** (the summary reports "Found 0" or the "Sink Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/crlf-results.md` and `sast/crlf-results.json`, then stop:

```markdown
# CRLF Injection Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one sink site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/crlf-recon.md` and split the sink sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces user input only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/crlf-recon.md` and count the numbered site sections under "Sink Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/crlf-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned CRLF sink site, determine whether a user-supplied value can reach the sink without CR (`\r`) and LF (`\n`) characters being stripped or effectively neutralized. Our goal is to find CRLF injection / HTTP response splitting vulnerabilities. Write results to `sast/crlf-batch-[N].md`.
>
> **Your assigned sink sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, validation layers, and how data flows through the application.
>
> **CRLF reference — trace the interpolated variable(s) backwards to their origin**:
>
> **Step 1 — Identify the source**: Where does the variable at the sink originate?
>
> 1. **Direct user input** — the variable is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.args.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `r.URL.Query().Get("x")`
>    - Path parameters: `request.view_args['x']`, `req.params.x`, `params[:id]`, `c.Param("x")`
>    - Request body / form fields: `request.form.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers (including `Referer`, `User-Agent`, `X-Forwarded-For`): `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.cookies.get(...)`, `req.cookies.x`
>
> 2. **Indirect user input** — the variable is derived from user input through transformations, function calls, or intermediate assignments:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable read from a class attribute or shared state set elsewhere → find the setter
>    - Variable conditionally assigned — check all branches
>    - Variable that has passed through validation (e.g., email format check) but CR/LF stripping is not part of the validation
>
> 3. **Second-order input** — the variable is read from the database or a cache, but the stored value originally came from user input (e.g., a username stored at registration, then displayed in a header at login):
>    - Find where this value was written — did it come from a user-supplied field?
>    - Was CR/LF stripped before storage?
>
> 4. **Server-side / hardcoded value** — the variable comes from config, an environment variable, a hardcoded constant, or purely server-side logic with no user influence — this site is NOT exploitable.
>
> **Step 2 — Check for CR/LF mitigations between source and sink**:
>
> Even when user input clearly reaches the sink, the finding may be a false positive if one of these mitigations is in place. Check each one carefully:
>
> - **Explicit CR/LF stripping**: `.replace('\r', '').replace('\n', '')`, `.replace(/[\r\n]/g, '')`, `replaceAll("[\r\n]", "")`, `strings.NewReplacer("\r", "", "\n", "").Replace(...)` — this eliminates exploitability
> - **Percent-encoding of the value**: `urllib.parse.quote(value)` (Python), `encodeURIComponent(value)` (JS), `URLEncoder.encode(value, "UTF-8")` (Java) — if applied before the header write, CR (`%0d`) and LF (`%0a`) are safe as literal characters in the encoded string
> - **Allowlist redirect validation**: redirect target is validated against a known-safe set of origins or path prefixes before being used — eliminates exploitability for redirect sinks
> - **Structured logging**: the variable is a named field, not a raw string fragment — eliminates log poisoning (but does NOT protect against header-write sinks)
> - **Framework-level sanitization**: Go `net/http >=1.6` rejects headers containing bare `\r`/`\n` at the Set level; Werkzeug `>=2.1` encodes `\r`/`\n` in `Location` headers — record as a conditional mitigation with the verified version
>
> **FP killers — reasons NOT to flag**:
> - The value passes through a type cast that categorically excludes CR/LF (e.g., `int(value)`, `uuid.UUID(value)`, a regex-validated phone number)
> - The header is an HTTP/2 or HTTP/3 pseudo-header where the transport layer handles encoding
> - The sink is inside a test file or mock server with no production path
>
> **Severity and exploitability assignment**:
>
> - `severity: critical` — CR/LF in a `Set-Cookie` header value (session fixation, cookie injection); CR/LF that can rewrite the response body (full response splitting → reflected XSS)
> - `severity: high` — CR/LF in any other HTTP response header reaching an untrusted client (arbitrary header injection; can be chained with cache poisoning or open-redirect)
> - `severity: medium` — CR/LF in a log line with no HTTP response impact (log poisoning; audit trail corruption)
> - `exploitability: reachable` — the sink is reached via a publicly accessible HTTP request handler and the variable demonstrably comes from user input with no CR/LF stripping
> - `exploitability: conditional` — the variable comes from user input but a middleware or validation layer may strip CR/LF; the mitigation is framework-level and version-dependent; or the endpoint requires authentication (authenticated attacker)
> - `exploitability: unreachable` — the code path is only exercised by internal, server-controlled input
> - `exploitability: unknown` — cannot determine origin with confidence (opaque helpers, complex indirect flow)
> - `confidence: high` — direct `req.query/body → setHeader/redirect` with no transformation
> - `confidence: medium` — user input flows through 1-2 intermediate functions or variables before reaching the sink
> - `confidence: low` — complex indirect flow, cannot fully trace, or origin is ambiguous
>
> **chain_id values**:
> - `"crlf-redirect"` — CRLF in a redirect target that chains with `sast-openredirect` (the `\r\n` can inject a header AND the redirect is otherwise open)
> - `"crlf-xss"` — CRLF that enables response splitting with attacker-controlled body content, chaining into XSS
> - `null` — standalone CRLF finding with no chaining
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the sink with no CR/LF stripping or encoding, and the sink is in a production request path.
> - **Likely Vulnerable**: User input probably reaches the sink (indirect flow) but some path uncertainty exists; or a framework-level mitigation may apply but its version has not been confirmed.
> - **Not Vulnerable**: The variable is server-side only, OR effective CR/LF stripping / encoding / allowlist / typed cast is in place at or before the sink.
> - **Needs Manual Review**: Cannot determine the variable's origin or the existence of stripping with confidence (opaque helpers, complex flows, external libraries).
>
> **Output format** — write to `sast/crlf-batch-[N].md`:
>
> ```markdown
> # CRLF Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink type**: [header-write / redirect / cookie / log]
> - **Issue**: [e.g., "HTTP query param `name` flows directly into response header `X-Greeting-For` without CR/LF stripping"]
> - **Taint trace**: [Step-by-step from the request source to the sink — cite variable names and file:line at each step]
> - **Severity**: [critical / high / medium]
> - **Exploitability**: [reachable / conditional / unreachable / unknown]
> - **Confidence**: [high / medium / low]
> - **chain_id**: [crlf-redirect / crlf-xss / null]
> - **Impact**: [What an attacker can do — inject Set-Cookie, split response, poison logs, etc.]
> - **Proof-of-concept payload**:
>   ```
>   [Manual curl or HTTP request showing the injection. Example:
>    curl "https://app.example.com/greet?name=Alice%0d%0aSet-Cookie:+admin=1"
>    # Expected: HTTP response contains "X-Greeting-For: Alice\r\nSet-Cookie: admin=1"]
>   ```
> - **Remediation**: [Strip \r and \n before header assignment, or use percent-encoding, or validate redirect against allowlist]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink type**: [header-write / redirect / cookie / log]
> - **Issue**: [indirect flow or framework-version uncertainty]
> - **Taint trace**: [Best-effort trace; mark uncertain steps with "→ [unclear]"]
> - **Severity**: [critical / high / medium]
> - **Exploitability**: [reachable / conditional / unreachable / unknown]
> - **Confidence**: [high / medium / low]
> - **chain_id**: [crlf-redirect / crlf-xss / null]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Explicit CR/LF stripping or redirect allowlist]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink type**: [header-write / redirect / cookie / log]
> - **Reason**: [e.g., "Variable is a hardcoded server config value" or "`.replace('\r','').replace('\n','')` applied before header write at line 42"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink type**: [header-write / redirect / cookie / log]
> - **Uncertainty**: [Why origin or sanitization could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `build_header_value()` in utils.py to determine whether it strips CR/LF"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/crlf-batch-*.md` file and merge them into `sast/crlf-results.md` (human-readable) and `sast/crlf-results.json` (canonical schema). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/crlf-batch-1.md`, `sast/crlf-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/crlf-results.md` using this format:

```markdown
# CRLF Injection Analysis Results: [Project Name]

## Executive Summary
- Sink sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first (sorted by severity: critical → high → medium),
 then LIKELY VULNERABLE (same severity sort),
 then NEEDS MANUAL REVIEW,
 then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical JSON to `sast/crlf-results.json` using the schema below. Assign each finding a unique `id` of the form `crlf-1`, `crlf-2`, etc. (sequential across all batches, in the same order they appear in the merged human-readable report):

```json
{
  "findings": [
    {
      "id": "crlf-1",
      "skill": "sast-crlf",
      "severity": "critical|high|medium|low|info",
      "title": "short one-line description",
      "description": "full explanation including exploitability and taint path",
      "location": { "file": "relative/path/to/file.ext", "line": 42, "column": 5 },
      "remediation": "how to fix — strip \\r and \\n before header write, or use percent-encoding, or validate redirect against allowlist",
      "exploitability": "reachable|conditional|unreachable|unknown",
      "confidence": "high|medium|low",
      "chain_id": "crlf-redirect|crlf-xss|null"
    }
  ]
}
```

Include only **Vulnerable** and **Likely Vulnerable** findings in the JSON `findings` array. Do NOT include "Not Vulnerable" or "Needs Manual Review" entries in the JSON (they go in the markdown only). If there are no Vulnerable or Likely Vulnerable findings, write `"findings": []`.

6. After writing both output files, **delete all intermediate batch files** (`sast/crlf-batch-*.md`) and the recon file (`sast/crlf-recon.md`).

---

## chain_id Reference

| chain_id | Meaning |
|---|---|
| `crlf-redirect` | CRLF injection in a redirect `Location` header; chains with `sast-openredirect` because the target URL may also be an open redirect, compounding the exploit surface |
| `crlf-xss` | CRLF that enables HTTP response splitting; the injected content reaches the response body, enabling reflected XSS; chains with `sast-xss` |
| `null` | Standalone CRLF finding — header injection or log poisoning with no identified chain |

---

## Test Fixture Reference

The following illustrates the true positive / true negative distinction this skill must enforce:

**True Positive** (must be flagged, `exploitability: reachable`, `severity: high`):
```python
# Flask — direct query param into response header, no stripping
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    resp = make_response("Hello")
    resp.headers['X-Greeting-For'] = name   # VULNERABLE
    return resp
# Payload: GET /greet?name=Alice%0d%0aSet-Cookie:+admin=1
# Result: response contains injected Set-Cookie header
```

**True Negative** (must NOT be flagged):
```python
# Flask — CR/LF stripped before assignment
@app.route('/greet')
def greet():
    name = request.args.get('name', '').replace('\r', '').replace('\n', '')
    resp = make_response("Hello")
    resp.headers['X-Greeting-For'] = name   # SAFE
    return resp
```

Only the first example is flagged; the second is classified "Not Vulnerable".

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sink sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any sink call where a variable is used as a header value, redirect URL, cookie content, or log string — regardless of origin. Do not trace user input in Phase 1.
- **Phase 2 is purely taint analysis**: trace the variable at each sink back to its origin. If it comes from a user-controlled source and CR/LF stripping is absent, the site is a real vulnerability.
- CR and LF can arrive percent-encoded as `%0d` and `%0a` in URLs. Ensure that URL decoding before the header write is considered — if the value is decoded before reaching the sink but after any stripping, the stripping may be bypassed.
- Log poisoning (severity: medium) is a real finding even if it does not affect HTTP response headers. Flag it with sink type "log" and note that it does not chain with `crlf-xss` or `crlf-redirect`.
- Cookie value sinks are the most severe: injecting `\r\nSet-Cookie: session=attacker` from another header context can enable session fixation. Assign `severity: critical` and `chain_id: null` (or `crlf-xss` if response splitting can follow).
- For Go projects, note in the finding whether the detected Go version is `>=1.6` (which rejects bad headers at the net/http level). If version is unconfirmed or the code uses a custom transport that bypasses `http.Header.Set`, keep `exploitability: conditional`.
- For Werkzeug / Flask projects, note whether Werkzeug `>=2.1` is present (which encodes `\r`/`\n` in `Location` headers). If the dependency version is unconfirmed, keep `exploitability: conditional` rather than downgrading to "Not Vulnerable".
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in a security assessment.
- Taint can flow indirectly: a request parameter may be stored in a user profile object, passed to a helper function, and returned as a string later used in a header write. Trace the full chain.
- Do not confuse XSS (body output) with CRLF injection (header output). Only flag sinks that write to response headers, redirect targets, cookie values, or log lines — not HTML rendering.
- Clean up intermediate files: delete `sast/crlf-recon.md` and all `sast/crlf-batch-*.md` files after the final output files are written.
