---
name: sast-cookieflags
description: >-
  Detect session and authentication cookies set without the HttpOnly, Secure, or
  SameSite flags across Flask, Django, Express, Spring Boot, PHP, Rails, and .NET.
  Uses a three-phase approach: recon (find cookie-setting sinks and framework config
  that omits or negates required flags), batched verify (confirm the cookie carries
  auth/session state and the missing flag is exploitable, 3 sinks per subagent, in
  parallel), and merge (consolidate batch results into sast/cookieflags-results.md
  and sast/cookieflags-results.json with schema-v2 fields exploitability, confidence,
  and chain_id). Covers explicit set_cookie/setcookie calls, express-session config,
  framework security settings, and Spring CookieSpec. Does NOT flag non-sensitive
  client-readable cookies (analytics, locale, theme) or SameSite-absent cookies where
  an independent CSRF token is present and validated. Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/cookieflags-results.md and
  sast/cookieflags-results.json.
version: 0.1.0
---

# Missing Cookie Security Flags Detection

You are performing a focused security assessment to find session and authentication cookies set without the `HttpOnly`, `Secure`, or `SameSite` flags. This skill uses a three-phase approach with subagents: **recon** (find cookie-setting sinks and insecure framework config), **batched verify** (confirm session/auth purpose and exploitable flag absence, in parallel batches of 3), and **merge** (consolidate results into both a human-readable report and a machine-readable JSON file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it does not.

---

## What are Missing Cookie Security Flags

HTTP cookies used for session management, authentication, and CSRF protection must carry three security attributes:

- **HttpOnly**: Prevents JavaScript from reading the cookie via `document.cookie`. Its absence allows an XSS payload to exfiltrate the session token.
- **Secure**: Instructs the browser to transmit the cookie only over HTTPS. Its absence allows the cookie to be sent in plaintext over HTTP, enabling passive eavesdropping or network MITM attacks.
- **SameSite**: Controls whether the browser sends the cookie with cross-site requests. `Lax` blocks cross-origin POST requests (most CSRF); `Strict` blocks all cross-site requests including navigations; `None` (requires `Secure`) permits all cross-site requests and must be paired with explicit CSRF token validation.

The core pattern: *a cookie that carries session or auth state is set without one or more of these flags, widening the attack surface for XSS-based session theft, network eavesdropping, or cross-site request forgery.*

### What this skill IS

- `set_cookie(name, value)` calls in Flask, Werkzeug, or raw WSGI responses missing `httponly=True`, `secure=True`, or `samesite='Lax'`
- Django settings `SESSION_COOKIE_HTTPONLY = False`, `SESSION_COOKIE_SECURE = False`, `SESSION_COOKIE_SAMESITE` absent or `None`
- Django settings `CSRF_COOKIE_HTTPONLY`, `CSRF_COOKIE_SECURE` set to `False` or not set when the site is HTTPS
- Express `res.cookie('session', val, {})` calls missing `httpOnly: true`, `secure: true`, or `sameSite: 'lax'`
- `express-session` / `cookie-session` configured without `cookie: { httpOnly: true, secure: true, sameSite: 'lax' }`
- Spring Security `http.sessionManagement()` without `cookieSerializer.setHttpOnly(true)` / `.setSecure(true)`, or `new Cookie(name, val)` without `setHttpOnly(true)` and `setSecure(true)`
- PHP `setcookie(name, value, expiry, path, domain)` (old positional form) missing the 7th and 8th arguments; `setcookie(name, value, options_array)` (PHP 7.3+) missing `'httponly' => true`, `'secure' => true`, `'samesite' => 'Lax'`
- PHP `session.cookie_httponly = 0` or `session.cookie_secure = 0` in `php.ini` / `ini_set`
- Rails `cookies[:session] = { value: val }` without `httponly: true, secure: true, same_site: :lax`
- Rails `config.session_store` options omitting `:secure` or `:httponly`
- ASP.NET `new CookieOptions { HttpOnly = false }` or `CookieOptions` missing `Secure = true`, `SameSite = SameSiteMode.Lax`

### What this skill is NOT

Do not flag these patterns:

- **Non-sensitive client-readable cookies**: Analytics tags (`_ga`, `_gid`), locale/language preferences (`lang`, `locale`), theme/UI preference cookies (`theme`, `dark_mode`) — these carry no auth impact. JavaScript legitimately needs to read them, so `HttpOnly` must NOT be set.
- **Cookies explicitly scoped to HTTP-only internal loopback services**: Services operating exclusively over HTTP on a private subnet where the `Secure` flag is architecturally N/A. Verify from `sast/architecture.md` — if TLS is deployed, `Secure` is still required.
- **SameSite absent with validated CSRF token**: When `SameSite` is not set (or is `None`) AND the application independently validates a CSRF token (CSRF double-submit cookie, synchronizer token pattern, `Django CsrfViewMiddleware` active with `CSRF_COOKIE_SAMESITE = None`), the CSRF risk is mitigated. Still flag the XSS / eavesdropping risks (`HttpOnly` / `Secure`) if missing.
- **Framework secure defaults already covering the cookie**: Several frameworks set `HttpOnly` and `Secure` by default for session cookies. If the codebase only creates session cookies through the framework's built-in session API (no explicit override), and the security settings are at their defaults or hardened, do NOT flag as a vulnerability (see FP-killers below).
- **`SameSite=None; Secure`** on cookies that need cross-origin access (OAuth callbacks, payment iframes): This is a legitimate combination when paired with explicit CSRF protection; do not flag the `SameSite=None` in isolation.

### Framework Secure Default FP-Killers

These framework behaviors produce safe defaults that eliminate otherwise-suspicious findings:

| Framework | Session cookie defaults | Only flag if explicitly overridden |
|---|---|---|
| Django >= 1.10 | `SESSION_COOKIE_HTTPONLY = True` | `SESSION_COOKIE_HTTPONLY = False` explicitly set |
| Django >= 2.1 | `SESSION_COOKIE_SAMESITE = 'Lax'` | Changed to `False` / `None` without CSRF token |
| Django | `SESSION_COOKIE_SECURE = False` (requires explicit opt-in) | Always flag if site serves HTTPS and `SECURE_SSL_REDIRECT` or `SECURE_HSTS_SECONDS` is set |
| Flask / Werkzeug | No defaults — all flags must be explicit | Flag any `set_cookie` on session/auth cookies missing flags |
| `flask-session` / `itsdangerous` session | `SESSION_COOKIE_HTTPONLY = True` default when `Flask.secret_key` set | Flag if `SESSION_COOKIE_HTTPONLY = False` in config |
| Express (`express-session`) | `httpOnly: true` default, `secure: false` default | Flag missing `secure: true` if HTTPS is used; flag explicit `httpOnly: false` |
| Spring Security >= 5 | `http.headers().httpStrictTransportSecurity()` + `cookieSameSite` configurable | Flag if `.httpOnly(false)` called or `setHttpOnly(false)` on manual Cookie |
| Rails >= 6 | `session_options[:httponly] = true` default | Flag `httponly: false` override |
| Laravel | `config/session.php`: `'http_only' => true` | Flag `'http_only' => false` |
| ASP.NET Core | `CookieAuthenticationOptions.Cookie.HttpOnly = true` default | Flag explicit `HttpOnly = false` |
| PHP (built-in session) | `session.cookie_httponly = 0` (insecure default) | Always flag unless `ini_set('session.cookie_httponly', '1')` or `php.ini` sets to `1` |

---

## Vulnerable vs. Secure Examples

### Python — Flask

```python
# VULNERABLE: HttpOnly and Secure absent, SameSite absent
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    response = make_response(redirect('/dashboard'))
    response.set_cookie('session_id', generate_session(user))
    # Missing: httponly=True, secure=True, samesite='Lax'
    return response

# VULNERABLE: Explicit opt-out of HttpOnly via config
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False

# SECURE: All three flags set
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    response = make_response(redirect('/dashboard'))
    response.set_cookie(
        'session_id',
        generate_session(user),
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=3600,
    )
    return response

# SECURE: Via Flask config (applies to flask.session cookie)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

### Python — Django Settings

```python
# VULNERABLE: Explicitly disabling secure defaults
SESSION_COOKIE_HTTPONLY = False   # CWE-1004: JS can read session cookie
SESSION_COOKIE_SECURE = False     # CWE-614: cookie sent over HTTP (on HTTPS site)
SESSION_COOKIE_SAMESITE = None    # CSRF risk — no SameSite protection
CSRF_COOKIE_SECURE = False        # CSRF cookie also unprotected

# VULNERABLE: SameSite missing entirely (older Django or misconfigured)
# SESSION_COOKIE_SAMESITE not defined anywhere in settings

# SECURE: Hardened Django session settings
SESSION_COOKIE_HTTPONLY = True    # default, but explicit is better
SESSION_COOKIE_SECURE = True      # required when serving HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'  # or 'Strict' for sensitive apps
CSRF_COOKIE_HTTPONLY = False      # intentionally False for JS CSRF-token reading
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

### Node.js — Express with express-session

```javascript
// VULNERABLE: httpOnly not set (false by default in some configs), secure missing
const session = require('express-session');
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,   // explicitly disabled — JS can read cookie
    secure: false,     // cookie transmitted over HTTP even on HTTPS
    // sameSite absent — CSRF risk
  }
}));

// VULNERABLE: res.cookie on an auth token without flags
app.post('/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('auth_token', token, { maxAge: 86400000 });
  // Missing: httpOnly: true, secure: true, sameSite: 'lax'
  res.json({ success: true });
});

// SECURE: express-session with all flags
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,        // set to true when behind HTTPS (use trust proxy)
    sameSite: 'lax',
    maxAge: 3600000,
  }
}));
app.set('trust proxy', 1);  // required for secure: true behind a reverse proxy

// SECURE: res.cookie with all flags
app.post('/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 86400000,
  });
  res.json({ success: true });
});
```

### Java — Spring Boot / Spring Security

```java
// VULNERABLE: Manual Cookie without HttpOnly or Secure
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
    String token = authService.authenticate(req);
    Cookie cookie = new Cookie("SESSION", token);
    cookie.setPath("/");
    cookie.setMaxAge(3600);
    // Missing: cookie.setHttpOnly(true); cookie.setSecure(true);
    response.addCookie(cookie);
    return ResponseEntity.ok().build();
}

// VULNERABLE: Spring Security session management without cookie hardening
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        // Missing cookie flags configuration
        return http.build();
    }
}

// VULNERABLE: application.properties — HttpOnly disabled
// server.servlet.session.cookie.http-only=false
// server.servlet.session.cookie.secure=false
// server.servlet.session.cookie.same-site=none

// SECURE: application.properties
// server.servlet.session.cookie.http-only=true
// server.servlet.session.cookie.secure=true
// server.servlet.session.cookie.same-site=lax

// SECURE: Manual Cookie with all flags
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req, HttpServletResponse response) {
    String token = authService.authenticate(req);
    Cookie cookie = new Cookie("SESSION", token);
    cookie.setPath("/");
    cookie.setMaxAge(3600);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    // SameSite requires Spring 5.2+: response.setHeader("Set-Cookie", ...) or CookieSerializer
    response.addCookie(cookie);
    return ResponseEntity.ok().build();
}

// SECURE: Spring Security cookie serializer
@Bean
public DefaultCookieSerializer cookieSerializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setHttpOnly(true);
    serializer.setUseSecureCookie(true);
    serializer.setSameSite("Lax");
    return serializer;
}
```

### PHP — setcookie and session config

```php
<?php
// VULNERABLE: Old positional-arg form — no httponly or secure flag
setcookie('session_id', $sessionValue, time() + 3600, '/');
// 7th arg (secure) and 8th arg (httponly) defaulting to false

// VULNERABLE: New options-array form — flags absent or false
setcookie('session_id', $sessionValue, [
    'expires' => time() + 3600,
    'path' => '/',
    // 'secure' => true,   // missing — cookie sent over HTTP
    // 'httponly' => true, // missing — JS can access cookie
    // 'samesite' => 'Lax' // missing — CSRF risk
]);

// VULNERABLE: session.cookie_httponly not set (PHP default is 0)
ini_set('session.cookie_httponly', '0');
ini_set('session.cookie_secure', '0');
session_start();

// SECURE: setcookie with all options
setcookie('session_id', $sessionValue, [
    'expires'  => time() + 3600,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);

// SECURE: session cookie hardening before session_start()
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Lax');
session_start();
```

### Ruby on Rails

```ruby
# VULNERABLE: Manual cookie missing flags
class SessionsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    cookies[:auth_token] = {
      value: user.generate_token,
      expires: 1.hour.from_now,
      # httponly: true,   # missing — JS can read
      # secure: true,     # missing — sent over HTTP
      # same_site: :lax,  # missing — CSRF risk
    }
    redirect_to dashboard_path
  end
end

# VULNERABLE: config/initializers/session_store.rb — insecure options
Rails.application.config.session_store :cookie_store,
  key: '_app_session',
  expire_after: 2.hours
  # secure: true is missing
  # httponly defaults to true in Rails but can be overridden

# SECURE: cookie with all flags
cookies[:auth_token] = {
  value: user.generate_token,
  expires: 1.hour.from_now,
  httponly: true,
  secure: true,
  same_site: :lax,
}

# SECURE: config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: '_app_session',
  expire_after: 2.hours,
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax
```

### .NET — ASP.NET Core

```csharp
// VULNERABLE: CookieOptions with HttpOnly disabled or Secure absent
[HttpPost("login")]
public IActionResult Login([FromBody] LoginRequest request)
{
    var token = _authService.Authenticate(request);
    Response.Cookies.Append("auth_token", token, new CookieOptions
    {
        HttpOnly = false,    // JS can read the cookie
        Secure = false,      // cookie transmitted over HTTP
        // SameSite not set — defaults to SameSiteMode.Unspecified
        Expires = DateTimeOffset.UtcNow.AddHours(1),
    });
    return Ok();
}

// VULNERABLE: Program.cs cookie authentication without secure options
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = false;
        options.Cookie.SecurePolicy = CookieSecurePolicy.None;
        options.Cookie.SameSite = SameSiteMode.None;
    });

// SECURE: CookieOptions with all flags
Response.Cookies.Append("auth_token", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax,
    Expires = DateTimeOffset.UtcNow.AddHours(1),
});

// SECURE: Program.cs cookie authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
    });
```

---

## Cookie Name Patterns That Indicate Session/Auth Cookies

Use these to assess whether an individual cookie is security-sensitive:

**High confidence — almost certainly session/auth:**
- Contains `session`, `sess`, `sid`, `Session`
- Contains `auth`, `token`, `tok`, `jwt`, `access`, `refresh`
- Contains `login`, `user`, `uid`, `identity`
- Named exactly: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `_session_id`
- Named exactly: `remember_me`, `remember_token`, `remember_user_token`

**Medium confidence — likely sensitive depending on context:**
- Contains `id` (e.g., `user_id`, `account_id`) — check if it controls authorization
- Contains `key`, `secret`, `credential`
- Framework-specific session cookie names: `connect.sid` (Express), `rack.session` (Rack/Rails), `csrftoken` (Django)

**Low confidence / likely non-sensitive — do not flag unless context shows auth use:**
- `lang`, `locale`, `i18n`, `timezone`
- `theme`, `dark_mode`, `preferences`, `prefs`
- `_ga`, `_gid`, `_gat`, `__utm*` (Google Analytics)
- `cookieconsent`, `cookie_notice`, `gdpr`
- `cart_id`, `basket_id` (unless tied to authenticated checkout — check context)

---

## Severity Classification

| Scenario | Severity | CWE |
|---|---|---|
| `HttpOnly` absent on session/auth cookie | **High** | CWE-1004 |
| `Secure` absent on session/auth cookie on HTTPS site | **Critical** | CWE-614 |
| Both `HttpOnly` and `Secure` absent | **Critical** | CWE-1004 + CWE-614 |
| `SameSite` absent/`None` with no independent CSRF defense | **Medium** | CWE-1004 |
| `SameSite` absent but CSRF token present and validated | **Low** (informational) | CWE-1004 |
| Framework default overridden to insecure value | Use same scale as above based on which flags | — |

Severity adjustments:
- Raise to **Critical** when `Secure` is absent AND the site provably serves HTTPS (look for `SECURE_SSL_REDIRECT`, `hsts`, `listen 443` in nginx/caddy config, or `HTTPS=true` in env)
- Lower one level when the endpoint is only reachable over an internal private network (no public internet exposure documented in architecture)
- Raise one level when `sast-xss` has flagged XSS vulnerabilities in the same codebase (`chain_id: "xss-session-theft"`) — missing `HttpOnly` becomes directly exploitable

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Cookie-Setting Sinks and Insecure Configuration

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a cookie is explicitly set (or where session cookie security settings are configured at the framework level) in a way that may omit or negate the `HttpOnly`, `Secure`, or `SameSite` flags on a session or authentication cookie. Write results to `sast/cookieflags-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, the frameworks in use, and the session management approach. This shapes which sinks are relevant.
>
> **What to search for — cookie-setting sinks and insecure config patterns**:
>
> Your goal in this phase is purely structural: find every candidate sink, configuration key, or explicit flag. Do NOT yet determine whether the cookie is actually sensitive or whether a framework default covers the gap — that is Phase 2's job.
>
> **1. Explicit `set_cookie` / `setcookie` / `res.cookie` API calls**
>
> Look for calls to cookie-setting functions where the options argument is missing, empty, or visibly omits one or more of the three security flags:
>
> - Python/Flask: `response.set_cookie(`, `.set_cookie(` — capture all arguments
> - Node.js/Express: `res.cookie(` — capture all option arguments
> - PHP: `setcookie(` — capture all positional args or the options array
> - Rails: `cookies[` assignment — capture the options hash
> - Java/Spring: `new Cookie(`, `response.addCookie(`, `.addCookie(` — check for `setHttpOnly`/`setSecure` calls
> - .NET: `Response.Cookies.Append(`, `new CookieOptions` — capture all properties
>
> **2. Framework session/cookie security configuration keys**
>
> Grep for these configuration settings explicitly set to insecure values or absent from settings files:
>
> - Django: `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE`, `CSRF_COOKIE_HTTPONLY`, `CSRF_COOKIE_SECURE`, `CSRF_COOKIE_SAMESITE` in `settings.py` / `settings/` directory
> - Flask: `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE` in `app.config`
> - PHP: `session.cookie_httponly`, `session.cookie_secure`, `session.cookie_samesite` in `php.ini`, `.htaccess`, or `ini_set(` calls
> - Spring Boot: `server.servlet.session.cookie.http-only`, `server.servlet.session.cookie.secure`, `server.servlet.session.cookie.same-site` in `application.properties` / `application.yml`
> - ASP.NET Core: `options.Cookie.HttpOnly`, `options.Cookie.SecurePolicy`, `options.Cookie.SameSite` in `Program.cs` / `Startup.cs`
> - Rails: `config.session_store` options, `ActionDispatch::Session::CookieStore` configuration
> - express-session: `cookie:` property in session middleware config
>
> **3. Middleware/filter classes that set session cookies globally**
>
> - Spring Security `SessionManagementConfigurer` or `HttpSessionSecurityContextRepository`
> - .NET `CookieAuthenticationOptions`
> - Rack session middleware in Rails
> - Django `SessionMiddleware` — only flag if settings explicitly override defaults
>
> **Patterns to note about each sink**:
> - What cookie name or session key is being set
> - Which flags are explicitly present vs. absent vs. explicitly set to insecure values
> - Whether this is a framework-level config (applies to all session cookies) or a per-call override
>
> **Output format** — write to `sast/cookieflags-recon.md`:
>
> ```markdown
> # Cookie Flags Recon: [Project Name]
>
> ## Summary
> Found [N] cookie-setting sinks and [M] framework configuration entries that may omit or negate security flags.
>
> ## Sinks and Configuration Entries
>
> ### 1. [Descriptive name — e.g., "res.cookie in POST /login handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / route**: [function name or route pattern]
> - **Type**: [explicit API call / framework config / middleware]
> - **Cookie name / key**: [name if determinable, or "unknown" / "session (framework-managed)"]
> - **Flags explicitly set**: [e.g., "httpOnly: false, secure: true, sameSite absent"]
> - **Flags potentially absent**: [e.g., "Secure, SameSite"]
> - **Code snippet**:
>   ```
>   [the relevant cookie-setting call or config assignment]
>   ```
>
> [Repeat for each sink or config entry]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/cookieflags-recon.md`. If the recon found **zero sinks and zero configuration entries** (the summary reports "Found 0" or the sections are empty or absent), **skip Phase 2 entirely**. Instead, write the following to `sast/cookieflags-results.md` and `sast/cookieflags-results.json`, then stop:

```markdown
# Cookie Flags Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Confirm Session/Auth Purpose and Exploitable Flag Absence (Batched)

After Phase 1 completes, read `sast/cookieflags-recon.md` and split the sinks and config entries into **batches of up to 3 each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/cookieflags-recon.md` and count the numbered entries under "Sinks and Configuration Entries" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 entries → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those entry sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned entries.
5. Each subagent writes to `sast/cookieflags-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary framework from `sast/architecture.md` and include relevant framework FP-killer defaults (from the table in the "Framework Secure Default FP-Killers" section above) in each subagent's instructions where indicated by `[FRAMEWORK FP-KILLERS]` below.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: For each assigned cookie-setting sink or framework configuration entry, determine whether the cookie is used for session management or authentication AND whether one or more security flags (`HttpOnly`, `Secure`, `SameSite`) are absent or set to an insecure value with no framework default or other control compensating for it. Write results to `sast/cookieflags-batch-[N].md`.
>
> **Your assigned sinks / config entries** (from the recon phase):
>
> [Paste the full text of the assigned entry sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to determine whether the application serves HTTPS, how session management is wired, and whether compensating CSRF controls exist.
>
> **Verification questions to answer for each candidate**:
>
> **Q1 — Is this cookie session/auth-sensitive?**
> - Does the cookie name match a high-confidence pattern (see cookie name pattern table)?
> - Is the cookie value a session ID, authentication token, JWT, or access credential?
> - Does the function that sets this cookie appear in an authentication or session management flow (login, logout, token refresh, OAuth callback)?
> - If the cookie is framework-managed (e.g., Django `SESSION_COOKIE_*`), it is by definition session/auth-sensitive.
>
> If the answer is clearly NO (analytics, locale, theme cookie with no auth use), classify as **Not Vulnerable** and explain why.
>
> **Q2 — Is `HttpOnly` absent or explicitly `false`?**
> - For explicit calls: is `httponly=True` / `httpOnly: true` / `HttpOnly = true` present in the call?
> - For framework config: is `SESSION_COOKIE_HTTPONLY = True` (Django) / `http-only: true` (Spring) / `'httponly' => true` (PHP) / `httponly: true` (Rails) present?
> - Is the framework's default `HttpOnly=true` (check the FP-killer table), and is there no explicit override to `false`? If so, NOT vulnerable for this flag.
>
> **Q3 — Is `Secure` absent or explicitly `false`?**
> - Same check as Q2 but for the `Secure` flag.
> - Does the application serve HTTPS? Look in `sast/architecture.md` for TLS configuration, `SECURE_SSL_REDIRECT`, `hsts` config, or proxy/load balancer setup. If the site is HTTPS-enabled and `Secure` is absent or `false`, this is a real vulnerability.
> - If the application operates exclusively over HTTP (internal service, development-only), `Secure` is N/A — classify as Not Vulnerable for this specific flag.
>
> **Q4 — Is `SameSite` absent, `None`, or set to a value that does not mitigate CSRF?**
> - `SameSite=Lax` or `SameSite=Strict` mitigates CSRF. If present, not vulnerable for CSRF.
> - `SameSite=None` permits cross-site requests. Only acceptable when `Secure` is also set AND explicit CSRF token validation is in place (look for Django `CsrfViewMiddleware`, Express `csurf` / `csrf` middleware, Spring Security `csrf()` enabled, Rails `protect_from_forgery`).
> - If `SameSite` is absent entirely: check whether the Django/Rails/Express CSRF middleware is active globally. If yes, downgrade to **Low** (informational). If no CSRF protection exists, **Medium**.
>
> **FP-Killers — framework defaults and compensating controls**:
>
> [FRAMEWORK FP-KILLERS]
>
> Additional FP patterns to apply:
> - For a `set_cookie` / `res.cookie` call: the framework may apply `HttpOnly` and `Secure` globally via middleware (e.g., `app.use(helmet())` in Express, `SESSION_COOKIE_HTTPONLY = True` in Django settings). Check whether a global middleware or framework default would cover this specific call. If so, do NOT flag.
> - A cookie set with `httpOnly: false` that is demonstrably a non-session UI cookie (value is `'light'` or `'dark'`, name is `theme`) is NOT vulnerable — JS must be able to read it.
> - `SameSite=None; Secure` is a valid combination for OAuth/payment flows that require cross-origin access. Check whether the endpoint is an OAuth callback or payment redirect.
>
> **Setting exploitability and confidence**:
>
> - `exploitability: reachable` — the cookie is confirmed as a session/auth cookie, the flag is absent or negated, and no compensating control covers the gap.
> - `exploitability: conditional` — the cookie appears to be session-sensitive but the flag is covered by a possible framework default whose exact value in production cannot be confirmed from static analysis.
> - `exploitability: unreachable` — the cookie is non-sensitive (analytics/theme/locale) or the missing flag is N/A (no HTTPS on HTTP-only internal service).
> - `exploitability: unknown` — cannot determine cookie purpose or production framework configuration from static analysis.
>
> - `confidence: high` — explicit `httponly=False` / `secure=False` in the code, OR a framework config key explicitly set to an insecure value.
> - `confidence: medium` — flag is absent (not set at all, relying on a default that may or may not be set elsewhere in config), or cookie purpose inferred from name/context rather than confirmed from call site logic.
> - `confidence: low` — cookie purpose unclear, framework default behavior uncertain, or flag presence/absence requires runtime inspection.
>
> **chain_id assignment**:
> - If `HttpOnly` is absent or `false`: `"chain_id": "xss-session-theft"` (chains with `sast-xss`)
> - If `SameSite` is absent or `None` without CSRF token: `"chain_id": "csrf-cookie"` (chains with `sast-csrf`)
> - If both `HttpOnly` and `Secure` are absent: set to `"xss-session-theft"` (the XSS chain is the primary risk)
> - If only `Secure` is missing: `"chain_id": null`
>
> **Output format** — write to `sast/cookieflags-batch-[N].md`:
>
> ```markdown
> # Cookie Flags Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / route**: [function name or route pattern]
> - **Cookie name**: [name or "session (framework-managed)"]
> - **Missing or insecure flags**: [e.g., "HttpOnly=false, Secure absent"]
> - **Severity**: [critical / high / medium / low]
> - **CWE**: [CWE-1004 / CWE-614 / both]
> - **Exploitability**: [reachable / conditional / unreachable / unknown]
> - **Confidence**: [high / medium / low]
> - **Chain ID**: ["xss-session-theft" / "csrf-cookie" / null]
> - **Impact**: [e.g., "XSS payload can read the session cookie and exfiltrate to attacker server"]
> - **Evidence**: [Why this cookie is session/auth-sensitive and which flag is missing/negated]
> - **Remediation**: [Framework-specific fix with code example]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / route**: [function name or route pattern]
> - **Cookie name**: [name or inferred purpose]
> - **Missing or insecure flags**: [which flags are suspect]
> - **Severity**: [estimated severity]
> - **CWE**: [CWE-1004 / CWE-614]
> - **Exploitability**: conditional
> - **Confidence**: medium
> - **Chain ID**: [appropriate value or null]
> - **Concern**: [What makes this suspect — e.g., framework default uncertain, flag may be covered by config elsewhere]
> - **Remediation**: [Explicit flag recommendation]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Cookie name**: [name]
> - **Reason**: [e.g., "Framework default covers HttpOnly; SESSION_COOKIE_HTTPONLY not overridden" or "Analytics cookie — no auth impact"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Cookie name**: [name or "unknown"]
> - **Uncertainty**: [Why purpose or flag state cannot be determined from static analysis]
> - **Suggestion**: [What to inspect at runtime or in additional config files]
> ```

### Phase 3: Merge — Consolidate Batch Results and Write Both Output Files

After **all** Phase 2 batch subagents complete, read every `sast/cookieflags-batch-*.md` file and merge them into both `sast/cookieflags-results.md` (human-readable) and `sast/cookieflags-results.json` (machine-readable canonical). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/cookieflags-batch-1.md`, `sast/cookieflags-batch-2.md`, ... files.
2. Collect all findings from each batch file, preserving all detail fields.
3. Assign a sequential finding ID: `cookieflags-001`, `cookieflags-002`, etc., ordered by severity (critical first, then high, medium, low, informational).
4. Write the merged human-readable report to `sast/cookieflags-results.md`:

```markdown
# Cookie Flags Analysis Results: [Project Name]

## Executive Summary
- Sinks and config entries analyzed: [total]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the machine-readable canonical JSON to `sast/cookieflags-results.json`:

```json
{
  "findings": [
    {
      "id": "cookieflags-001",
      "skill": "sast-cookieflags",
      "severity": "critical",
      "title": "Session cookie set without Secure and HttpOnly flags in POST /login handler",
      "description": "The `auth_token` cookie is set without `httpOnly: true` and `secure: true`. An XSS payload on the same origin can exfiltrate the session token via `document.cookie`. Additionally, because `Secure` is absent, the cookie is transmitted in cleartext if the browser makes any HTTP request to the origin.",
      "location": { "file": "src/routes/auth.js", "line": 42, "column": 3 },
      "remediation": "Add `httpOnly: true, secure: true, sameSite: 'lax'` to the cookie options object. Ensure `app.set('trust proxy', 1)` is set if the app is behind a reverse proxy.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "xss-session-theft"
    }
  ]
}
```

Every finding from the batch files must appear in the JSON array. If a batch finding was classified [NOT VULNERABLE], omit it from the JSON (the JSON is findings-only). If a batch finding was [NEEDS MANUAL REVIEW], include it with `"severity": "info"`, `"exploitability": "unknown"`, and `"confidence": "low"`.

6. After writing both output files, **delete all intermediate batch files** (`sast/cookieflags-batch-*.md`) and the recon file (`sast/cookieflags-recon.md`).

---

## Remediation Reference

### Flask
```python
# In app config (applies globally to flask.session)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)
# For manual cookies
response.set_cookie('session_id', value, httponly=True, secure=True, samesite='Lax')
```

### Django
```python
# settings.py
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True      # requires HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = False      # must be readable by JS for AJAX CSRF token
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'Lax'
```

### Express / Node.js
```javascript
// express-session
app.use(require('express-session')({
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
  resave: false,
  saveUninitialized: false,
}));
app.set('trust proxy', 1);  // required behind nginx/caddy/ALB

// Manual cookie
res.cookie('auth', token, { httpOnly: true, secure: true, sameSite: 'lax' });
```

### Spring Boot
```properties
# application.properties
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=lax
```

```java
// For manually created cookies
Cookie cookie = new Cookie("SESSION", token);
cookie.setHttpOnly(true);
cookie.setSecure(true);
response.addCookie(cookie);
// Add SameSite via header (Spring 5.2+)
response.setHeader("Set-Cookie",
    String.format("SESSION=%s; Path=/; HttpOnly; Secure; SameSite=Lax", token));
```

### PHP
```php
// Before session_start()
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Lax');
session_start();

// Or via options array (PHP 7.3+)
setcookie('session_id', $value, [
    'expires'  => time() + 3600,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
```

### Rails
```ruby
# config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: '_app_session',
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax

# Manual cookies
cookies[:auth_token] = {
  value: token,
  httponly: true,
  secure: true,
  same_site: :lax,
  expires: 1.hour.from_now,
}
```

### .NET ASP.NET Core
```csharp
// Program.cs
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
    });

// Manual
Response.Cookies.Append("auth", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax,
    Expires = DateTimeOffset.UtcNow.AddHours(1),
});
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context. The deployment model (HTTPS vs HTTP, reverse proxy, cloud-managed TLS) directly affects whether the `Secure` flag absence is exploitable.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sinks/config entries per subagent**. If there are 1-3 total, use a single subagent.
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned entries' text from the recon file, not the entire recon file.
- **Phase 1 is purely structural**: find every cookie-setting call and every relevant config key. Do not assess sensitivity or flag exploitability in Phase 1.
- **Phase 2 applies judgment**: determine cookie sensitivity, whether framework defaults compensate, and whether the missing flag is exploitable given the deployment context.
- Framework secure defaults are a key FP source. Django's `SESSION_COOKIE_HTTPONLY = True` default eliminates a finding unless an explicit override exists. Know the defaults for each framework (see FP-killers table).
- Non-sensitive cookies (analytics, locale, theme) are the other major FP source. A cookie named `theme` with a value of `'dark'` that JS reads to render the UI is intentionally `HttpOnly=false` — do not flag it.
- `SameSite=None; Secure` is legitimate for OAuth and payment flows. Check the endpoint purpose before flagging.
- When `sast/cookieflags-results.json` is written, every finding must include the schema-v2 fields `exploitability`, `confidence`, and `chain_id` (null if not applicable). Write `"findings": []` if no findings were confirmed.
- Clean up intermediate files: delete `sast/cookieflags-recon.md` and all `sast/cookieflags-batch-*.md` after both final output files are written.
- The `chain_id` values `"xss-session-theft"` and `"csrf-cookie"` are shared with `sast-xss` and `sast-csrf` respectively. When both skills are run in the same SAST session, the report aggregator can correlate findings by `chain_id` to surface compound attack chains.
