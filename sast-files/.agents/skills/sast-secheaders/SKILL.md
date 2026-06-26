---
name: sast-secheaders
description: >-
  Detect missing or misconfigured HTTP security headers that weaken defence-in-depth protections
  against clickjacking, content-type sniffing, protocol downgrade, XSS, and CDN supply-chain
  attacks using a three-phase approach: recon (find every route, middleware registration, and HTML
  template where a critical security header is absent or explicitly disabled), batched verify
  (determine in parallel whether each candidate serves HTML or framing-capable content, 3 candidates
  each, and whether the absence is a real gap versus a compensating control), and merge (consolidate
  batch results into sast/secheaders-results.md and sast/secheaders-results.json). Covers Express
  (Helmet), Django (SECURE_* settings, django-csp), Flask (Talisman), Spring Security
  (http.headers()), Rails (secure_headers), and CDN SRI. Requires sast/architecture.md (run
  sast-analysis first). Outputs findings to sast/secheaders-results.md and
  sast/secheaders-results.json. Use when asked to find clickjacking exposure, missing HSTS, absent
  CSP, or CWE-693 / CWE-1021 issues.
version: 0.1.0
---

# Missing Security Headers Detection

You are performing a focused security assessment to find HTTP responses that are missing one or more critical browser-facing security headers. This skill uses a three-phase approach with subagents: **recon** (find every location where a critical header is absent, disabled, or set to a permissive value), **batched verify** (determine whether each candidate actually serves HTML and whether compensating controls exist), and **merge** (consolidate batch reports into `sast/secheaders-results.md` and `sast/secheaders-results.json`).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What Are Missing Security Headers

Modern browsers enforce a set of HTTP response headers that restrict how pages can be embedded, what scripts can run, and whether connections can be downgraded. When a web application omits or misconfigures these headers, it leaves users exposed to well-understood attacks that browsers would otherwise block automatically.

The five header categories this skill targets:

1. **Clickjacking protection** (`X-Frame-Options` or CSP `frame-ancestors`): Without one of these, a malicious page can embed the application in a transparent `<iframe>` and trick users into clicking UI elements they can't see — stealing clicks, redirecting transactions, or triggering state-changing actions.
2. **Content-type sniffing** (`X-Content-Type-Options: nosniff`): Without this header, some browsers will "sniff" a response body to guess its MIME type, potentially executing a script disguised as an image or text file uploaded by an attacker.
3. **Protocol downgrade / HSTS** (`Strict-Transport-Security`): Without HSTS, an active network attacker can intercept the first HTTP request (before the redirect to HTTPS) and strip TLS for the entire session — a classic SSL-stripping attack.
4. **Inline XSS via CSP** (`Content-Security-Policy`): A CSP restricts which origins may load scripts, styles, fonts, and frames. Without it, any XSS payload that executes inline or loads from an attacker-controlled CDN is unblocked at the browser level.
5. **CDN supply-chain integrity** (`integrity` / SRI on `<script>` and `<link>` tags): Without Subresource Integrity checks on external CDN references, a compromised CDN can silently serve a backdoored version of a library to all users.

The core pattern: *a server sends an HTML response to a browser without one or more of these headers, or explicitly configures the header to its least-safe value.*

### What Missing Security Headers IS

- An Express application that never calls `app.use(helmet())` and does not manually set `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, or `X-Content-Type-Options`
- A Django project with `SECURE_HSTS_SECONDS = 0` (default) in `settings.py`, meaning the `Strict-Transport-Security` header is never sent
- A Django project with `X_FRAME_OPTIONS` missing or set to something other than `'DENY'` or `'SAMEORIGIN'`
- A Flask application that does not use `flask-talisman` and has no `@app.after_request` hook setting security headers
- A Spring Security configuration that calls `http.headers().disable()` or `http.headers().frameOptions().disable()`
- A Spring Security configuration that never calls `http.headers().contentSecurityPolicy(...)` for HTML endpoints
- A Rails application where `config.action_dispatch.default_headers` does not include `X-Frame-Options` and `X-Content-Type-Options`
- An HTML template with `<script src="https://cdn.example.com/lib.min.js">` that has no `integrity="sha384-..."` and no `crossorigin="anonymous"` attribute
- Any response header containing `X-Frame-Options: ALLOWALL` — this value grants permission to any origin and provides no protection
- A `Content-Security-Policy: default-src *` — a wildcard source list defeats the purpose of CSP entirely

### What Missing Security Headers is NOT

Do not flag these patterns:

- **Pure JSON API endpoint with `Content-Type: application/json`**: Security headers like `X-Frame-Options`, `Content-Security-Policy`, and `X-Content-Type-Options` are relevant to HTML responses rendered by browsers. A REST API returning JSON that is consumed programmatically carries no clickjacking or XSS browser risk. Flag only if the endpoint can also serve HTML under some conditions.
- **HSTS absent on a plain HTTP endpoint**: HSTS is only meaningful when sent over an HTTPS connection. If the application does not serve HTTPS at all (e.g., an internal-only HTTP service behind a TLS-terminating load balancer that adds HSTS at the edge), the absence in application code is expected and not a finding.
- **CSP absent on an endpoint serving no HTML**: An API that returns binary data, PDF, XML, or JSON with the correct `Content-Type` and `nosniff` does not need CSP because there is no browser scripting context.
- **CSP delivered via `<meta http-equiv="Content-Security-Policy">` in the HTML template**: The `<meta>` tag is a valid alternative for setting CSP. If you find a CSP meta tag in the template, the header is present — do not flag as missing. (Note: `frame-ancestors` directive is NOT honoured from a `<meta>` tag and must come from the HTTP header.)
- **`frame-ancestors` in CSP superseding `X-Frame-Options`**: If a `Content-Security-Policy` header includes a `frame-ancestors` directive, it takes precedence over `X-Frame-Options` in browsers that support CSP Level 2+. Do not flag `X-Frame-Options` as missing if a `frame-ancestors` directive is already present in the CSP.
- **Helmet configured via environment-specific config files**: If `helmet()` is applied in a production config that is required at startup, the fact that the middleware call is in a separate file rather than `app.js` does not make it absent.
- **SRI absent on first-party assets**: `integrity` attributes are only meaningful for third-party CDN resources. Scripts served from the same origin are already protected by the browser's same-origin policy.
- **`X-Content-Type-Options: nosniff` set at the load balancer / CDN layer**: If `sast/architecture.md` confirms that the edge layer (Cloudflare, nginx, AWS ALB) injects the header, the absence in application code is not a gap.

### Patterns That Confirm a Security Header IS Present

When you see these patterns, the corresponding header is covered — do not flag:

**1. Express — Helmet middleware applied before routes**
```javascript
// SECURE: helmet sets X-Frame-Options, X-Content-Type-Options, HSTS, and CSP defaults
const helmet = require('helmet');
app.use(helmet());

// SECURE: helmet with explicit CSP override
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'cdn.example.com'],
      },
    },
  })
);
```

**2. Django — SECURE settings enabled**
```python
# settings.py — SECURE: all four header controls enabled
SECURE_HSTS_SECONDS = 31536000          # sends Strict-Transport-Security
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
X_FRAME_OPTIONS = 'DENY'               # sends X-Frame-Options: DENY
SECURE_CONTENT_TYPE_NOSNIFF = True      # sends X-Content-Type-Options: nosniff
# CSP via django-csp:
CSP_DEFAULT_SRC = ("'self'",)
```

**3. Flask — flask-talisman applied**
```python
# SECURE: Talisman sets all security headers at once
from flask_talisman import Talisman
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
    },
    frame_options='DENY',
)
```

**4. Spring Security — headers() configured**
```java
// SECURE: all header protections active
http
    .headers(headers -> headers
        .frameOptions(frame -> frame.deny())
        .xssProtection(xss -> xss.block(true))
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(hsts -> hsts
            .maxAgeInSeconds(31536000)
            .includeSubDomains(true)
        )
        .contentSecurityPolicy(csp -> csp
            .policyDirectives("default-src 'self'")
        )
    );
```

**5. Rails — default_headers with all required entries**
```ruby
# config/application.rb — SECURE
config.action_dispatch.default_headers = {
  'X-Frame-Options'           => 'DENY',
  'X-XSS-Protection'          => '1; mode=block',
  'X-Content-Type-Options'    => 'nosniff',
  'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
}
# Plus secure_headers gem for CSP:
SecureHeaders::Configuration.default do |config|
  config.csp = { default_src: %w['self'] }
end
```

**6. HTML template with SRI**
```html
<!-- SECURE: CDN script with integrity hash and crossorigin -->
<script
  src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
  integrity="sha384-UwRMGj5EcF5MMpEivEjF4Z+GD3D/TnBAtQMBoTrHZ1p7qyBXVDe3I6gUG38hqN1"
  crossorigin="anonymous"
></script>
```

---

## Vulnerable vs. Secure Examples

### Express (Node.js) — Helmet absent

```javascript
// VULNERABLE: No security headers middleware, manual res.send() returns HTML
const express = require('express');
const app = express();

// ❌ Missing: helmet() or manual header settings
app.get('/dashboard', (req, res) => {
  // Response serves HTML with no X-Frame-Options, no CSP, no HSTS, no X-Content-Type-Options
  res.send(`
    <html>
      <head><title>Dashboard</title></head>
      <body><h1>Welcome</h1></body>
    </html>
  `);
});

// VULNERABLE: Helmet imported but not mounted
const helmet = require('helmet');
// helmet is imported but never called as middleware — headers are NOT sent
app.get('/admin', (req, res) => {
  res.send('<html><body>Admin Panel</body></html>');
});

// SECURE: helmet applied globally before route handlers
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());  // ← Applies all default security headers

app.get('/dashboard', (req, res) => {
  res.send('<html><body>Dashboard</body></html>');
});
```

```javascript
// VULNERABLE: manual header setting that is permissive
res.setHeader('X-Frame-Options', 'ALLOWALL');           // ← ALLOWALL is no protection
res.setHeader('Content-Security-Policy', 'default-src *');  // ← wildcard CSP

// SECURE: restrictive values
res.setHeader('X-Frame-Options', 'DENY');
res.setHeader('Content-Security-Policy', "default-src 'self'");
res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
res.setHeader('X-Content-Type-Options', 'nosniff');
```

```javascript
// VULNERABLE: CDN script in EJS / Pug template without SRI
// views/layout.ejs
// <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
//                                                          ↑ No integrity= attribute

// SECURE: CDN script with SRI
// <script
//   src="https://code.jquery.com/jquery-3.7.1.min.js"
//   integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="
//   crossorigin="anonymous"></script>
```

### Django (Python) — Missing SECURE settings

```python
# VULNERABLE: settings.py with defaults (HSTS disabled, frame options unset)
DEBUG = False
ALLOWED_HOSTS = ['example.com']

# ❌ SECURE_HSTS_SECONDS defaults to 0 → Strict-Transport-Security header not sent

# ❌ XFrameOptionsMiddleware removed from MIDDLEWARE → no X-Frame-Options header
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',  ← REMOVED
    ...
]

# VULNERABLE: explicitly permissive
SECURE_HSTS_SECONDS = 0           # ← explicitly disabling HSTS

# VULNERABLE: django-csp not installed and no CSP set anywhere
# (grep: no CSP_DEFAULT_SRC, no CSP_SCRIPT_SRC anywhere in settings)

# SECURE: complete SECURE settings
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True

# MIDDLEWARE must include both:
# 'django.middleware.security.SecurityMiddleware'          ← sends HSTS, nosniff
# 'django.middleware.clickjacking.XFrameOptionsMiddleware' ← sends X-Frame-Options

# SECURE CSP via django-csp:
# pip install django-csp
MIDDLEWARE += ['csp.middleware.CSPMiddleware']
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC  = ("'self'", 'cdn.example.com')
CSP_IMG_SRC     = ("'self'", 'data:')
```

### Flask (Python) — flask-talisman absent

```python
# VULNERABLE: Flask app with no security header middleware
from flask import Flask, render_template

app = Flask(__name__)

# ❌ No flask-talisman, no @app.after_request hook for security headers
@app.route('/profile')
def profile():
    return render_template('profile.html')  # HTML served with no security headers

# VULNERABLE: @after_request hook that misses headers
@app.after_request
def add_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # ❌ Missing: X-Frame-Options, Strict-Transport-Security, Content-Security-Policy
    return response

# SECURE: flask-talisman applied at app init
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
csp = {
    'default-src': ["'self'"],
    'script-src':  ["'self'", 'cdn.example.com'],
    'img-src':     ["'self'", 'data:'],
}
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy=csp,
    frame_options='DENY',
    content_type_options=True,
)

# SECURE: complete @after_request alternative (if Talisman is not an option)
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']   = "default-src 'self'"
    return response
```

### Spring Security (Java) — headers disabled

```java
// VULNERABLE: headers explicitly disabled — no security headers sent at all
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers.disable());  // ← ALL security headers disabled
        return http.build();
    }
}

// VULNERABLE: individual headers selectively disabled
http.headers(headers -> headers
    .frameOptions(frame -> frame.disable())    // ← clickjacking protection removed
    .contentSecurityPolicy(csp -> {})          // ← CSP not configured
    // hsts not called → HSTS header absent
);

// VULNERABLE: permissive frameOptions when sensitive pages exist
http.headers(headers -> headers
    .frameOptions(frame -> frame.sameOrigin()) // allows framing from same origin
    // For a login or payment page, sameOrigin is still risky
);

// SECURE: all protections enabled
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .frameOptions(frame -> frame.deny())
            .contentTypeOptions(Customizer.withDefaults())
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true)
            )
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("default-src 'self'; script-src 'self' cdn.example.com")
            )
        );
    return http.build();
}
```

### Rails (Ruby) — default_headers incomplete

```ruby
# VULNERABLE: config/application.rb overrides default_headers without X-Frame-Options
config.action_dispatch.default_headers = {
  'X-XSS-Protection'       => '1; mode=block',
  'X-Content-Type-Options'  => 'nosniff',
  # ❌ Missing: X-Frame-Options → clickjacking possible
  # ❌ Missing: Strict-Transport-Security → protocol downgrade possible
}

# VULNERABLE: secure_headers gem absent
# (grep shows no SecureHeaders::Configuration.default block anywhere in codebase)

# VULNERABLE: secure_headers with opt-out
class ApplicationController < ActionController::Base
  ensure_security_headers
  # Specific controller silently removes a header:
  skip_before_action :set_hsts_header   # ← removes HSTS for this controller
end

# SECURE: config/application.rb with all headers
config.action_dispatch.default_headers = {
  'X-Frame-Options'           => 'DENY',
  'X-XSS-Protection'          => '1; mode=block',
  'X-Content-Type-Options'    => 'nosniff',
  'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
  'Referrer-Policy'           => 'strict-origin-when-cross-origin',
}

# SECURE: secure_headers gem (config/initializers/secure_headers.rb)
SecureHeaders::Configuration.default do |config|
  config.hsts            = "max-age=#{20.years.to_i}; includeSubDomains; preload"
  config.x_frame_options = 'DENY'
  config.x_content_type_options = 'nosniff'
  config.csp = {
    default_src: %w['self'],
    script_src:  %w['self' cdn.example.com],
    img_src:     %w['self' data:],
    connect_src: %w['self'],
    font_src:    %w['self'],
    style_src:   %w['self'],
    base_uri:    %w['self'],
    form_action: %w['self'],
    frame_ancestors: %w['none'],
  }
end
```

### HTML Templates — Missing SRI

```html
<!-- VULNERABLE: External CDN scripts and stylesheets without integrity checks -->
<!DOCTYPE html>
<html>
<head>
  <!-- ❌ No integrity hash — a compromised CDN could serve malicious JS -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
  <!-- ❌ Bootstrap CSS without SRI -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>

<!-- SECURE: All CDN resources have SRI hashes -->
<!DOCTYPE html>
<html>
<head>
  <script
    src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"
    integrity="sha512-v2CJ7UaYy4JwqLDIrZUI/4hqeoQieOmAZNXBeQyjo21dadnwR+8ZaIJVT8EE2iyI9LLxwFaEm7oLL4mGIDNcQ=="
    crossorigin="anonymous"
    referrerpolicy="no-referrer">
  </script>
  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
    integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
    crossorigin="anonymous">
</head>
```

---

## Severity Reference (CWE-693 / CWE-1021)

| Condition | Severity |
|---|---|
| HSTS absent on a confirmed HTTPS app (protocol downgrade / SSL strip possible) | **high** |
| `X-Frame-Options` / CSP `frame-ancestors` absent on a sensitive page (login, payment, account settings) | **high** |
| CSP entirely absent AND inline XSS is possible on the same page (chains with sast-xss) | **critical** |
| CSP entirely absent on an HTML page (no inline XSS confirmed) | **medium** |
| `X-Content-Type-Options` absent | **medium** |
| CDN `<script>` or `<link>` without SRI | **medium** |
| `X-Frame-Options: ALLOWALL` or `Content-Security-Policy: default-src *` (permissive misconfiguration) | **high** |
| Header absent on a pure JSON API endpoint with correct Content-Type (non-HTML) | **info** (not flagged — omit from JSON) |

OWASP mapping: **A02:2021 — Cryptographic Failures** (HSTS), **A05:2021 — Security Misconfiguration** (all headers).

CWE references: **CWE-693** (Protection Mechanism Failure), **CWE-1021** (Improper Restriction of Rendered UI Layers — clickjacking).

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Missing Security Header Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a critical HTTP security header is absent, explicitly disabled, or set to a permissive value. Write results to `sast/secheaders-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand what web framework is in use, whether a security-header middleware (Helmet, Talisman, secure_headers, django-csp) is present, and which routes serve HTML vs. pure API responses.
>
> **What to search for — security header gaps**:
>
> For each framework, look for these specific patterns. Flag ANY absence or misconfiguration — Phase 2 will determine whether the endpoint serves HTML and whether a compensating control exists.
>
> **Express (Node.js)**:
> - Search `package.json` for `"helmet"` in `dependencies`. If absent, flag the entire Express app as lacking Helmet.
> - If Helmet is in `package.json`, search source files for `require('helmet')` or `import helmet`. If the import is present but `app.use(helmet())` is never called before route handlers, flag as Helmet imported but not mounted.
> - Search for `res.setHeader('X-Frame-Options', ...)` — flag if value is `'ALLOWALL'` or any non-`'DENY'`/`'SAMEORIGIN'` value.
> - Search for `res.setHeader('Content-Security-Policy', ...)` — flag if value contains `default-src *` or is absent entirely.
> - Search HTML templates (`.ejs`, `.pug`, `.hbs`, `.html`) for `<script src="https://` or `<link rel="stylesheet" href="https://` that do NOT have an `integrity=` attribute.
>
> **Django (Python)**:
> - Search `settings.py` (and any settings files that `settings.py` imports) for:
>   - `SECURE_HSTS_SECONDS` — flag if set to `0` or if the setting is absent (Django default is `0`)
>   - `X_FRAME_OPTIONS` — flag if absent, or set to a non-`'DENY'` / non-`'SAMEORIGIN'` value
>   - `SECURE_CONTENT_TYPE_NOSNIFF` — flag if `False` (check Django version; default is `True` in Django 3.x+ with SecurityMiddleware)
>   - `XFrameOptionsMiddleware` — flag if `'django.middleware.clickjacking.XFrameOptionsMiddleware'` is absent from `MIDDLEWARE`
>   - `SecurityMiddleware` — flag if `'django.middleware.security.SecurityMiddleware'` is absent from `MIDDLEWARE`
> - Search for `django-csp` in `requirements.txt`, `pyproject.toml`, `Pipfile` — if absent, flag as CSP not configured
> - If `django-csp` is present, check for `CSP_DEFAULT_SRC` in settings — if absent or wildcard, flag
> - Search Django templates (`.html` in `templates/`) for CDN `<script src="https://` and `<link href="https://` without `integrity=`
>
> **Flask (Python)**:
> - Search `requirements.txt`, `pyproject.toml`, `Pipfile` for `flask-talisman`. If absent, flag the Flask app as lacking security header middleware.
> - If `flask-talisman` is absent, search for `@app.after_request` hooks — inspect which headers they set and flag any that are missing from the required set (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`).
> - Search Flask templates (`.html` in `templates/`) for CDN resources without `integrity=`.
>
> **Spring Security (Java)**:
> - Search `*.java` for `http.headers().disable()` or `headers -> headers.disable()` — flag as all security headers disabled.
> - Search for `http.headers(headers -> headers.frameOptions(frame -> frame.disable()))` — flag as clickjacking protection disabled.
> - Search for `@EnableWebSecurity` classes; verify each `SecurityFilterChain` bean includes `.httpStrictTransportSecurity(` and `.contentSecurityPolicy(` — flag if absent.
> - Search Thymeleaf / JSP templates for CDN resources without `integrity=`.
>
> **Rails (Ruby)**:
> - Search `config/application.rb` and `config/environments/*.rb` for `config.action_dispatch.default_headers`.
>   - If the assignment omits `'X-Frame-Options'`, flag as clickjacking protection missing.
>   - If the assignment omits `'Strict-Transport-Security'`, flag as HSTS missing.
>   - If the assignment omits `'X-Content-Type-Options'`, flag as content sniffing protection missing.
> - Search `Gemfile` for `secure_headers` — if absent, note CSP may not be configured.
> - If `secure_headers` is in `Gemfile`, search `config/initializers/secure_headers.rb` for `SecureHeaders::Configuration.default` — if absent or if `config.csp = SecureHeaders::OPT_OUT`, flag as CSP opted out.
> - Search ERB / Haml templates for CDN resources without `integrity=`.
>
> **Generic patterns (any framework)**:
> - Search `nginx.conf`, `caddy.json` or `Caddyfile`, `apache2.conf` / `.htaccess` for security header directives — document what the web server adds (this becomes context for Phase 2's compensating-control check).
> - Search all HTML templates for patterns matching `<script src="https?://` (external origin) or `<link.*href="https?://` (external origin) without a following `integrity=` attribute on the same tag.
>
> **What NOT to flag in Phase 1**:
> - Do not attempt to determine whether an endpoint serves HTML in Phase 1 — flag all candidates and leave that for Phase 2.
> - Do not flag `X-Frame-Options: SAMEORIGIN` as a hard vulnerability — note it for Phase 2 context assessment.
> - Do not flag API-only express apps that explicitly set `Content-Type: application/json` on every route — but do flag if any route also serves HTML.
>
> **Output format** — write to `sast/secheaders-recon.md`:
>
> ```markdown
> # Security Headers Recon: [Project Name]
>
> ## Summary
> Found [N] locations where one or more critical security headers are absent or misconfigured.
>
> ## Security Header Gap Sites
>
> ### 1. [Descriptive name — e.g., "Helmet absent in Express app"]
> - **File**: `path/to/file.ext` (lines X-Y if applicable)
> - **Framework**: [Express / Django / Flask / Spring / Rails / HTML template]
> - **Missing or misconfigured headers**: [list: X-Frame-Options, CSP, HSTS, X-Content-Type-Options, SRI]
> - **Pattern found**: [e.g., "No `app.use(helmet())` call in app.js" / "`SECURE_HSTS_SECONDS = 0` in settings.py"]
> - **Code snippet** (if applicable):
>   ```
>   [the relevant line(s)]
>   ```
> - **Endpoint / scope**: [e.g., "Affects all routes in app.js" / "Affects /dashboard route" / "CDN script in base.html line 14"]
> - **Note**: [any context — e.g., "helmet is in package.json but not mounted", "XFrameOptionsMiddleware removed from MIDDLEWARE"]
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/secheaders-recon.md`. If the recon found **zero gap sites** (the summary reports "Found 0" or the "Security Header Gap Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to both output files and stop:

```markdown
# Security Headers Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Write the markdown to `sast/secheaders-results.md` and the JSON to `sast/secheaders-results.json`.

Only proceed to Phase 2 if Phase 1 found at least one security header gap site.

### Phase 2: Verify — HTML Response and Compensating Control Analysis (Batched)

After Phase 1 completes, read `sast/secheaders-recon.md` and split the gap sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent determines whether the gap is a real finding for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/secheaders-recon.md` and count the numbered site sections under "Security Header Gap Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/secheaders-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary framework from `sast/architecture.md` and select only the matching vulnerable/secure examples from the "Vulnerable vs. Secure Examples" section above. Pass these selected examples to each subagent where indicated by `[FRAMEWORK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned security header gap site, determine whether the gap is a real vulnerability — specifically whether the affected endpoint serves HTML, whether compensating controls exist, and what the actual risk is. Write results to `sast/secheaders-batch-[N].md`.
>
> **Your assigned sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the application's tech stack, whether a TLS-terminating proxy is in front of the app, and which endpoints serve HTML vs. pure API responses.
>
> **Verify — determine if the gap is a real finding**:
>
> For each site, answer these questions in order:
>
> **Question 1: Does this endpoint / scope serve HTML or framing-capable content?**
>
> Security headers are only meaningful for responses rendered by a browser. Determine:
>
> - Does the route call `res.send(html)`, `res.render(...)`, `render_template(...)`, `return render(request, '...')`, or `render :html`?
> - Does `Content-Type: text/html` apply to responses from this route?
> - Could the endpoint serve HTML under any code path (e.g., error pages, redirects)?
>
> If the endpoint serves only `application/json`, `application/octet-stream`, or other non-HTML types → **Not Vulnerable** (headers N/A for non-HTML API). Note the evidence.
>
> If the endpoint serves HTML or can serve HTML → proceed to Question 2.
>
> **Question 2: Is the missing header covered by a compensating control?**
>
> Check for these compensating controls before flagging:
>
> - **Web server layer**: Does `nginx.conf`, `Caddyfile`, or `.htaccess` inject the missing header for all responses? If so, the application-level absence is not a vulnerability — note the compensating control.
> - **Reverse proxy / CDN**: Does `sast/architecture.md` confirm that Cloudflare, AWS CloudFront, or a load balancer adds the header at the edge? If confirmed → note as covered, reduce confidence.
> - **CSP `frame-ancestors` superseding `X-Frame-Options`**: If a `Content-Security-Policy` header with a `frame-ancestors` directive is present (from any source — application, server, or CDN), the absence of `X-Frame-Options` is not an additional risk.
> - **CSP via `<meta>` tag**: If the HTML template includes `<meta http-equiv="Content-Security-Policy" content="...">`, CSP is present. (Exception: `frame-ancestors` in a `<meta>` CSP is NOT honoured by browsers — still flag if `X-Frame-Options` is also absent.)
>
> If all missing headers are covered by compensating controls → **Not Vulnerable**. Document exactly which control covers which header.
>
> If one or more headers remain uncovered → proceed to Question 3.
>
> **Question 3: Which specific headers are missing and what is the concrete risk?**
>
> For each missing header, assess the concrete attack scenario:
>
> - **`Strict-Transport-Security` absent on an HTTPS app**: Risk is SSL-stripping. An attacker on a shared network intercepts the first HTTP request before the HTTPS redirect and can strip TLS for the session. Severity **high** for public-facing apps.
> - **`X-Frame-Options` / CSP `frame-ancestors` absent**: Risk is clickjacking. Severity **high** when the page performs sensitive actions (login, account changes, payment confirmation, delete actions). Severity **medium** for purely informational pages.
> - **`X-Content-Type-Options` absent**: Risk is MIME-type sniffing leading to script execution from user-controlled content. Severity **medium** (requires a file upload or content injection path to weaponize fully).
> - **`Content-Security-Policy` absent AND inline XSS is present (chains with sast-xss)**: Risk is unmitigated XSS. Severity **critical** — CSP absence amplifies XSS from exploitable to trivially exploitable.
> - **`Content-Security-Policy` absent (no confirmed XSS)**: Risk is defence-in-depth gap. Severity **medium** — CSP would restrict script execution but its absence alone does not enable an attack.
> - **CDN resource without SRI**: Risk is supply-chain attack via CDN compromise. Severity **medium** — requires CDN compromise (low probability, high impact when it occurs).
>
> **Question 4: Is this a framework-wide configuration gap or a per-route gap?**
>
> - If Helmet/Talisman/secure_headers/SecurityMiddleware is absent at the application level, all HTML routes are affected — one finding covers the entire app.
> - If a middleware is applied but a specific route bypasses it (e.g., mounted before `app.use(helmet())`), flag that route specifically.
> - For Django `SECURE_HSTS_SECONDS = 0`, the gap is application-wide — one finding.
>
> **FP-killers** (patterns that confirm the site is NOT a real vulnerability):
>
> 1. Helmet is called in a startup file that is always required before routes — search for `require('./app')` or `import app from './app'` in the entry file to confirm mount order.
> 2. Django `SECURE_CONTENT_TYPE_NOSNIFF` defaults to `True` in Django 3.x+ when `SecurityMiddleware` is in `MIDDLEWARE` — verify the Django version before flagging.
> 3. `X_FRAME_OPTIONS = 'SAMEORIGIN'` in Django is not absent — it sets a value. Decide if it warrants a finding based on whether the app has sensitive pages that should use `'DENY'` instead.
> 4. Spring Security's `headers()` is enabled by default — calling `http.headers()` without `.disable()` applies default protections. Only flag if `.disable()` or a specific sub-option `.disable()` is confirmed.
> 5. SRI is not required for first-party assets — only for resources loaded from external CDN origins (different hostnames).
>
> **exploitability / confidence rules**:
>
> - `exploitability: reachable` — the HTML endpoint is in production code with no header protection, serving a sensitive page (auth, account changes, payment)
> - `exploitability: conditional` — the endpoint serves HTML but the missing header only matters under specific conditions (e.g., HSTS absent but app is HTTPS-only via bookmark; or `X-Frame-Options` absent on a page requiring authentication)
> - `exploitability: unreachable` — the endpoint is an internal-only admin UI with network-level access controls; or the app is in a development environment only
> - `confidence: high` — explicit disable (`.disable()`, `SECURE_HSTS_SECONDS = 0`, `X-Frame-Options: ALLOWALL`) or complete absence of a standard middleware (no Helmet, no django-csp) in a confirmed HTML-serving app
> - `confidence: medium` — absence inferred from missing middleware, but the middleware may be applied elsewhere (e.g., in a config file not yet inspected); or the endpoint may not serve HTML in all cases
> - `confidence: low` — middleware presence unknown (not in package.json / requirements, but may be injected by a parent module); or the endpoint's HTML-serving status is unclear
>
> **chain_id rules**:
>
> - If CSP is absent AND `sast/xss-results.json` exists and has findings for the same application → set `chain_id: "csp-xss-amplify"` (absent CSP amplifies XSS severity)
> - If `X-Frame-Options` / CSP `frame-ancestors` is absent AND `sast/csrf-results.json` exists and has findings → set `chain_id: "clickjack-csrf"` (iframe-based CSRF is easier without frame isolation)
> - If no chain applies → `chain_id: null`
>
> **Framework examples for this project's stack**:
>
> [FRAMEWORK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Header absent or misconfigured on a confirmed HTML endpoint, no compensating control, production-reachable
> - **Likely Vulnerable**: Header absent but compensating control status is unknown (e.g., load balancer may add it), or the endpoint may not serve HTML in all conditions
> - **Not Vulnerable**: Header covered by a confirmed compensating control, or endpoint provably does not serve HTML
> - **Needs Manual Review**: Cannot determine whether HTML is served or whether a compensating control exists without running the application
>
> **Output format** — write to `sast/secheaders-batch-[N].md`:
>
> ```markdown
> # Security Headers Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y if applicable)
> - **Framework**: [Express / Django / Flask / Spring / Rails / HTML template]
> - **Missing headers**: [list each missing header]
> - **Issue**: [e.g., "All HTML routes in the Express app lack security headers because helmet() is not mounted"]
> - **Affected endpoints**: [e.g., "All routes in app.js" / "/login, /account/settings, /payment/confirm"]
> - **Concrete attack**: [e.g., "Attacker embeds /login in a transparent iframe and captures user credentials via clickjacking"]
> - **Severity**: critical | high | medium
> - **exploitability**: reachable | conditional | unreachable
> - **confidence**: high | medium | low
> - **chain_id**: "csp-xss-amplify" | "clickjack-csrf" | null
> - **Remediation**: [Specific fix with code — e.g., "Add `app.use(helmet())` before all route handlers in app.js"]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext`
> - **Framework**: [framework]
> - **Missing headers**: [list]
> - **Issue**: [description]
> - **Severity**: medium | high
> - **exploitability**: conditional
> - **confidence**: medium | low
> - **chain_id**: null
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext`
> - **Reason**: [e.g., "nginx.conf adds X-Frame-Options: DENY for all responses" / "Route serves application/json only"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext`
> - **Uncertainty**: [Why the verdict cannot be determined statically]
> - **Suggestion**: [What a human reviewer should check]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/secheaders-batch-*.md` file and merge them into both `sast/secheaders-results.md` (human-readable) and `sast/secheaders-results.json` (machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/secheaders-batch-1.md`, `sast/secheaders-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Assign a sequential numeric ID to each finding for the JSON output: `secheaders-1`, `secheaders-2`, etc. (ordered: Vulnerable first, then Likely Vulnerable, then Needs Manual Review, then Not Vulnerable).
5. Write the merged markdown report to `sast/secheaders-results.md`:

```markdown
# Security Headers Analysis Results: [Project Name]

## Executive Summary
- Sites analyzed: [total gap sites from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

6. Write the machine-readable JSON to `sast/secheaders-results.json` using the canonical schema. For each Vulnerable, Likely Vulnerable, and Needs Manual Review finding, emit one JSON object. Not Vulnerable findings are omitted from the JSON output (true negatives do not belong in the findings array):

```json
{
  "findings": [
    {
      "id": "secheaders-1",
      "skill": "sast-secheaders",
      "severity": "high",
      "title": "Helmet middleware absent — all HTML routes lack security headers",
      "description": "The Express application in app.js does not call app.use(helmet()) or set any security headers manually. All HTML responses are served without X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, or X-Content-Type-Options. An attacker can embed the /dashboard and /login routes in a transparent iframe to execute clickjacking attacks capturing user credentials.",
      "location": { "file": "app.js", "line": 12, "column": 1 },
      "remediation": "Add `const helmet = require('helmet'); app.use(helmet());` immediately after Express app initialization and before all route handler registrations. For production, configure the CSP directive explicitly: app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } })).",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    },
    {
      "id": "secheaders-2",
      "skill": "sast-secheaders",
      "severity": "high",
      "title": "HSTS disabled — Django SECURE_HSTS_SECONDS set to 0",
      "description": "settings.py explicitly sets SECURE_HSTS_SECONDS = 0, preventing Django's SecurityMiddleware from sending the Strict-Transport-Security header. An active network attacker can intercept the initial HTTP request before the HTTPS redirect and strip TLS for the entire session (SSL-stripping attack).",
      "location": { "file": "config/settings.py", "line": 47, "column": 1 },
      "remediation": "Set SECURE_HSTS_SECONDS = 31536000 (one year), SECURE_HSTS_INCLUDE_SUBDOMAINS = True, and SECURE_SSL_REDIRECT = True in settings.py. Ensure 'django.middleware.security.SecurityMiddleware' is the first entry in MIDDLEWARE.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    }
  ]
}
```

Field mapping from batch results to JSON:
- `id`: `secheaders-<N>` sequential
- `skill`: always `"sast-secheaders"`
- `severity`: from the batch finding's **Severity** field (`"critical"` if CSP absent and XSS chains; `"high"` for HSTS/framing gaps; `"medium"` for SRI/nosniff/CSP-only gaps)
- `title`: short one-line description synthesized from the finding name
- `description`: combine **Issue** + **Affected endpoints** + **Concrete attack** fields from the batch result
- `location.file`: from **File** field, path only; use the line of the relevant configuration or middleware registration
- `location.line`: the line number of the relevant setting, `app.use()` call, or template element
- `location.column`: column if visible from the code snippet; `null` if not determined
- `remediation`: from the **Remediation** field in the batch result
- `exploitability`: from the **exploitability** field in the batch result
- `confidence`: from the **confidence** field in the batch result
- `chain_id`: from the **chain_id** field in the batch result (`null` if not set)

If no real findings exist (all sites were Not Vulnerable), write `"findings": []` to the JSON file.

7. After writing both output files, **delete all intermediate batch files** (`sast/secheaders-batch-*.md`) and the recon file (`sast/secheaders-recon.md`).

---

## Chain IDs

| chain_id | Composed skills | Combined narrative |
|---|---|---|
| `csp-xss-amplify` | `sast-secheaders` + `sast-xss` | Absent or wildcard CSP removes the browser's last line of defence against an XSS payload found in the same codebase, raising effective XSS severity to critical |
| `clickjack-csrf` | `sast-secheaders` + `sast-csrf` | Absent framing protection enables iframe-based CSRF that can bypass same-site cookie restrictions in some browser configurations |

Set `chain_id` on the `sast-secheaders` finding when the paired skill's results file exists and contains at least one finding for the same application. Leave `chain_id: null` when the paired finding is absent or unconfirmed.

---

## Remediation Reference

Include the relevant framework-specific remediation in every finding's `remediation` field:

**Express (Node.js) — add Helmet**
```javascript
// Install: npm install helmet
// In app.js / server.js, before all routes:
const helmet = require('helmet');
app.use(helmet());

// For a production CSP (adjust sources to your app's needs):
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'", 'cdn.example.com'],
        styleSrc:   ["'self'", 'https:'],
        imgSrc:     ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
        fontSrc:    ["'self'", 'https:', 'data:'],
        objectSrc:  ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);
```

**Django (Python) — enable all SECURE settings**
```python
# settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',        # ← must be first
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ...
]

# CSP via django-csp (pip install django-csp):
MIDDLEWARE += ['csp.middleware.CSPMiddleware']
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC  = ("'self'",)
CSP_IMG_SRC     = ("'self'", "data:")
CSP_STYLE_SRC   = ("'self'",)
CSP_FONT_SRC    = ("'self'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_OBJECT_SRC  = ("'none'",)
```

**Flask (Python) — add flask-talisman**
```python
# pip install flask-talisman
from flask_talisman import Talisman

csp = {
    'default-src': "'self'",
    'script-src':  ["'self'", 'cdn.example.com'],
    'img-src':     ["'self'", 'data:'],
    'style-src':   ["'self'"],
    'object-src':  "'none'",
}

Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    content_security_policy=csp,
    frame_options='DENY',
    content_type_options=True,
    referrer_policy='strict-origin-when-cross-origin',
)
```

**Spring Security (Java) — configure headers**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers
        .frameOptions(frame -> frame.deny())
        .contentTypeOptions(Customizer.withDefaults())
        .httpStrictTransportSecurity(hsts -> hsts
            .maxAgeInSeconds(31536000)
            .includeSubDomains(true)
            .preload(true)
        )
        .contentSecurityPolicy(csp -> csp
            .policyDirectives(
                "default-src 'self'; " +
                "script-src 'self' cdn.example.com; " +
                "img-src 'self' data:; " +
                "object-src 'none'"
            )
        )
        .referrerPolicy(referrer -> referrer
            .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
        )
    );
    return http.build();
}
```

**Rails (Ruby) — update default_headers and add secure_headers**
```ruby
# config/application.rb
config.action_dispatch.default_headers = {
  'X-Frame-Options'           => 'DENY',
  'X-XSS-Protection'          => '1; mode=block',
  'X-Content-Type-Options'    => 'nosniff',
  'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
  'Referrer-Policy'           => 'strict-origin-when-cross-origin',
}

# Gemfile: gem 'secure_headers'
# config/initializers/secure_headers.rb
SecureHeaders::Configuration.default do |config|
  config.hsts            = "max-age=#{20.years.to_i}; includeSubDomains; preload"
  config.x_frame_options = 'DENY'
  config.x_content_type_options = 'nosniff'
  config.x_xss_protection = '1; mode=block'
  config.referrer_policy  = 'strict-origin-when-cross-origin'
  config.csp = {
    default_src: %w['none'],
    script_src:  %w['self' cdn.example.com],
    img_src:     %w['self' data:],
    style_src:   %w['self'],
    connect_src: %w['self'],
    font_src:    %w['self'],
    object_src:  %w['none'],
    base_uri:    %w['self'],
    form_action: %w['self'],
    frame_ancestors: %w['none'],
  }
end
```

**HTML Templates — add SRI to CDN resources**
```html
<!-- Generate hashes: https://www.srihash.org/
     or: openssl dgst -sha384 -binary file.js | openssl base64 -A -->

<!-- jQuery -->
<script
  src="https://code.jquery.com/jquery-3.7.1.min.js"
  integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="
  crossorigin="anonymous"></script>

<!-- Bootstrap CSS -->
<link
  rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
  integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
  crossorigin="anonymous">

<!-- Bootstrap JS -->
<script
  src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
  integrity="sha384-YvpcrYf0tY3lHB60NNkmXc4s9bIOgUxi8T/jzmDr7V84/p7CWvqAnE34ug0q6fKJKH8"
  crossorigin="anonymous"></script>
```

**General guidance**:
- Apply security headers globally via middleware, not per-route — a per-route approach inevitably misses endpoints
- Test your CSP in report-only mode first (`Content-Security-Policy-Report-Only`) to collect violation reports before enforcing
- Include a `report-uri` or `report-to` directive in your CSP to receive violation reports from browsers
- Add your app to the HSTS preload list (https://hstspreload.org/) only after confirming `includeSubDomains` will not break any subdomain
- Generate SRI hashes using the SRI Hash Generator (https://www.srihash.org/) or `openssl dgst -sha384 -binary <file> | openssl base64 -A`
- Lock down CDN libraries to exact versions when adding SRI — upgrade the version and regenerate the hash when you want to update

---

## Chains with Other Skills

Security header gaps compound with other findings. Check these chains when setting `chain_id`:

- **sast-xss + absent CSP** (`chain_id: "csp-xss-amplify"`): A CSP restricts which scripts can execute. When `sast-xss` finds a reflected or stored XSS vulnerability and `sast-secheaders` confirms CSP is absent or uses `default-src *`, the XSS is trivially exploitable because no browser-level control blocks the injected script. Set `chain_id: "csp-xss-amplify"` on both findings.
- **sast-csrf + absent framing protection** (`chain_id: "clickjack-csrf"`): When `X-Frame-Options` and CSP `frame-ancestors` are both absent, an attacker can embed the application in an iframe and trigger CSRF-protected actions by tricking users into clicking on the invisible framed page. If `sast-csrf` has findings for the same application, set `chain_id: "clickjack-csrf"` on both findings.

Chain composition example:
```
sast-xss finding:        Reflected XSS in /search?q= parameter (xss-1)
sast-secheaders finding: CSP absent on all routes (secheaders-1)
→ chain_id: "csp-xss-amplify" on both xss-1 and secheaders-1
→ Combined narrative: Browser's script restriction bypass (CSP absent) amplifies the reflected
  XSS to trivially exploitable — no browser-level mitigation blocks the injected payload.

sast-csrf finding:       Missing CSRF token on /account/delete endpoint (csrf-1)
sast-secheaders finding: X-Frame-Options absent on /account/delete (secheaders-2)
→ chain_id: "clickjack-csrf" on both csrf-1 and secheaders-2
→ Combined narrative: Attacker embeds /account/delete in a transparent iframe and uses a
  clickjacking overlay to get the authenticated user to trigger the unprotected action.
```

---

## Test Fixture (True Positive / True Negative Reference)

The following minimal examples define what the skill MUST flag (TP) and MUST NOT flag (TN):

**TP — Must flag, exploitability: reachable, severity: medium (Helmet absent, HTML serving)**
```javascript
// app/server.js — Express app with no security headers
const express = require('express');
const app = express();

// ← TP: no helmet(), no manual header setting
app.get('/dashboard', (req, res) => {
  res.send('<html><body><h1>Dashboard</h1></body></html>');  // HTML response, no headers
});

app.listen(3000);
```

**TP — Must flag, exploitability: reachable, severity: high (HSTS explicitly disabled)**
```python
# config/settings.py
SECURE_HSTS_SECONDS = 0        # ← TP: explicit zero disables HSTS on an HTTPS app
X_FRAME_OPTIONS = 'SAMEORIGIN' # present but worth noting for context
```

**TP — Must flag, exploitability: reachable, severity: high (Spring headers disabled)**
```java
// SecurityConfig.java
http.headers(headers -> headers.disable());  // ← TP: all security headers stripped
```

**TP — Must flag, exploitability: reachable, severity: medium (CDN script without SRI)**
```html
<!-- templates/base.html line 12 -->
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
<!-- ↑ TP: external CDN script with no integrity= attribute -->
```

**TN — Must NOT flag (helmet applied before routes)**
```javascript
// app/server.js
const express = require('express');
const helmet  = require('helmet');
const app = express();

app.use(helmet());  // ← TN: applied globally before all routes

app.get('/dashboard', (req, res) => {
  res.send('<html><body>Dashboard</body></html>');
});
```

**TN — Must NOT flag (JSON API endpoint, headers N/A)**
```javascript
// routes/api.js
router.get('/api/v1/users', (req, res) => {
  res.json({ users: [] });  // ← TN: Content-Type: application/json, not HTML
});
// Note: if the same app ALSO serves HTML on other routes, those routes still need headers
```

**TN — Must NOT flag (nginx compensating control)**
```nginx
# nginx.conf — adds headers at the edge for all responses
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
# ← TN: application-level absence is covered; not a vulnerability
```

**TN / TP split — CSP via meta tag**
```html
<!-- templates/base.html -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
<!-- ← TN for CSP: browser honours meta CSP for most directives -->
<!-- ← TP for X-Frame-Options: frame-ancestors in meta CSP is NOT honoured by browsers;
        if no X-Frame-Options HTTP header is present, clickjacking is still possible -->
```

Assert: only the TPs are flagged in results; TNs must appear as NOT VULNERABLE or be absent from the JSON findings array.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **Phase 1 is purely structural**: flag any location where a security header is absent or misconfigured, regardless of whether the endpoint serves HTML. Do not assess HTML-serving status in Phase 1 — that is Phase 2's job.
- **Phase 2 is the HTML/compensating-control determination phase**: for each assigned site, answer whether the endpoint serves HTML, whether a compensating control covers the gap, and what the concrete attack is. Set `exploitability` and `confidence` based on the evidence found.
- The most important FP source for this skill is **API endpoints that do not serve HTML**: security headers are browser safety features; they carry no security value on JSON or binary API responses. Always confirm that the affected route can serve an HTML response before flagging.
- The second most common FP source is **compensating controls at the edge**: many deployments add security headers at the nginx, Caddy, or CDN layer. Check `sast/architecture.md` and any web-server config files before concluding that headers are missing.
- `X-Frame-Options: SAMEORIGIN` is NOT absent — it is a valid value. Only flag it as a finding if the application has sensitive pages (login, payment, account management) that should use `DENY`, and document the reasoning clearly.
- CSP via `<meta http-equiv="Content-Security-Policy">` covers most CSP directives — do not flag as missing CSP. **Exception**: the `frame-ancestors` directive is not honoured from a `<meta>` tag and requires the HTTP header.
- When CSP `frame-ancestors` is present in the HTTP header, the absence of `X-Frame-Options` is not an additional finding — `frame-ancestors` takes precedence in modern browsers.
- For SRI, only flag external CDN resources (different hostname from the application). First-party assets are protected by same-origin policy and do not require `integrity=`.
- Set `chain_id: "csp-xss-amplify"` when CSP is absent AND `sast/xss-results.json` exists with findings. Check the file existence and content before setting this chain.
- Set `chain_id: "clickjack-csrf"` when `X-Frame-Options` / `frame-ancestors` is absent AND `sast/csrf-results.json` exists with findings for the same app.
- Clean up intermediate files: delete `sast/secheaders-recon.md` and all `sast/secheaders-batch-*.md` files after the final reports are written. The only outputs that should remain are `sast/secheaders-results.md` and `sast/secheaders-results.json`.
- Severity escalation: raise to **critical** when CSP is absent AND an inline XSS finding exists (chain sast-xss); raise to **high** when HSTS is absent on a confirmed HTTPS app or when framing protection is absent on a sensitive page; default to **medium** for CSP-only absence or SRI gaps.
- For Django, always verify which version is in use: `SECURE_CONTENT_TYPE_NOSNIFF` defaults to `True` since Django 3.0 when `SecurityMiddleware` is active — check the Django version before flagging this setting as missing.
- For Spring Security, the default header configuration (when `http.headers()` is called without `.disable()`) already includes `X-Content-Type-Options`, `X-Frame-Options: DENY`, and `X-XSS-Protection`. Only flag specific headers as absent when a corresponding `.disable()` call or missing configuration sub-block is confirmed.
