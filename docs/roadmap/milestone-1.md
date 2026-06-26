# Milestone 1 — Clean static, high prevalence (detailed plan)

13 Tier-A skills. See [../ROADMAP.md](../ROADMAP.md) and the per-skill task in it.

## Per-skill spec format

Every skill below is specified as:

- **Header** — framework mapping, tier, CWE.
- **Scope** — what it IS and explicitly what it is NOT (the boundary that keeps FP down).
- **Recon sinks** — the concrete grep/AST targets the recon phase looks for, per language/framework.
- **Verify** — the taint question + the FP-killers; sets `exploitability` / `confidence`.
- **Severity** — the default, and when to raise or lower it.
- **Remediation** — the fix written into the finding.
- **Chains with** — sibling skills it composes with via `chain_id`.
- **Test fixture** — a minimal repo with a true positive and the FP-killer true negatives; the skill must flag only the TP.

---

## sast-deser — Insecure deserialization

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-502

**Scope.** Untrusted bytes reaching a deserializer that can instantiate arbitrary types or
invoke code (gadget chains). NOT: deserializing trusted/internal data; `JSON.parse` of plain
data with no type resolution; schema-validated input.

**Recon sinks** (recon-phase grep/AST targets):

| Language | Sinks |
|---|---|
| Java | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream` (no allow-list), SnakeYAML `new Yaml()` without `SafeConstructor`, `Kryo` |
| Python | `pickle.load(s)`, `yaml.load` (no `SafeLoader`), `jsonpickle.decode`, `dill.load`, `shelve` |
| PHP | `unserialize(` on request data |
| .NET | `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `Json.NET` `TypeNameHandling.All/Auto` |
| Ruby | `Marshal.load`, `YAML.load` (pre-`safe_load` Psych) |
| Node | `node-serialize`, `serialize-to-js`, `funcster`, `cryo` |

**Verify.** Does the deserialized input cross a trust boundary (HTTP body, upload, queue,
cookie, cache)? FP-killers: trusted/hardcoded source; `SafeLoader`/`SafeConstructor`; an
explicit type allow-list; schema validation before deserialize. `exploitability: reachable`
only when untrusted bytes reach the sink with no allow-list; `confidence: high` for a direct
request→sink flow, `medium` when the source is inferred.

**Severity.** Default **critical** (reachable gadget chain → RCE). Lower to **high** when a
type allow-list is present but incomplete; **medium** when the input is untrusted but no
known gadget exists on the classpath.

**Remediation.** Use a safe deserializer (`yaml.safe_load`, Psych `safe_load`,
`SafeConstructor`), an explicit type allow-list, or a data-only format (JSON without type
resolution). Never deserialize untrusted bytes into typed objects.

**Chains with.** `sast-deps` (a known-vulnerable gadget library raises confidence) →
`chain_id` "rce-gadget".

**Test fixture.** TP: `pickle.loads(request.data)`. TN: `yaml.safe_load(request.data)`. TN:
`pickle.loads(open('trusted.pkl','rb').read())`. Assert only the TP is flagged, `reachable`,
`critical`.

---

## sast-errorhandling — Security Error Handling

**Framework:** Web25 A10 · **Tier:** A · **CWE:** CWE-209 / CWE-636

**Scope.** Fail-open exception handlers, error responses that leak stack traces or secrets, debug
mode left enabled in production, and empty/swallowed catch blocks that silence security-relevant
exceptions. NOT: catching and logging expected application errors; non-security empty catches for
benign I/O cleanup; debug flags in test/dev environment files.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Python / Django / Flask | `DEBUG = True` in settings; bare `except: pass`; `traceback.print_exc()` in response; `app.run(debug=True)` |
| Java / Spring | `e.printStackTrace()` in response body; `server.error.include-stacktrace=always`; empty `catch (Exception e) {}` |
| Node / Express | `err.stack` in `res.json()`; `NODE_ENV` not set to `production`; empty `.catch(() => {})` |
| .NET / ASP.NET | `customErrors mode="Off"`; `<compilation debug="true">`; swallowed `catch (Exception) {}` |
| PHP | `display_errors = On`; `error_reporting(E_ALL)` in production; empty `catch (\Exception $e) {}` |
| Ruby / Rails | `config.consider_all_requests_local = true`; rescuing and silently returning `nil` |

**Verify.** Does the exception handler expose internal details (stack trace, SQL, file path, secret
value) to an untrusted caller, or does it swallow a security exception allowing the program to
proceed as if it succeeded? FP-killers: stack trace sent only to a structured logger (not to the
response); debug flag in a file explicitly excluded from production config; catch that re-raises
or records a security audit event. `exploitability: reachable` when the error output channel is
an HTTP response or API payload reachable without authentication; `confidence: high` for a direct
`e.printStackTrace()` / `err.stack` in a response handler, `medium` for a debug flag whose
production path is ambiguous.

**Severity.** Default **high** (information disclosure enabling further attacks). Raise to
**critical** when the error response contains a secret, credential, or private key. Lower to
**medium** when the stack trace is behind an authenticated admin endpoint; **low** when only a
generic error code is exposed.

**Remediation.** Return a generic error response to clients; log detail server-side with a
correlation ID. Set `DEBUG = False` / `NODE_ENV=production`. Catch specific exceptions; never
swallow security exceptions silently — record an audit event and return a safe failure response.

**Chains with.** `sast-hardcodedsecrets` (secrets surfaced in stack traces raise severity) →
`chain_id` "error-secret-leak".

**Test fixture.** TP: `except Exception as e: return jsonify({"error": str(e), "trace": traceback.format_exc()})`. TN: `except Exception as e: logger.error(e); return jsonify({"error": "Internal server error"})`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-massassign — Mass Assignment

**Framework:** API23 API3 · **Tier:** B · **CWE:** CWE-915

**Scope.** Auto-binding of request parameters directly to ORM model instances without an explicit
allow-list, enabling privilege escalation via overposting of fields such as `is_admin`, `role`,
or `balance`. NOT: explicit allow-listed parameter binding; DTOs / serializers with `fields`
restricted; forms using `fields`/`only` constraints.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Rails (Ruby) | `Model.new(params)`, `update(params)`, `params.permit!`, `attr_accessible` absent |
| Django (Python) | `ModelForm` with `fields = '__all__'`; direct `**request.POST` to model constructor |
| Spring (Java) | `@ModelAttribute` binding to entity class; `BeanUtils.copyProperties(request, entity)` |
| Express (Node) | `Object.assign(user, req.body)`; `User.create(req.body)` without field picking |
| Laravel (PHP) | `Model::create($request->all())`; `$model->fill($request->all())` without `$fillable` |
| ASP.NET | `[Bind]` without `Include`; `TryUpdateModelAsync` on entity without property list |

**Verify.** Is a user-supplied map (request body, query params, form data) passed directly to a
model/entity constructor or update method without an explicit field allow-list? FP-killers:
`params.require().permit(:field1, :field2)` pattern; `fields = ['field1', 'field2']` on the
serializer; DTO class that only exposes safe fields. `exploitability: reachable` when the model
contains privilege or financial fields and the endpoint is accessible without admin role;
`confidence: high` for `params.permit!` or `fields = '__all__'`; `medium` when
allow-list presence is inferred from adjacent code.

**Severity.** Default **high** (privilege escalation). Raise to **critical** when the model
contains an `is_admin` / `role` / `balance` field and the endpoint is unauthenticated or
low-privilege. Lower to **medium** when the model has no sensitive fields.

**Remediation.** Use an explicit allow-list: Rails `params.permit`, Django serializer `fields`,
Spring `@InitBinder` with `setAllowedFields`, Express explicit field picking. Never pass raw
request data directly to model constructors.

**Chains with.** `sast-missingauth` (unauthenticated endpoint + mass assignment = critical) →
`chain_id` "overpost-privesc".

**Test fixture.** TP: `User.create(req.body)` where `User` has an `isAdmin` field. TN: `User.create({ name: req.body.name, email: req.body.email })`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-excessivedata — Excessive Data Exposure

**Framework:** API23 API3 · **Tier:** B · **CWE:** CWE-213

**Scope.** Serializers or API responses that return the entire ORM object (including password
hashes, tokens, internal flags) instead of an explicit field allow-list. NOT: serializers
with `fields`, `only`, or `exclude` constraints that provably omit sensitive fields; internal
admin APIs that intentionally expose all fields with appropriate access control.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Django REST (Python) | `ModelSerializer` with `fields = '__all__'`; `serializer.data` from un-restricted queryset |
| Rails (Ruby) | `render json: @user` without `only:` / `except:`; `.to_json` on ActiveRecord object |
| Spring (Java) | `@ResponseBody` returning JPA entity directly; `ResponseEntity<UserEntity>` |
| Express (Node) | `res.json(user.toObject())`; `res.send(await User.findOne(...))` without field selection |
| Laravel (PHP) | `return $user` from controller without `$hidden`; `User::all()->toJson()` |
| FastAPI (Python) | response model is ORM model class instead of a Pydantic schema with field subset |

**Verify.** Does the serialization path from a model instance to an HTTP response include fields
that should be private (password, password_hash, token, secret, ssn, credit_card)? FP-killers:
`fields = ['id', 'name', 'email']` excludes sensitive fields; `$hidden = ['password']` in
Laravel; `exclude = ('password',)` in DRF; database query selects only the required columns.
`exploitability: reachable` when sensitive fields appear in the response schema and the endpoint
is accessible to users who should not see them; `confidence: high` for `fields = '__all__'` on a
model with a `password` column; `medium` when model fields must be inferred from the schema.

**Severity.** Default **high** (sensitive data exposure). Raise to **critical** when the response
includes password hashes, API keys, or PII fields returned to unauthenticated callers. Lower to
**medium** when the endpoint is admin-only with appropriate access control.

**Remediation.** Define an explicit serializer schema listing only the fields required by the
consumer. Never return a raw ORM object as an API response. Audit response schemas against the
data model to ensure sensitive fields are excluded.

**Chains with.** `sast-missingauth` (unauthenticated endpoint amplifies exposure severity) →
`chain_id` "data-overexposure".

**Test fixture.** TP: `class UserSerializer(ModelSerializer): class Meta: model = User; fields = '__all__'`. TN: `class UserSerializer(ModelSerializer): class Meta: model = User; fields = ['id', 'username', 'email']`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-tls — TLS Verification Disabled

**Framework:** Web25 A02 / A04 · **Tier:** A · **CWE:** CWE-295

**Scope.** Code that explicitly disables certificate or hostname verification for outbound TLS
connections, enabling machine-in-the-middle attacks. NOT: self-signed cert pinning with an
explicit trusted CA bundle; test/mock servers with TLS disabled via clearly scoped test helpers;
environment-gated flags that are demonstrably never set in production config.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Python (requests / httpx / urllib) | `verify=False`; `ssl._create_unverified_context()`; `ssl.CERT_NONE`; `check_hostname=False` |
| Go | `InsecureSkipVerify: true` in `tls.Config` |
| Node.js | `NODE_TLS_REJECT_UNAUTHORIZED=0`; `rejectUnauthorized: false` in `https.request` options |
| Java | `ALLOW_ALL_HOSTNAME_VERIFIER`; `TrustAllCerts` / `X509TrustManager` returning without validation; `HttpsURLConnection.setDefaultHostnameVerifier` with always-true lambda |
| .NET | `ServerCertificateValidationCallback` returning `true`; `ServicePointManager.ServerCertificateValidationCallback` |
| Ruby | `OpenSSL::SSL::VERIFY_NONE`; `verify_mode: OpenSSL::SSL::VERIFY_NONE` |
| PHP | `CURLOPT_SSL_VERIFYPEER => false`; `CURLOPT_SSL_VERIFYHOST => 0` |

**Verify.** Is the TLS verification flag reachable in a production code path (not test-only)?
FP-killers: flag set only inside `if Rails.env.test?` / `if os.getenv('TEST')` blocks that are
provably unreachable in production; custom `SSLContext` that provides a valid CA bundle instead
of disabling verification. `exploitability: reachable` when the flag is in production-reachable
code with no env-guard; `confidence: high` for a literal `verify=False`; `medium` when gated
behind an environment variable whose production value is ambiguous.

**Severity.** Default **high** (MITM on any outbound TLS connection). Raise to **critical** when
the affected connection carries credentials, tokens, or PII. Lower to **medium** when limited to
an internal network segment with no path to the internet.

**Remediation.** Remove the `verify=False` / `InsecureSkipVerify` flag. If a custom CA is
required, pass a CA bundle path (`verify='/path/to/ca.crt'`). Use cert pinning for high-value
connections. Never disable verification to work around expired or self-signed certificates in
production.

**Chains with.** `sast-hardcodedsecrets` (credentials transmitted over unverified TLS compound
severity) → `chain_id` "mitm-credential".

**Test fixture.** TP: `requests.get(url, verify=False)`. TN: `requests.get(url, verify='/etc/ssl/certs/ca-certificates.crt')`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-cookieflags — Missing Cookie Security Flags

**Framework:** Web25 A02 · **Tier:** A · **CWE:** CWE-1004 / CWE-614

**Scope.** Session or authentication cookies set without the `HttpOnly`, `Secure`, or `SameSite`
flags, enabling XSS-based cookie theft, network eavesdropping, and CSRF. NOT: non-session
cookies (analytics, preferences) where theft carries no authentication impact; cookies
explicitly scoped to non-HTTPS-only internal services; SameSite absent but CSRF token present
and validated.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Python / Flask | `set_cookie(` without `httponly=True, secure=True, samesite='Lax'`; `SESSION_COOKIE_HTTPONLY = False` |
| Python / Django | `SESSION_COOKIE_HTTPONLY = False`; `SESSION_COOKIE_SECURE = False`; `SESSION_COOKIE_SAMESITE` missing |
| Express (Node) | `res.cookie('session', val, {})` missing `httpOnly: true, secure: true, sameSite: 'lax'` |
| Java / Spring | `http.sessionManagement()` without `cookie.httpOnly(true).secure(true)`; `new Cookie(name, val)` without `setHttpOnly(true)` |
| PHP | `setcookie(` without `['httponly' => true, 'secure' => true, 'samesite' => 'Lax']`; `session.cookie_httponly = 0` |
| Rails (Ruby) | `cookies[:session] = { value: val }` without `httponly: true, secure: true, same_site: :lax` |
| .NET | `new CookieOptions { HttpOnly = false }` or missing `Secure = true` |

**Verify.** Is the cookie used for session management, authentication, or CSRF protection? Are
one or more of `HttpOnly`, `Secure`, or `SameSite` absent or set to an insecure value?
FP-killers: cookie is a non-sensitive client-readable cookie (theme, locale) with no auth
impact; service operates exclusively over HTTP on an internal loopback (Secure flag N/A);
`SameSite=None` paired with `Secure` and an explicit CSRF token validation. `exploitability:
reachable` when the cookie name matches a session/auth pattern and the missing flag is
exploitable on the serving domain; `confidence: high` for an explicit `httponly=False` or absent
flag on a `session`/`auth`/`token` named cookie; `medium` when the cookie purpose is inferred.

**Severity.** Default **high** (`HttpOnly` missing enables XSS-based session theft). Raise to
**critical** when `Secure` is also absent and the site serves HTTPS (cookie transmitted
in cleartext). Lower to **medium** when only `SameSite` is missing and an independent CSRF
defense is present.

**Remediation.** Set all three flags on every session cookie: `HttpOnly` (prevents JS access),
`Secure` (HTTPS-only transmission), `SameSite=Lax` or `Strict` (CSRF mitigation). Use framework
defaults: Django `SESSION_COOKIE_HTTPONLY = True`, Express `{ httpOnly: true, secure: true,
sameSite: 'lax' }`.

**Chains with.** `sast-xss` (XSS + missing HttpOnly = session takeover) → `chain_id`
"xss-session-theft"; `sast-csrf` (missing SameSite amplifies CSRF) → `chain_id` "csrf-cookie".

**Test fixture.** TP: `res.cookie('sessionId', token, { httpOnly: false })`. TN: `res.cookie('sessionId', token, { httpOnly: true, secure: true, sameSite: 'lax' })`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-secheaders — Missing Security Headers

**Framework:** Web25 A02 · **Tier:** A · **CWE:** CWE-693 / CWE-1021

**Scope.** HTTP responses missing security headers that prevent clickjacking (`X-Frame-Options`,
`frame-ancestors` CSP), content-type sniffing (`X-Content-Type-Options`), protocol downgrade
(`Strict-Transport-Security`), XSS via inline scripts (`Content-Security-Policy`), or
supply-chain attacks via CDN resources (`integrity` / SRI). NOT: headers absent on non-HTML API
responses where they carry no security value; CSP absent on an endpoint that serves no HTML;
HSTS absent on plain HTTP endpoints (not applicable).

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Express (Node) | Absence of `helmet()` middleware; manual `res.setHeader` missing `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security` |
| Django (Python) | `SECURE_BROWSER_XSS_FILTER = False`; `X_FRAME_OPTIONS` not `'DENY'`; `SECURE_HSTS_SECONDS = 0`; `django-csp` absent |
| Flask (Python) | `Talisman` / `flask-talisman` absent; no `@after_request` setting security headers |
| Spring (Java) | `http.headers().disable()`; `http.headers().frameOptions().disable()`; `http.headers().contentSecurityPolicy()` absent |
| Rails (Ruby) | `config.action_dispatch.default_headers` missing `X-Frame-Options`, `X-Content-Type-Options`; `secure_headers` gem absent |
| HTML templates | `<script src="https://cdn...">` without `integrity=` and `crossorigin=` attributes |

**Verify.** Is the response an HTML page or a page-framing-capable resource? Are one or more
critical security headers absent or set to a permissive value (`X-Frame-Options: ALLOWALL`,
`Content-Security-Policy: default-src *`)? FP-killers: the endpoint is a pure JSON API with
`Content-Type: application/json` and no HTML; CSP is set via a meta tag in the HTML template
(acceptable substitute for the header); `frame-ancestors` in CSP supersedes `X-Frame-Options`.
`exploitability: reachable` when the missing header enables a concrete attack path on the
serving origin; `confidence: high` for an explicit `.disable()` call or `SECURE_HSTS_SECONDS =
0`; `medium` when absence is inferred from a missing middleware.

**Severity.** Default **medium** (defence-in-depth header missing). Raise to **high** when HSTS
is absent on an HTTPS site (downgrade attack) or `X-Frame-Options` / CSP `frame-ancestors` is
absent (clickjacking on a sensitive page). Raise to **critical** when CSP is absent and inline
XSS is possible on the same page.

**Remediation.** Use a security-header middleware: Helmet.js for Express, `django-csp` +
`SECURE_*` settings for Django, `secure_headers` gem for Rails. Set at minimum:
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'self'`. Add `integrity`
and `crossorigin` to all CDN `<script>` and `<link>` tags.

**Chains with.** `sast-xss` (absent CSP amplifies XSS exploitability) → `chain_id`
"csp-xss-amplify"; `sast-csrf` (absent `SameSite` + absent frame isolation) → `chain_id`
"clickjack-csrf".

**Test fixture.** TP: Express app with `app.get('/dashboard', (req, res) => res.send(html))` and no `helmet()` call. TN: same app with `app.use(helmet())` before the route. Assert only the TP is flagged, `reachable`, `medium`.

---

## sast-crlf — CRLF / HTTP Response Splitting

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-93 / CWE-113

**Scope.** Untrusted input injected into HTTP response headers, `Location` redirect targets, log
lines, or cookie values without stripping carriage-return (`\r`, `%0d`) and line-feed (`\n`,
`%0a`) characters, enabling header injection, response splitting, log poisoning, and open
redirect chaining. NOT: input written only to the response body; URL redirect targets validated
against an explicit allowlist that prevents CR/LF bypass; log entries sanitized by a structured
logger (no raw string interpolation into log lines).

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Python (Flask / Django / FastAPI) | `response.headers[key] = user_input`; `redirect(user_input)` without validation; `logging.info(f"... {user_input}")` |
| Java (Servlet / Spring) | `response.setHeader(name, userInput)`; `response.addHeader`; `response.sendRedirect(userInput)`; `log.info("... " + userInput)` |
| Node / Express | `res.setHeader(name, req.query.value)`; `res.redirect(req.query.url)`; `console.log("User: " + req.body.name)` |
| PHP | `header("Location: " . $_GET['url'])`; `header($userControlledName . ": " . $val)` |
| Go | `w.Header().Set(name, r.URL.Query().Get("key"))`; `http.Redirect(w, r, userInput, 302)` |
| Ruby / Rails | `response.headers[key] = params[:value]`; `redirect_to params[:url]` without `allow_other_host` guard |

**Verify.** Does user-supplied input reach a `setHeader` / `addHeader` / `redirect` / log sink
without CR/LF stripping? FP-killers: input sanitized by `urllib.parse.quote` / `encodeURI`
before use in a header value; redirect target validated against an allowlist of known-safe
origins; structured logger that serializes the field as a JSON value (no raw newline injection
possible). `exploitability: reachable` when the affected header is written to an HTTP response
reaching an untrusted client; `confidence: high` for a direct `req.query → response.setHeader`
flow; `medium` when the source passes through intermediate functions.

**Severity.** Default **high** (response splitting / session fixation via Set-Cookie injection).
Raise to **critical** when a CR/LF payload can inject a `Set-Cookie` header or rewrite the
response body. Lower to **medium** for log poisoning only (no response-header impact).

**Remediation.** Strip or percent-encode `\r` and `\n` before inserting any user input into a
header value. Validate redirect targets against an allowlist. Use structured loggers that
serialize values as JSON fields rather than raw string interpolation.

**Chains with.** `sast-openredirect` (CRLF in redirect target compounds exploit surface) →
`chain_id` "crlf-redirect"; `sast-xss` (response-splitting can inject HTML body) → `chain_id`
"crlf-xss".

**Test fixture.** TP: `resp.headers['X-User'] = request.args.get('name')` (name = `foo\r\nSet-Cookie: admin=1`). TN: `resp.headers['X-User'] = request.args.get('name', '').replace('\r', '').replace('\n', '')`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-zipslip — Zip Slip / Archive Extraction Path Traversal

**Framework:** Web25 A01 · **Tier:** A · **CWE:** CWE-22

**Scope.** Archive extraction (zip, tar, jar, war, cpio, 7z) where entry names are used to
construct output file paths without canonicalization and containment checks, allowing a
maliciously crafted archive to write files outside the intended extraction directory (e.g.,
`../../etc/cron.d/backdoor`). NOT: extraction into a sandboxed temporary directory that is
immediately deleted; entry names filtered through a library that provably prevents path
traversal (e.g., `zipfile.Path` with containment enforcement); read-only operations that
inspect entries without writing.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| Python | `zipfile.ZipFile.extract(member, path)` / `extractall(path)` without member name validation; `tarfile.TarFile.extract` / `extractall` |
| Java | `new ZipEntry(entry.getName())` + `new FileOutputStream(destDir + entry.getName())`; `entry.getName()` used in path without `getCanonicalPath()` check |
| Go | `zip.File.Open()` + `os.Create(filepath.Join(dest, f.Name))` without `filepath.Clean` containment check |
| Node.js | `unzipper`, `adm-zip`, `extract-zip`, `tar` packages — `entry.path` used in `fs.createWriteStream(path.join(dest, entry.path))` without traversal check |
| .NET | `ZipArchiveEntry.FullName` used in `Path.Combine(dest, entry.FullName)` without `Path.GetFullPath` containment check |
| Ruby | `Zip::File.open` with `entry.name` in `File.join(dest, entry.name)` without `expand_path` containment |

**Verify.** Is the archive entry name used to construct a filesystem write path? Is the resolved
absolute path verified to be within the extraction root via `canonicalize` / `getCanonicalPath`
/ `Path.GetFullPath` before the file is created? FP-killers: entry name passed to a library
function that provably strips traversal sequences before write; extraction root is ephemeral and
unprivileged; entry names filtered against a regex that rejects `..` and absolute paths before
use. `exploitability: reachable` when the archive source is user-supplied (upload, URL fetch)
and the extraction path is within the web root, cron directory, or other privileged location;
`confidence: high` for a direct `entry.getName() → FileOutputStream` flow; `medium` when the
archive source is partially trusted.

**Severity.** Default **critical** (arbitrary file write → RCE via config/script overwrite).
Lower to **high** when the write path is outside the web root but within the application
directory; **medium** when the destination is a temporary directory with restricted execution.

**Remediation.** Resolve the canonical path of each entry's output file and assert it starts
with the canonical extraction root before writing. Reject entries with absolute paths or
sequences containing `..`. Use safe extraction helpers where available (`zipfile.Path` in Python
3.12+, `joschi/zip-iterator` for Java).

**Chains with.** `sast-pathtraversal` (same CWE family; path traversal in read context) →
`chain_id` "path-write-rce"; `sast-rce` (overwriting a config/script leads to code execution)
→ `chain_id` "zipslip-rce".

**Test fixture.** TP: `zip_ref.extractall(dest_dir)` where archive contains entry `../../etc/passwd`. TN: `for member in zip_ref.namelist(): assert not os.path.isabs(member) and '..' not in member.split('/'); zip_ref.extract(member, dest_dir)`. Assert only the TP is flagged, `reachable`, `critical`.

---

## sast-pipelineinj — CI/CD Pipeline Injection

**Framework:** Web25 A03 · **Tier:** A · **CWE:** CWE-94

**Scope.** Untrusted event payload values (e.g., `github.event.pull_request.title`,
`github.event.issue.body`, `github.event.comment.body`, `github.head_ref`) interpolated
directly into a `run:` shell step or `actions/github-script` via `${{ ... }}` expression
syntax, enabling a pull-request author to inject arbitrary shell commands into the CI runner.
NOT: values from trusted contexts (`github.sha`, `github.actor` on a protected branch);
interpolation into non-shell steps (e.g., a pure `with:` input to a third-party action that
escapes it); workflow files that gate on `pull_request_target` with environment approval
required.

**Recon sinks** (recon-phase grep/AST targets):

| Platform | Sinks |
|---|---|
| GitHub Actions | `run: ... ${{ github.event.pull_request.title }}` / `${{ github.event.issue.body }}` / `${{ github.event.comment.body }}` / `${{ github.head_ref }}` / `${{ github.event.inputs.* }}` inside `run:` or `actions/github-script` |
| GitHub Actions | `env:` block assigning `${{ github.event.* }}` then referenced in `run:` via `$ENV_VAR` (safer but still a risk if the env var is passed to shell eval) |
| GitLab CI | `.gitlab-ci.yml` `script:` steps interpolating `$CI_COMMIT_REF_NAME` or custom trigger variables without quoting |
| CircleCI | Pipeline parameter values from API trigger used in a `run:` step without sanitization |

**Verify.** Is a `github.event.*` or equivalent user-controlled value interpolated via `${{ }}`
directly inside a `run:` block? FP-killers: the value is assigned to an environment variable
(not `${{ }}` inline in `run:`) AND the shell step does not `eval` or `bash -c` that variable;
the workflow triggers only on `push` to a protected branch (no external contributor control);
`pull_request_target` with a required environment approval gate. `exploitability: reachable` when
the workflow trigger allows external contributors (e.g., `pull_request`, `issue_comment`,
`pull_request_review_comment`); `confidence: high` for a direct `${{ github.event.pull_request.title }}`
in `run:`; `medium` when the injection path is through an intermediate env var.

**Severity.** Default **critical** (arbitrary command execution on the CI runner, with access to
repository secrets). Lower to **high** when the runner has no access to secrets and the
repository is private with restricted contributor access.

**Remediation.** Never interpolate `github.event.*` directly into `run:` steps. Pass untrusted
values via environment variables and reference them as `$ENV_VAR` in shell. Use
`toJSON(github.event.*)` for structured data. Validate and sanitize branch names before use.
Prefer actions that accept inputs over inline shell for untrusted data.

**Chains with.** `sast-hardcodedsecrets` (secrets in the runner environment are exfiltrated via
the injected command) → `chain_id` "pipeline-secret-exfil".

**Test fixture.** TP: `run: echo "PR title: ${{ github.event.pull_request.title }}"` in a workflow triggered by `pull_request`. TN: `env:\n  PR_TITLE: ${{ github.event.pull_request.title }}\nrun: echo "PR title: $PR_TITLE"`. Assert only the TP is flagged, `reachable`, `critical`.

---

## sast-depconfusion — Dependency Confusion

**Framework:** Web25 A03 · **Tier:** A · **CWE:** CWE-427

**Scope.** Internal package names resolvable from public registries (npm, PyPI, RubyGems) when
registry scoping or allowlisting is absent, and `postinstall` / `prepare` / setup scripts in
dependencies that execute arbitrary code at install time. NOT: packages explicitly scoped to a
private registry via `.npmrc` / `pip.conf` with `index-url` pinned and no public fallback;
packages with `integrity` / hash pins verified before execution; `postinstall` scripts in
well-known, widely-used packages reviewed by the security team.

**Recon sinks** (recon-phase grep/AST targets):

| Platform | Sinks |
|---|---|
| npm / pnpm / yarn | Unscoped package names in `package.json` `dependencies` / `devDependencies` that match known internal names; `.npmrc` missing `@scope:registry`; `postinstall` / `preinstall` / `prepare` script in any dependency |
| PyPI (pip) | `requirements.txt` / `pyproject.toml` package names without a hash pin (`--require-hashes`) or index pin; `setup.py` with custom install commands in dependencies |
| RubyGems | `Gemfile` gems without `source:` pointing to a private Gemgems server; no `gemspec` integrity checking |
| Maven / Gradle | Artifact IDs matching internal naming conventions resolved from Maven Central without a checksum; `gradle.properties` missing `systemProp.org.gradle.internal.http.connectionTimeout` pinned to internal nexus |
| NuGet | Package IDs matching internal names without a private feed configured in `NuGet.config` with `clear` element removing public feeds |

**Verify.** Does the package name appear in a public registry search? Is there no explicit
registry lock preventing public resolution? Does any dependency include a `postinstall` or
equivalent lifecycle script? FP-killers: `.npmrc` has `@internal:registry=https://internal.registry/`
with `registry=` set to an internal-only mirror and no public fallback; `pip.conf` sets
`index-url` to an internal PyPI with no `extra-index-url`; all packages pinned with
hash verification (`--require-hashes` / lock file with integrity field). `exploitability:
reachable` when the internal package name is discoverable and the registry config permits public
fallback; `confidence: high` for an unscoped internal-looking name with a public registry as the
only configured source; `medium` when internal naming convention must be inferred.

**Severity.** Default **critical** (supply-chain RCE at install time for `postinstall` scripts).
Lower to **high** when no lifecycle script is present but the package could be substituted;
**medium** when only a devDependency with no production impact.

**Remediation.** Scope all internal packages (`@company/pkg-name`). Pin the private registry in
`.npmrc` / `pip.conf` with no public fallback. Enable `--require-hashes` for pip. Audit
`postinstall` scripts in all dependencies. Use Sigstore / Artifact Attestations to verify
package provenance.

**Chains with.** `sast-rce` (malicious postinstall script achieves code execution) → `chain_id`
"dep-confusion-rce"; `sast-hardcodedsecrets` (install-time script exfiltrates secrets from the
build environment) → `chain_id` "dep-confusion-secret-exfil".

**Test fixture.** TP: `package.json` with `"internal-utils": "^1.0.0"` and no scoped registry in `.npmrc`. TN: `package.json` with `"@company/internal-utils": "^1.0.0"` and `.npmrc` containing `@company:registry=https://npm.internal.company.com/`. Assert only the TP is flagged, `reachable`, `critical`.

---

## sast-dangerousapi — Dangerous API Inventory

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-95 / CWE-470

**Scope.** Inventory of inherently dangerous sinks: dynamic code evaluation (`eval`, `Function`,
`exec`, `compile`), reflective class/method invocation, native-code bridges (JNI, ctypes,
cffi), and process-spawning functions — regardless of whether taint is proven — because each
occurrence requires explicit human review. NOT: `eval` applied to a provably constant/literal
argument; reflection used only on hard-coded class names; `subprocess.run` with a literal
list argument containing no user input.

**Recon sinks** (recon-phase grep/AST targets):

| Language/Framework | Sinks |
|---|---|
| JavaScript / Node | `eval(`, `new Function(`, `setTimeout(str,`; `vm.runInNewContext(`; `require(userInput)`; `child_process.exec(` / `execSync(` with string arg |
| Python | `eval(`; `exec(`; `compile(`; `__import__(userInput)`; `importlib.import_module(userInput)`; `ctypes.CDLL(`; `subprocess.Popen(shell=True`; `os.system(` |
| Java | `Method.invoke(`; `Class.forName(userInput)`; `Runtime.getRuntime().exec(`; `ScriptEngine.eval(`; JNI `System.loadLibrary(` with variable arg |
| PHP | `eval(`; `preg_replace` with `/e` modifier; `call_user_func($userInput`; `call_user_func_array($userInput`; `create_function(` |
| Ruby | `eval(`; `send(userInput`; `public_send(userInput`; `constantize(userInput`; `Kernel.system(userInput` |
| .NET | `CSharpCodeProvider().CompileAssemblyFromSource`; `Assembly.Load(userBytes)`; `Activator.CreateInstance(Type.GetType(userInput))` |
| Go | `plugin.Open(userInput)`; `os/exec.Command(userInput)` with variable first arg |

**Verify.** Is any argument to the dangerous sink derived from user-controllable input? Even when
the argument appears constant, flag the occurrence for manual review and downgrade confidence.
FP-killers: `eval` on a verified-constant string literal; `Class.forName` called with a
hard-coded class name string; `subprocess.run(['ls', '-la'], shell=False)` with no user input in
the list. `exploitability: reachable` when the sink argument contains user input with no
allowlist; `confidence: high` for direct user-input-to-sink; `medium` for dangerous sink with
opaque argument (flag for human review regardless); `low` for constant argument (informational
only).

**Severity.** Default **high** (dangerous API with potentially controlled argument). Raise to
**critical** when user input reaches the sink with no allowlist or escaping (proven taint). Lower
to **medium** for reflection on a whitelist-constrained argument; **low** for purely informational
inventory of constant-argument dangerous calls.

**Remediation.** Replace `eval` / `exec` with a safe alternative (AST parsing, a plugin
interface, a pre-compiled list of allowed operations). Replace string-based `exec` / `system`
calls with list-form `subprocess.run([...], shell=False)`. Replace reflective instantiation with
a factory pattern mapping string keys to allowed constructors. Wrap JNI / ctypes calls in a
strict input-validation layer.

**Chains with.** `sast-rce` (confirmed taint to dangerous API = RCE finding) → `chain_id`
"dangerousapi-rce"; `sast-prototype` (JavaScript `eval` + prototype pollution amplify each
other) → `chain_id` "eval-proto".

**Test fixture.** TP: `result = eval(request.args.get('expr'))`. TN: `SAFE_OPS = {'add': lambda a, b: a + b}; result = SAFE_OPS[request.args.get('op')](x, y)`. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-ssrfimds — Cloud Metadata SSRF (IMDSv1)

**Framework:** Web25 A01 / API23 API7 · **Tier:** A · **CWE:** CWE-918

**Scope.** Server-Side Request Forgery where a user-controlled URL can reach the cloud instance
metadata endpoint (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`,
`169.254.170.2` for ECS), combined with detection of cloud execution context and IMDSv1
(token-less) usage. NOT: SSRF mitigated by IMDSv2 enforcement (PUT-token required) with no
path to bypass; requests blocked by an egress firewall allowlist that excludes the metadata
CIDR; metadata endpoint URL not reachable from the application network.

**Recon sinks** (recon-phase grep/AST targets):

| Signal | Patterns |
|---|---|
| User-controlled URL fetch | `requests.get(user_url)`; `httpx.get(user_url)`; `fetch(req.body.url)`; `HttpClient.GetAsync(userUrl)`; `RestTemplate.getForObject(userUrl,`; `curl_exec` with `CURLOPT_URL => $userInput` |
| IMDSv1 usage | `http://169.254.169.254/latest/meta-data/` without a prior `PUT` for a token; `http://metadata.google.internal/computeMetadata/v1/` without `Metadata-Flavor: Google` header from a *server-side* caller |
| Cloud context indicators | `AWS_DEFAULT_REGION` / `AWS_EXECUTION_ENV` / `ECS_CONTAINER_METADATA_URI` / `GOOGLE_CLOUD_PROJECT` / `METADATA_FLAVOR` environment variables present |
| URL allowlist absent | No regex/SSRF-guard library (`ssrffilter`, `blind-ssrf-chains`, AWS IMDSv2 hop-limit) wrapping the outbound request |

**Verify.** Is the URL fetch sink reachable from user input AND is the cloud metadata endpoint
reachable from the execution environment (inferred from cloud env vars or known cloud provider
deployment context)? FP-killers: IMDSv2 enforced via `HttpTokens: required` / hop-limit 1 and
code does perform the PUT-token preflight; URL is validated against an allowlist that excludes
`169.254.0.0/16` and RFC-1918 ranges; metadata endpoint explicitly blocked in egress policy
documented in the finding context. `exploitability: reachable` when a user-controlled URL
reaches an outbound HTTP call with no SSRF filter and cloud metadata CIDR is reachable;
`confidence: high` for a direct `user_url → requests.get` in a Lambda / EC2 / GCE / AKS
context; `medium` when cloud context is inferred from dependencies rather than env vars.

**Severity.** Default **critical** (credential theft via metadata endpoint → full cloud account
takeover). Lower to **high** when IMDSv2 is partially enforced (hop limit set but HttpTokens
not `required`); **medium** when the cloud provider has no sensitive credentials on the metadata
path reachable from the identified endpoint.

**Remediation.** Enforce IMDSv2 (`HttpTokens: required`) on all EC2 instances and ECS task
definitions. Validate user-supplied URLs against an allowlist (block RFC-1918, link-local
`169.254.0.0/16`, and IPv6 equivalents). Use a dedicated SSRF-guard library. Apply egress
network controls blocking metadata CIDRs from application subnets.

**Chains with.** `sast-ssrf` (generic SSRF skill provides the broader sink inventory) →
`chain_id` "ssrf-imds"; `sast-iac` (IMDSv2 not enforced in Terraform/CloudFormation raises
confidence) → `chain_id` "imds-iac-confirm".

**Test fixture.** TP: `url = request.args.get('url'); resp = requests.get(url)` deployed in a Lambda (AWS env vars present) with no URL validation. TN: `url = request.args.get('url'); assert not is_private_ip(url); resp = requests.get(url)` with `is_private_ip` blocking `169.254.0.0/16`. Assert only the TP is flagged, `reachable`, `critical`.
