---
name: sast-postmessage
description: >-
  Detect origin-trust failures in browser and WebSocket contexts using a
  three-phase approach: recon (find postMessage handlers, WebSocket upgrade
  points, and target="_blank" links), batched verify (trace whether event.data
  flows to a sink without an origin check, whether WebSocket connections are
  exploitable via cross-site request, and whether reverse-tabnabbing is
  possible, in parallel subagents of 3 candidates each), and merge (consolidate
  into sast/postmessage-results.md and sast/postmessage-results.json). Covers
  CWE-346 (origin validation error) across three related attack classes:
  postMessage-without-origin-check, cross-site WebSocket hijacking (CSWSH), and
  reverse-tabnabbing.
version: 0.1.0
---

# postMessage / CSWSH / Reverse-Tabnabbing (Origin Trust) Detection

You are performing a focused security assessment to find origin-trust failures in browser and WebSocket contexts. This skill uses a three-phase approach with subagents: **recon** (find candidates), **batched verify** (determine exploitability in parallel batches of up to 3 candidates each), and **merge** (consolidate batch results into one report and one JSON file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What are Origin-Trust Failures

Origin-trust failures occur when a web application processes a cross-origin message, WebSocket connection, or navigation event without verifying the calling origin. There are three related attack classes covered by this skill.

The core pattern: *cross-origin input is accepted and acted upon without checking that the sender is a trusted origin.*

### Attack Class 1 — postMessage without Origin Check

`window.postMessage()` sends messages between `Window` objects regardless of their origin. A `message` event listener that reads `event.data` without first checking `event.origin` against a trusted allowlist will process messages from any page, including attacker-controlled pages. When `event.data` is then rendered into the DOM, passed to `eval`, or used to mutate sensitive application state, the vulnerability is equivalent to XSS.

**Typical sink chain**: attacker page → `targetWindow.postMessage(payload, '*')` → victim handler reads `event.data` without origin guard → `innerHTML = event.data.html` → XSS.

### Attack Class 2 — Cross-Site WebSocket Hijacking (CSWSH)

WebSocket connections are initiated via an HTTP upgrade request that browsers automatically attach session cookies to. WebSocket servers that do not validate the `Origin` header on the upgrade request can be contacted from any attacker-controlled page using `new WebSocket('wss://victim.example.com/ws')`. If the WebSocket session is authenticated by cookie, the attacker's page inherits those credentials and can read and write authenticated WebSocket traffic — functionally identical to CSRF for WebSocket channels.

**Typical sink chain**: attacker page → `new WebSocket('wss://victim/ws')` (browser attaches victim's session cookies) → server accepts upgrade without origin check → attacker reads/writes authenticated WS frames.

### Attack Class 3 — Reverse-Tabnabbing

When an anchor tag or `window.open()` opens a URL in a new tab without `rel="noopener"`, the newly opened page has access to the opener window via `window.opener`. If the opened URL is attacker-controlled (e.g., a user-supplied link rendered without sanitization), the attacker's page can redirect the original page to a phishing URL by executing `window.opener.location = 'https://evil.example.com'`. The user returns to their original tab and sees a convincing but fake page.

**Typical sink chain**: `<a href="[user-supplied URL]" target="_blank">` without `rel="noopener noreferrer"` → attacker controls linked page → `window.opener.location = phishing_url`.

### What These Vulnerabilities ARE

**postMessage handler sinks** — handlers that use `event.data` without a guard:
- `window.addEventListener('message', handler)` or `self.addEventListener('message', handler)` where the handler body reads `event.data.*` fields and passes them to DOM sinks, fetch calls, state mutations, or storage writes without checking `event.origin`
- Service workers and shared workers that listen to `self.on('message', ...)` and act on `data` without origin validation
- React/Vue/Angular message bus wrappers that forward postMessage payloads to component state

**WebSocket server upgrade endpoints** — upgrade handlers that skip Origin validation:
- Node.js `ws` library: `wss.on('connection', (socket, req) => { /* no req.headers.origin check */ })`
- Express-ws middleware that does not inspect `req.headers.origin` on the upgrade
- Socket.IO with wildcard CORS (`cors: { origin: '*' }`) on an authenticated namespace
- Python `websockets` library: `serve(handler, host, port)` where `handler` does not check `websocket.request_headers['Origin']`
- Django Channels: `WebsocketConsumer.connect()` without checking `self.scope['headers']` for origin
- Go `gorilla/websocket`: `upgrader.CheckOrigin = func(r *http.Request) bool { return true }` (explicit allowall) or no `CheckOrigin` override when cookies are used

**Tabnabbing sinks** — `target="_blank"` without `rel="noopener"`:
- HTML: `<a href="url" target="_blank">` without `rel="noopener noreferrer"`
- JSX/React: `<a href={url} target="_blank">` without `rel="noopener noreferrer"`
- Vue template: `<a :href="url" target="_blank">` without `rel="noopener noreferrer"`
- Angular template: `<a [href]="url" target="_blank">` without `rel="noopener noreferrer"`
- JavaScript: `window.open(url, '_blank')` without a subsequent `opened.opener = null`
- Server-side rendered HTML where `target="_blank"` links are generated from user-supplied URLs

### What These Vulnerabilities are NOT

Do not flag these as origin-trust failures:

- **`postMessage` handlers that unconditionally discard the payload**: `window.addEventListener('message', () => {})` or handlers that never read `event.data` — there is no sink.
- **WebSocket endpoints not using cookie/session auth**: If the server requires a token in the first WS frame or in a URL query parameter and does not rely on cookies, CSWSH does not apply because the attacker's page cannot supply the token.
- **WebSocket endpoints behind a CORS-equivalent allowlist**: If the upgrade handler checks `Origin` against `settings.ALLOWED_HOSTS` or an explicit allowlist before proceeding, the endpoint is protected.
- **`target="_blank"` links to same-origin pages**: If the link points to the same origin and the page is trusted, tabnabbing is not possible.
- **`target="_blank"` with explicit `rel="noopener"` or `rel="noopener noreferrer"`**: These attributes sever the `window.opener` reference.
- **`window.open` with `noopener` in the windowFeatures string**: `window.open(url, '_blank', 'noopener')` is safe.
- **CSP `frame-ancestors` without other controls**: CSP alone does not prevent postMessage or CSWSH — it prevents embedding, not cross-origin messaging.

### Patterns That Prevent These Vulnerabilities

**1. postMessage origin guard — strict equality**
```javascript
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted.example.com') return;  // guard
  document.getElementById('out').innerHTML = event.data.html;
});
```

**2. postMessage origin guard — allowlist**
```javascript
const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];

window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.includes(event.origin)) return;  // guard
  processMessage(event.data);
});
```

**3. WebSocket origin validation — Node.js / ws**
```javascript
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const origin = req.headers['origin'];
  const allowedOrigins = process.env.WS_ALLOWED_ORIGINS.split(',');
  if (!allowedOrigins.includes(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});
```

**4. WebSocket origin validation — Django Channels**
```python
class ChatConsumer(WebsocketConsumer):
    ALLOWED_ORIGINS = {'https://app.example.com'}

    def connect(self):
        origin = dict(self.scope['headers']).get(b'origin', b'').decode()
        if origin not in self.ALLOWED_ORIGINS:
            self.close(code=4003)
            return
        self.accept()
```

**5. WebSocket origin validation — gorilla/websocket**
```go
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        allowedOrigins := strings.Split(os.Getenv("WS_ALLOWED_ORIGINS"), ",")
        origin := r.Header.Get("Origin")
        for _, allowed := range allowedOrigins {
            if origin == allowed {
                return true
            }
        }
        return false
    },
}
```

**6. Reverse-tabnabbing prevention — HTML/JSX**
```html
<!-- HTML -->
<a href="https://external.example" target="_blank" rel="noopener noreferrer">Link</a>
```
```jsx
// React JSX
<a href={url} target="_blank" rel="noopener noreferrer">Link</a>
```

**7. Reverse-tabnabbing prevention — window.open**
```javascript
const child = window.open(url, '_blank');
if (child) child.opener = null;  // sever reference after open
// Alternative: use the windowFeatures string
window.open(url, '_blank', 'noopener,noreferrer');
```

---

## Vulnerable vs. Secure Examples

### postMessage — Missing Origin Check

```javascript
// VULNERABLE: event.data flows to innerHTML with no origin guard
window.addEventListener('message', (event) => {
  document.getElementById('output').innerHTML = event.data.html;
  localStorage.setItem('token', event.data.token);
});

// VULNERABLE: eval on message data — arbitrary code execution
window.addEventListener('message', (event) => {
  eval(event.data.command);
});

// SECURE: origin guard before any data access
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') return;  // guard must be first
  document.getElementById('output').innerHTML = event.data.html;
});

// SECURE: allowlist guard
const ALLOWED = new Set(['https://app.example.com', 'https://cdn.example.com']);
window.addEventListener('message', (event) => {
  if (!ALLOWED.has(event.origin)) return;
  processData(event.data);
});
```

### postMessage — React State Mutation Without Guard

```jsx
// VULNERABLE: Redux dispatch triggered by unverified postMessage
useEffect(() => {
  const handler = (event) => {
    dispatch(setAuthToken(event.data.token));   // no origin check
  };
  window.addEventListener('message', handler);
  return () => window.removeEventListener('message', handler);
}, [dispatch]);

// SECURE: verify before dispatch
useEffect(() => {
  const handler = (event) => {
    if (event.origin !== process.env.REACT_APP_TRUSTED_ORIGIN) return;
    dispatch(setAuthToken(event.data.token));
  };
  window.addEventListener('message', handler);
  return () => window.removeEventListener('message', handler);
}, [dispatch]);
```

### CSWSH — Node.js / ws

```javascript
// VULNERABLE: no origin check; any page can open a WS with the victim's cookies
const wss = new WebSocket.Server({ port: 8080 });
wss.on('connection', (ws, req) => {
  const userId = req.headers.cookie.split('session=')[1];  // cookie-based auth
  ws.on('message', (msg) => handleUserMessage(userId, msg));
});

// SECURE: validate origin before upgrading
const http = require('http');
const WebSocket = require('ws');
const ALLOWED = new Set((process.env.WS_ORIGINS || '').split(','));

const server = http.createServer();
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (!ALLOWED.has(req.headers.origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});
```

### CSWSH — Python websockets

```python
# VULNERABLE: open to any origin
import asyncio, websockets

async def handler(websocket, path):
    # cookie-based session resolved from headers, no origin check
    async for message in websocket:
        await process(message)

asyncio.run(websockets.serve(handler, 'localhost', 8765))

# SECURE: reject non-allowlisted origins
ALLOWED_ORIGINS = {'https://app.example.com'}

async def handler(websocket, path):
    origin = websocket.request_headers.get('Origin', '')
    if origin not in ALLOWED_ORIGINS:
        await websocket.close(1008, 'Forbidden origin')
        return
    async for message in websocket:
        await process(message)
```

### CSWSH — Socket.IO with wildcard CORS on authenticated namespace

```javascript
// VULNERABLE: wildcard CORS on authenticated namespace
const io = require('socket.io')(server, {
  cors: { origin: '*', credentials: true },  // wildcard + credentials = CSWSH
});

io.use(authenticateSocket);
io.on('connection', (socket) => { /* ... */ });

// SECURE: explicit origin allowlist
const io = require('socket.io')(server, {
  cors: {
    origin: ['https://app.example.com', 'https://admin.example.com'],
    credentials: true,
  },
});
```

### CSWSH — Django Channels

```python
# VULNERABLE: connect() never checks origin
class NotificationConsumer(WebsocketConsumer):
    def connect(self):
        user = self.scope['user']            # relies on session cookie
        self.accept()                        # accepts from any origin

# SECURE: origin guard in connect()
class NotificationConsumer(WebsocketConsumer):
    ALLOWED_ORIGINS = {'https://app.example.com'}

    def connect(self):
        headers = dict(self.scope['headers'])
        origin = headers.get(b'origin', b'').decode()
        if origin not in self.ALLOWED_ORIGINS:
            self.close(code=4003)
            return
        self.accept()
```

### Reverse-Tabnabbing — HTML and JSX

```html
<!-- VULNERABLE: no rel attribute; opener has window.opener access -->
<a href="https://external-site.com" target="_blank">Visit</a>

<!-- VULNERABLE: partial rel; noopener is missing in older browsers -->
<a href="https://external-site.com" target="_blank" rel="noreferrer">Visit</a>

<!-- SECURE: both noopener and noreferrer -->
<a href="https://external-site.com" target="_blank" rel="noopener noreferrer">Visit</a>
```

```jsx
// VULNERABLE: missing rel in React
function ExternalLink({ href, children }) {
  return <a href={href} target="_blank">{children}</a>;
}

// SECURE: always include rel when using target="_blank"
function ExternalLink({ href, children }) {
  return <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>;
}
```

### Reverse-Tabnabbing — window.open

```javascript
// VULNERABLE: opener link is preserved
function openHelp(url) {
  window.open(url, '_blank');
}

// SECURE: sever opener reference
function openHelp(url) {
  const child = window.open(url, '_blank', 'noopener,noreferrer');
  if (child) child.opener = null;  // belt-and-suspenders
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find Origin-Trust Candidates

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase that is a candidate for an origin-trust failure — postMessage handlers, WebSocket upgrade/connection handlers, and `target="_blank"` anchors or `window.open` calls without `noopener`. Write all candidates to `sast/postmessage-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the frontend stack (React, Vue, Angular, vanilla JS), backend stack (Node.js, Python, Go, Java), WebSocket libraries in use, and template engines for rendered HTML.
>
> **What to search for:**
>
> **Category A — postMessage handlers:**
>
> Search for `addEventListener('message'` or `addEventListener("message"` in all `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`, `.vue`, `.svelte`, `.html` files. Also search for `.on('message'` in worker contexts. For each match:
> - Record the file and line number.
> - Extract the handler body (typically the next 10–30 lines).
> - Note whether the handler body reads `event.data` (or destructures from it) before checking `event.origin`.
> - A handler that reads `event.data` or any property of `event.data` BEFORE checking `event.origin` is a candidate — even if there is a check elsewhere in the handler.
> - A handler that checks `event.origin` as the very first statement (before any `event.data` access) and returns or throws on mismatch is **not a candidate** — skip it.
> - Also search for wrapper patterns: `(event) => dispatch(...)`, `(e) => setState(...)`, or `(msg) => fetch(...)` triggered by postMessage without an explicit origin guard.
>
> **Category B — WebSocket server upgrade / connection handlers:**
>
> Search for:
> - Node.js `ws`: `.on('connection',` in files that also contain `WebSocket.Server` or `new WebSocket.Server`; look for the upgrade path.
> - Express-ws: `app.ws(` or `router.ws(`
> - Socket.IO: `io = require('socket.io')` or `io = socketio(` — note the `cors` config value.
> - Python `websockets`: `websockets.serve(` or `async with websockets.connect(` on the server side
> - Python `aiohttp`: `web.WebSocketResponse()` usage in handlers
> - Django Channels: `class ... WebsocketConsumer` or `class ... AsyncWebsocketConsumer` — look for `connect(self)` method
> - Go `gorilla/websocket`: `upgrader.Upgrade(` — note whether `upgrader.CheckOrigin` is overridden and what it returns
> - Go `nhooyr.io/websocket`: `websocket.Accept(` — note the `InsecureSkipVerify` option
>
> For each WebSocket endpoint, note:
> - Whether session cookies are involved in authentication (check for session middleware, cookie-based auth).
> - Whether `Origin` header is read and compared anywhere in the upgrade flow.
> - Whether there is a CORS config that names explicit origins vs. `*` or missing.
>
> **Category C — `target="_blank"` without `noopener`:**
>
> Search for `target="_blank"` in `.html`, `.htm`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.erb`, `.jinja2`, `.j2`, `.html.j2`, `.twig`, `.blade.php`, `.njk`, `.ejs` files. Also search for `window.open(` with `'_blank'` in `.js`, `.ts`, `.jsx`, `.tsx` files. For each match:
> - Record the file and line number.
> - Note whether `rel="noopener"` or `rel="noopener noreferrer"` is present in the same element.
> - For `window.open`, note whether `'noopener'` is in the third argument string, or whether the return value has `.opener = null` set immediately after.
> - If the `href` or URL argument is static and clearly a same-origin path (e.g., `/help`, `./docs`), note this — it reduces severity but the tabnabbing risk still exists if the page could be hijacked.
> - If the `href` comes from a variable that may be user-supplied, escalate priority.
>
> **Output format** — write to `sast/postmessage-recon.md`:
>
> ```markdown
> # postMessage / CSWSH / Tabnabbing Recon: [Project Name]
>
> ## Summary
> Found [N] candidates: [A] postMessage handlers, [B] WebSocket endpoints, [C] target="_blank" links.
>
> ## Candidates
>
> ### 1. [Category A|B|C] — [Descriptive name — e.g., "postMessage handler in chat.js updates DOM"]
> - **Category**: A (postMessage) | B (WebSocket) | C (Tabnabbing)
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / component / endpoint**: [function name, component, or route]
> - **Trigger pattern**: [e.g., `addEventListener('message', handler)` / `wss.on('connection', ...)` / `<a target="_blank">`]
> - **Key concern**: [e.g., "reads event.data.html before any origin check" / "no req.headers.origin validation" / "href from user prop, no rel=noopener"]
> - **Code snippet**:
>   ```
>   [relevant code — 5-15 lines centered on the candidate]
>   ```
>
> [Repeat for each candidate, numbered sequentially]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/postmessage-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty), **skip Phase 2 and Phase 3 entirely**. Instead, write the following two files and stop (you may delete `sast/postmessage-recon.md` after writing):

`sast/postmessage-results.md`:
```markdown
# postMessage / CSWSH / Tabnabbing Analysis Results

No vulnerabilities found.
```

`sast/postmessage-results.json`:
```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Confirm Exploitability (Batched)

After Phase 1 completes, read `sast/postmessage-recon.md` and split the candidates into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/postmessage-recon.md` and count the numbered candidate sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/postmessage-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary stack from `sast/architecture.md` and select relevant examples from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate, determine whether the origin-trust failure is exploitable. Write results to `sast/postmessage-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand auth mechanisms, trusted origins, deployment topology, and which domains communicate with each other.
>
> ---
>
> **For Category A candidates (postMessage handlers) — answer these questions:**
>
> **Q1: Does `event.data` (or any field of it) flow to a dangerous sink?**
>
> Dangerous sinks for postMessage data include:
> - DOM sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` or `bypassSecurityTrustHtml`
> - JavaScript execution: `eval()`, `setTimeout(string, ...)`, `setInterval(string, ...)`, `new Function(string)()`
> - Sensitive state mutation: dispatching auth tokens, setting session cookies, writing credentials to `localStorage` or `sessionStorage`
> - Network requests with unvalidated data: `fetch(event.data.url, ...)` where the URL is fully attacker-controlled
> - Redirect: `location.href = event.data.redirect` without allowlist validation
>
> If `event.data` does NOT flow to any dangerous sink (e.g., the handler only logs it, or immediately discards it), classify as **Not Vulnerable**.
>
> **Q2: Is there a working origin guard before the sink?**
>
> A working guard must:
> - Execute BEFORE any `event.data` access or sink operation.
> - Compare `event.origin` against a hardcoded constant or a hardcoded allowlist array/Set.
> - Return, throw, or prevent execution when the origin does not match.
>
> These are **NOT sufficient guards**:
> - `if (event.origin) { ... }` — truthy check only, does not validate the value
> - `if (event.origin.endsWith('.example.com'))` — subdomain bypass (attacker registers `evil.example.com` or `app.example.com.evil.com`)
> - `if (event.origin.includes('example.com'))` — substring bypass (`https://evil.example.com.attacker.com`)
> - A guard present but placed AFTER `event.data` is already read and passed somewhere
> - A guard that only runs inside an `if/else` branch that is not always taken
>
> **Q3: What is the severity?**
> - `high` when `event.data` reaches an HTML/JS execution sink without origin check — XSS equivalent.
> - `high` when `event.data` causes session/auth state mutation (token storage, auth dispatch) without origin check.
> - `medium` when `event.data` causes non-script state mutation (UI config, routing, preferences) that an attacker can exploit for meaningful impact.
> - `low` when the sink is benign (log output only, display of non-sensitive data with escaping).
>
> **Q4: What is exploitability?**
> - `reachable` when the handler is registered at top level or in a widely-reachable component and the sink accepts arbitrary data.
> - `conditional` when the handler is inside an auth-gated component or requires a specific application state.
> - `unreachable` when the handler is dead code, test-only, or requires same-origin triggering.
>
> **FP-killers for Category A** — skip (Not Vulnerable) if ALL of the following are true:
> - An origin check is the very first operation in the handler, using strict equality or a hardcoded allowlist.
> - The check returns or throws before any `event.data` field is accessed.
> - The allowlist does not use dynamic values from `localStorage`, `sessionStorage`, or any user-supplied source.
>
> ---
>
> **For Category B candidates (WebSocket endpoints) — answer these questions:**
>
> **Q1: Is the WebSocket connection authenticated via cookies or session tokens in headers?**
>
> If the server resolves user identity exclusively from a token in the first WebSocket message body or a URL query parameter (e.g., `?token=...`), and does NOT use session cookies, then CSWSH does not apply — classify as **Not Vulnerable (token auth)**. Note: if both cookie auth AND token auth are present but cookie auth is active, the cookie path is still exploitable.
>
> **Q2: Is the `Origin` header validated before the WebSocket upgrade completes?**
>
> - Node.js `ws`: is there an `upgrade` event handler on the HTTP server that checks `req.headers.origin` before calling `wss.handleUpgrade`?
> - Express-ws: is `app.ws()` preceded by middleware that inspects the origin?
> - Socket.IO: is the `cors.origin` option set to an explicit array of trusted origins (not `'*'` and not a callback that always returns `true`)?
> - Python `websockets`: does the handler check `websocket.request_headers['Origin']` before calling `accept()`?
> - Django Channels: does `WebsocketConsumer.connect()` read `self.scope['headers']` for origin and call `self.close()` on mismatch?
> - Go `gorilla/websocket`: is `upgrader.CheckOrigin` overridden with a function that returns `false` for untrusted origins (not just `return true` or missing)?
>
> **Q3: What is severity?**
> - `high` by default for cookie-authenticated WebSocket endpoints without origin check — an attacker can hijack the authenticated session.
> - Lower to `medium` if the WebSocket only sends non-sensitive data and the application's threat model accepts the exposure.
>
> **Q4: What is exploitability?**
> - `reachable` when the endpoint is reachable from a browser context, uses cookie auth, and has no origin check.
> - `conditional` when origin checks are present in some code paths but missing in others, or when the endpoint requires specific app state.
> - `unreachable` when the endpoint is internal-only (not accessible from browser contexts) or auth is exclusively non-cookie.
>
> **FP-killers for Category B** — skip (Not Vulnerable) if:
> - The `Origin` header is compared against an explicit allowlist before the upgrade completes, or
> - Authentication is exclusively via a token in the WS frame payload or URL query string (no cookie auth).
>
> ---
>
> **For Category C candidates (`target="_blank"` / `window.open`) — answer these questions:**
>
> **Q1: Is `window.opener` severed?**
>
> Check whether ANY of these protections are present:
> - `rel="noopener"` or `rel="noopener noreferrer"` in the `<a>` element (both `noopener` and `noreferrer` individually sever opener in modern browsers; use both for maximum compat).
> - `'noopener'` in the `windowFeatures` string of `window.open(url, name, features)`.
> - `child.opener = null` immediately after `window.open()` returns.
>
> If any of the above are present, classify as **Not Vulnerable**.
>
> **Q2: Can the linked URL be attacker-controlled?**
>
> - If `href` or the `window.open` URL is a hardcoded same-origin path or a trusted absolute URL, severity is `low` — tabnabbing still requires the target page to be compromised.
> - If `href` comes from a user-supplied or externally-sourced variable (user-submitted links, database-stored URLs, URL query parameters), severity is `medium` — the attacker controls the opened page.
> - If the opened page is explicitly attacker-controlled (e.g., an "open in new tab" feature for user-submitted content), severity is `medium` to `high` depending on the sensitivity of the parent page.
>
> **Q3: What is the parent page sensitivity?**
> - If the parent page handles auth, payment, sensitive forms, or admin operations: raise severity to `medium` even for static external links.
> - If the parent page is a public-facing marketing page with no sensitive user data: severity remains `low`.
>
> **Q4: What is exploitability?**
> - `reachable` when the link is widely visible and the URL can be attacker-controlled.
> - `conditional` when the link appears only in specific user flows or requires login.
> - `unreachable` when the target URL is hardcoded and same-origin.
>
> **FP-killers for Category C** — skip (Not Vulnerable) if:
> - `rel="noopener"` is present (modern browsers sever opener for `noreferrer` alone but include `noopener` for completeness).
> - The URL is a hardcoded relative path on the same origin and the page cannot be attacker-influenced.
>
> ---
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> ---
>
> **Classification**:
> - **Vulnerable**: Origin guard absent and `event.data` reaches a dangerous sink (Cat A); cookie-authenticated WS with no origin check (Cat B); `target="_blank"` with no `noopener` (Cat C).
> - **Likely Vulnerable**: Origin guard present but bypassable (suffix check, substring check, guard placed after data access); WS endpoint with partial CORS config.
> - **Not Vulnerable**: Working origin guard in place (Cat A); WS with explicit allowlist or token-only auth (Cat B); `noopener` present (Cat C).
> - **Needs Manual Review**: Verification requires runtime behavior (dynamically constructed allowlists, lazy-loaded handlers, shared worker context) that cannot be determined statically.
>
> **Output format** — write to `sast/postmessage-batch-[N].md`:
>
> ```markdown
> # postMessage / CSWSH / Tabnabbing Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Category**: A (postMessage) | B (WebSocket CSWSH) | C (Tabnabbing)
> - **Endpoint / function / component**: [route, function, or component name]
> - **Issue**: [e.g., "event.data.html rendered into innerHTML; event.origin never checked"]
> - **Attack chain**: [Step-by-step — e.g., "attacker page calls postMessage({html:'<script>...'}) → victim handler reads event.data.html → innerHTML assignment → XSS"]
> - **Severity**: [high | medium | low]
> - **Exploitability**: [reachable | conditional | unreachable | unknown]
> - **Confidence**: [high | medium | low]
> - **Impact**: [what an attacker achieves — session hijack, account takeover, phishing, data exfiltration, etc.]
> - **Remediation**: [specific fix for this exact finding]
> - **chain_id**: [postmessage-xss | cswsh-csrf | tabnabbing | null]
> - **Proof-of-Concept**:
>   ```
>   [Minimal HTML/JS or curl that demonstrates the issue.
>    For postMessage: attacker page snippet calling postMessage.
>    For CSWSH: malicious page snippet opening the WS with victim's cookies.
>    For tabnabbing: attacker page using window.opener.location.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Category**: A | B | C
> - **Endpoint / function / component**: [route, function, or component name]
> - **Issue**: [what protection is present but insufficient]
> - **Bypass**: [how the weak guard can be bypassed]
> - **Severity**: [high | medium | low]
> - **Exploitability**: [reachable | conditional | unreachable | unknown]
> - **Confidence**: [high | medium | low]
> - **Remediation**: [specific fix]
> - **chain_id**: [postmessage-xss | cswsh-csrf | tabnabbing | null]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Category**: A | B | C
> - **Endpoint / function / component**: [route, function, or component name]
> - **Reason**: [e.g., "origin guard `if (event.origin !== 'https://app.example.com') return;` precedes all data access"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Category**: A | B | C
> - **Endpoint / function / component**: [route, function, or component name]
> - **Uncertainty**: [why static analysis is insufficient]
> - **Suggestion**: [what to inspect at runtime or in additional config]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/postmessage-batch-*.md` file and:

1. Merge all findings into `sast/postmessage-results.md` (human-readable).
2. Emit `sast/postmessage-results.json` (machine-readable canonical schema).
3. Delete all intermediate files.

You (the orchestrator) do this directly — no additional subagent needed.

**Merge procedure**:

1. Read all `sast/postmessage-batch-1.md`, `sast/postmessage-batch-2.md`, ... files.
2. Collect all findings from each batch. Combine into one list, preserving every detail field.
3. Compute totals: count total candidates analyzed (from recon), and count per classification.
4. Write `sast/postmessage-results.md`:

```markdown
# postMessage / CSWSH / Tabnabbing Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total from recon]
  - Category A (postMessage handlers): [N]
  - Category B (WebSocket CSWSH): [N]
  - Category C (Tabnabbing): [N]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write `sast/postmessage-results.json` using the canonical schema:

```json
{
  "findings": [
    {
      "id": "postmessage-1",
      "skill": "sast-postmessage",
      "severity": "high",
      "title": "postMessage handler reads event.data without origin check",
      "description": "The message event listener at src/chat.js:42 processes event.data.html through innerHTML without verifying event.origin. Any cross-origin page can send a postMessage payload and achieve DOM-based XSS in the victim's browser.",
      "location": { "file": "src/chat.js", "line": 42, "column": 3 },
      "remediation": "Add `if (event.origin !== 'https://app.example.com') return;` as the very first statement in the handler, before any event.data access.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "postmessage-xss"
    }
  ]
}
```

Rules for the JSON output:
- `id`: `postmessage-<N>` where N is a sequential integer starting at 1, ordered by severity descending.
- `skill`: always `"sast-postmessage"`.
- `severity`: `"critical"` / `"high"` / `"medium"` / `"low"` / `"info"`. Use `"high"` for postMessage-to-XSS and CSWSH; `"medium"` for bypassable guards and user-URL tabnabbing; `"low"` for static-URL tabnabbing with no sensitive parent page.
- `title`: one line, 80 chars or fewer.
- `description`: 2–4 sentences covering the exact sink, the missing control, and the attacker's capability.
- `location.file`: repo-relative path (no leading `./`).
- `location.line`: the line number of the handler registration, upgrade call, or anchor element.
- `location.column`: column of the vulnerable token; use `1` if unknown.
- `remediation`: actionable, specific to this finding (not generic advice).
- `exploitability`: `"reachable"` | `"conditional"` | `"unreachable"` | `"unknown"`.
- `confidence`: `"high"` | `"medium"` | `"low"`.
- `chain_id`: one of the values from the table below, or `null` if no chain applies.

If there are no findings across all batches, write `{ "findings": [] }`.

6. After writing both output files, **delete all intermediate files**:
   - `sast/postmessage-recon.md`
   - All `sast/postmessage-batch-*.md`

---

## chain_id Reference

| chain_id | Attack chain description |
|---|---|
| `postmessage-xss` | postMessage handler receives `event.data` and renders it to a DOM sink (innerHTML, eval, dangerouslySetInnerHTML, etc.) without an origin check. Chains with the `sast-xss` skill — the same DOM sink is the XSS finding; the missing origin guard is the amplifier. |
| `cswsh-csrf` | Cross-site WebSocket hijacking where a cookie-authenticated WebSocket endpoint accepts connections from any origin. The session cookie is the shared exploit vehicle with CSRF. Chains with the `sast-csrf` skill. |
| `tabnabbing` | Reverse-tabnabbing via `target="_blank"` without `rel="noopener"`. Standalone chain; severity is influenced by whether the URL is user-controlled and whether the parent page is sensitive. |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file.
- **Category A (postMessage)** — the guard must appear BEFORE the first `event.data` access. A guard after data is read is too late; the data could already be passed to a callback. Be precise about code ordering.
- **Category B (CSWSH)** — the severity depends on the auth mechanism. Token-based auth in the WS frame is NOT exploitable via CSWSH. Cookie or session-based auth IS exploitable.
- **Category C (Tabnabbing)** — `noreferrer` alone implicitly sets `noopener` in modern browsers (Chrome 88+, Firefox 79+), but for defense in depth and backward compatibility always flag the absence of explicit `noopener`. Do not flag links that are same-origin AND non-user-controllable as high.
- A postMessage allowlist check against a runtime-dynamic value (e.g., `if (event.origin === config.trustedOrigin)` where `config.trustedOrigin` is loaded from `localStorage`) is a **weak guard** and should be flagged as Likely Vulnerable — an attacker who can write to `localStorage` can inject a trusted origin.
- For `gorilla/websocket`, the default `CheckOrigin` compares the request host against the `Origin` header's host. This is same-host but NOT the same as a full origin allowlist. If the application is deployed at a specific origin, this default may be sufficient; if the deployment is multi-tenant or the host header can be spoofed, flag it.
- Socket.IO with `cors: { origin: '*', credentials: true }` is always a CSWSH candidate — flag it as Vulnerable regardless of other auth controls, because the wildcard overrides same-origin protections.
- When in doubt about a guard's sufficiency, classify as "Likely Vulnerable" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- For the JSON `location.line`, report the line of the handler/anchor/open call itself (the candidate line from recon), not the line of the sink inside the handler.
- Always write `sast/postmessage-results.json` even when there are zero findings — the aggregator uses its presence to confirm the scan ran.
- Clean up ALL intermediate files after writing the final results: `sast/postmessage-recon.md` and all `sast/postmessage-batch-*.md`.
