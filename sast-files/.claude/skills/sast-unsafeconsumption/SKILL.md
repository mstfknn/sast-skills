---
name: sast-unsafeconsumption
description: >-
  Detect unsafe consumption of third-party API responses where data returned from
  an external HTTP call flows directly into a dangerous sink (SQL query, HTML render,
  shell command, file path, redirect URL) without schema validation or sanitization.
  Maps to OWASP API10:2023 and CWE-20. Uses a three-phase approach: recon (find
  unvalidated third-party response fields flowing to sinks), batched verify (parallel
  taint analysis per candidate, 3 at a time), and merge (consolidate into
  sast/unsafeconsumption-results.md + sast/unsafeconsumption-results.json). Requires
  sast/architecture.md (run sast-analysis first). Use when asked to find unsafe API
  consumption, supply-chain injection, or upstream data injection bugs.
version: 0.1.0
---

# Unsafe Consumption of Third-Party API Responses

You are performing a focused security assessment to find **unsafe consumption** vulnerabilities — situations where data returned from an external or upstream HTTP API flows directly into a dangerous sink without being validated against an explicit schema. This skill uses a three-phase approach with subagents: **recon** (find sink sites that receive third-party response data without intervening validation), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into final output files).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Unsafe Consumption of Third-Party APIs

When an application receives a response from an external service (a payment gateway, geolocation API, identity provider, weather feed, or any upstream microservice outside the trust boundary) it is receiving **untrusted data** — exactly as untrusted as user input. If that data flows into a SQL query, a shell command, an HTML template, a file path, or a redirect URL without first being validated against an explicit schema, the application inherits every injection risk that already applies to user-supplied input, with the added supply-chain dimension that the upstream service itself may be compromised.

The core pattern: *a field extracted from a third-party HTTP response reaches a dangerous sink without a Pydantic / Zod / JSON Schema validation step between the API call and the sink.*

### What Unsafe Consumption IS

- Extracting a field from `response.json()` / `res.json()` / `response.getBody()` and interpolating it directly into a SQL string.
- Passing a redirect URL taken from an upstream JSON field directly to `res.redirect()` or `header('Location: ')` without an allowlist check.
- Passing a field from an external API response to `subprocess.run()`, `exec()`, `Runtime.exec()`, or `shell_exec()`.
- Rendering a field from an upstream API response into an HTML template without output encoding.
- Using a filename or path segment returned by an upstream API to open or write files without path validation.
- Storing an upstream field unvalidated and then later using it in a SQL query (second-order variant).

### What Unsafe Consumption is NOT

Do not flag:

- **Validated responses**: Data that passes through `UserSchema.parse(...)` (Zod), `MyModel.model_validate(data)` (Pydantic v2), `jsonschema.validate(data, schema)`, or any equivalent strict schema validation *before* individual fields are accessed. The validation call must appear *between* the HTTP response and the sink use of the field.
- **Typed field extraction with a safe sink API**: `parseInt(data.userId)` used as a positional parameter in a parameterized query — the integer cast eliminates the injection surface for that specific sink.
- **Trusted internal services sharing the same trust boundary**: An internal microservice behind a private VPC that your team controls and deploys, provided the architecture notes classify it as internal. Flag when architecture.md is ambiguous.
- **Responses used only in logging or metrics** with no injection-capable sink.
- **Hardcoded or config-driven URLs** passed to `fetch()` / `requests.get()` — the *request URL* is not the issue; the *response data* is.

### Third-Party vs. Internal Trust Boundary

Use `sast/architecture.md` to determine trust boundaries. Any service your application calls via HTTP that is:

- operated by a third party (payment processor, geocoder, identity provider, SaaS API),
- an upstream partner or vendor API,
- a microservice in a separate deployment unit that your team does not control end-to-end,

…is **untrusted** for the purposes of this skill. If the architecture doc is silent on a called service, treat it as third-party and flag conservatively.

### Patterns That Prevent Unsafe Consumption

**1. Pydantic schema validation (Python)**
```python
# SAFE: model_validate enforces schema before field access
import httpx
from pydantic import BaseModel

class PaymentResponse(BaseModel):
    transaction_id: str
    amount: float
    redirect_url: str

resp = httpx.get("https://payment.example.com/status/123")
resp.raise_for_status()
parsed = PaymentResponse.model_validate(resp.json())
# parsed.transaction_id is now a validated str
cursor.execute("INSERT INTO payments (txn_id, amount) VALUES (%s, %s)",
               (parsed.transaction_id, parsed.amount))
```

**2. Zod schema validation (TypeScript / Node.js)**
```typescript
// SAFE: parse enforces schema before field access
import { z } from "zod";
import axios from "axios";

const GeoSchema = z.object({
  city: z.string().max(100),
  countryCode: z.string().length(2),
});

const resp = await axios.get("https://geo.example.com/ip/" + ip);
const geo = GeoSchema.parse(resp.data);          // throws ZodError on bad data
await db.query("INSERT INTO sessions (city, country) VALUES ($1, $2)",
               [geo.city, geo.countryCode]);
```

**3. JSON Schema validation (language-agnostic)**
```javascript
// SAFE: ajv validates before field extraction
import Ajv from "ajv";
const ajv = new Ajv({ strict: true });
const schema = { type: "object", properties: { userId: { type: "integer" } }, required: ["userId"] };
const validate = ajv.compile(schema);
const body = await fetch(thirdPartyUrl).then(r => r.json());
if (!validate(body)) throw new Error("Invalid upstream response");
await db.query("SELECT * FROM users WHERE id = $1", [body.userId]);
```

**4. Integer cast for numeric-only SQL parameters**
```python
# CONDITIONALLY SAFE for numeric sink only — not a substitute for full schema validation
user_id = int(resp.json()["userId"])             # raises ValueError on non-integer
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

**5. Redirect allowlist**
```typescript
// SAFE: allowlist gates the redirect URL field
const ALLOWED_REDIRECTS = ["https://app.example.com/success", "https://app.example.com/cancel"];
const data = PaymentSchema.parse(await resp.json());
if (!ALLOWED_REDIRECTS.includes(data.redirectUrl)) throw new Error("Illegal redirect");
res.redirect(data.redirectUrl);
```

---

## Vulnerable vs. Secure Examples

### Python / httpx or requests

```python
# VULNERABLE: raw dict field from external API flows into concatenated SQL
import httpx

resp = httpx.get("https://partner.example.com/order/99")
data = resp.json()
# No validation. data["product_id"] is untrusted.
cursor.execute("SELECT * FROM products WHERE id = " + data["product_id"])
#                                                      ^^^^^^^^^^^^^^^^^ UNSAFE

# VULNERABLE: redirect from upstream without allowlist
resp2 = httpx.post("https://payment.example.com/checkout", json=cart)
redirect_url = resp2.json()["next"]           # untrusted
return redirect(redirect_url)                 # open redirect / SSRF

# VULNERABLE: upstream field into shell command
metadata = httpx.get("https://files.example.com/meta/123").json()
subprocess.run(["convert", metadata["filename"], "out.png"])
#                                  ^^^^^^^^^^^^ path traversal / command injection

# SECURE: Pydantic validation before any field use
from pydantic import BaseModel

class OrderResponse(BaseModel):
    product_id: int          # strict int — non-integer raises ValidationError
    name: str

parsed = OrderResponse.model_validate(
    httpx.get("https://partner.example.com/order/99").json()
)
cursor.execute("SELECT * FROM products WHERE id = %s", (parsed.product_id,))
```

### Node.js / axios or fetch

```javascript
// VULNERABLE: response.data field directly into template literal query
const { data } = await axios.get(`https://inventory.example.com/item/${sku}`);
const [rows] = await pool.query(`SELECT * FROM items WHERE name = '${data.name}'`);
//                                                                   ^^^^^^^^^ UNSAFE

// VULNERABLE: res.json() field into res.redirect without validation
app.get("/oauth/callback", async (req, res) => {
  const tokenResp = await fetch("https://auth.example.com/token", { method: "POST", body: "..." });
  const body = await tokenResp.json();
  res.redirect(body.next);              // open redirect — body.next is attacker-influenced
});

// SECURE: Zod parse before use
import { z } from "zod";

const ItemSchema = z.object({ name: z.string().max(200) });
const { data } = await axios.get(`https://inventory.example.com/item/${sku}`);
const item = ItemSchema.parse(data);
const [rows] = await pool.query("SELECT * FROM items WHERE name = $1", [item.name]);
```

### Java / RestTemplate or WebClient

```java
// VULNERABLE: getBody() field concatenated into JDBC query
ResponseEntity<Map> resp = restTemplate.getForEntity(thirdPartyUrl, Map.class);
String userId = (String) resp.getBody().get("userId");
// No type assertion or schema check
String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
jdbcTemplate.queryForObject(sql, userRowMapper);       // SQL injection via upstream

// VULNERABLE: getBody() field into Runtime.exec
String filename = (String) resp.getBody().get("file");
Runtime.getRuntime().exec(new String[]{"convert", filename, "out.png"});

// SECURE: typed POJO deserialization + parameterized query
// ObjectMapper.readValue into a typed class performs implicit type validation
UserApiResponse parsed = objectMapper.readValue(resp.getBody(), UserApiResponse.class);
jdbcTemplate.queryForObject(
    "SELECT * FROM users WHERE id = ?", userRowMapper, parsed.getUserId());
```

### PHP / Guzzle

```php
// VULNERABLE: json() field into PDO query without prepare
$resp = $client->get('https://partner.example.com/price?sku=' . $sku);
$data = $resp->json();
$result = $pdo->query("SELECT * FROM prices WHERE sku = '" . $data['sku'] . "'");

// VULNERABLE: json() field into header redirect
header('Location: ' . $data['returnUrl']);   // open redirect

// VULNERABLE: json() field into shell
shell_exec('process_file ' . $data['filename']);

// SECURE: explicit cast + prepared statement
$sku = (string) filter_var($data['sku'], FILTER_SANITIZE_SPECIAL_CHARS);
$stmt = $pdo->prepare("SELECT * FROM prices WHERE sku = :sku");
$stmt->execute(['sku' => $sku]);
// Better: full JSON Schema or manual type check before any field use
```

### Ruby / Faraday

```ruby
# VULNERABLE: response body field into find_by_sql
response = conn.get('/user/profile')
body = JSON.parse(response.body)
@users = User.find_by_sql("SELECT * FROM users WHERE email = '#{body['email']}'")

# VULNERABLE: redirect_to with upstream URL
redirect_to body['next_page']      # open redirect / SSRF

# SECURE: explicit cast + parameterized ActiveRecord
email = body['email'].to_s.strip
@user = User.find_by(email: email)   # safe ORM; not raw SQL
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Unvalidated Third-Party Response Fields Flowing to Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a field extracted from an external HTTP API response flows into a dangerous sink (SQL query, shell command, HTML render, file path, redirect) without an intervening schema validation step. Write results to `sast/unsafeconsumption-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to identify which HTTP client libraries are in use, which external services are called, and what the trust boundaries are.
>
> **Step 1 — Identify third-party HTTP call sites**:
>
> Search for outbound HTTP calls using common client libraries. These are the *sources* of untrusted data:
>
> | Language / Library | Patterns to find |
> |---|---|
> | Python / requests | `requests.get(`, `requests.post(`, `requests.request(`, `session.get(`, `session.post(` |
> | Python / httpx | `httpx.get(`, `httpx.post(`, `httpx.request(`, `client.get(`, `client.post(`, `await client.get(` |
> | Python / aiohttp | `session.get(`, `session.post(`, `aiohttp.ClientSession` |
> | Node.js / axios | `axios.get(`, `axios.post(`, `axios.request(`, `axios(` |
> | Node.js / node-fetch / fetch | `fetch(`, `node-fetch`, `.then(r => r.json())`, `await res.json()` |
> | Node.js / got | `got.get(`, `got.post(`, `got(` |
> | Node.js / ky | `ky.get(`, `ky.post(` |
> | Java / RestTemplate | `restTemplate.getForEntity(`, `restTemplate.postForObject(`, `restTemplate.exchange(` |
> | Java / WebClient | `webClient.get()`, `webClient.post()`, `.retrieve()`, `.bodyToMono(` |
> | Java / HttpClient | `HttpClient.newHttpClient()`, `.send(`, `.sendAsync(` |
> | PHP / Guzzle | `$client->get(`, `$client->post(`, `$client->request(` |
> | PHP / cURL | `curl_exec(`, `file_get_contents(` with HTTP URL |
> | Ruby / Faraday | `conn.get(`, `conn.post(`, `Faraday.new` |
> | Ruby / Net::HTTP | `Net::HTTP.get(`, `Net::HTTP.start(` |
> | C# / HttpClient | `httpClient.GetAsync(`, `httpClient.PostAsync(`, `.GetStringAsync(` |
> | Go / http | `http.Get(`, `http.Post(`, `client.Do(` |
>
> **Step 2 — Trace response data extraction**:
>
> For each HTTP call site found, look for how the response body is extracted and how its fields are accessed:
>
> - Python: `.json()`, `.json()['field']`, `.json().get('field')`, `json.loads(resp.text)['field']`
> - Node.js / TS: `await res.json()`, `response.data.field`, `(await fetch(...).then(r => r.json())).field`, destructuring from `data`
> - Java: `.getBody()`, `.getBody().get("field")`, `objectMapper.readValue(resp.getBody(), Map.class).get("field")`
> - PHP: `$response->json()['field']`, `json_decode($body, true)['field']`
> - Ruby: `JSON.parse(response.body)['field']`
> - C#: `JsonSerializer.Deserialize<Dictionary<string,object>>(content)["field"]`
> - Go: `json.Unmarshal(body, &result); result.Field`
>
> **Step 3 — Check for schema validation between response and sink**:
>
> Before flagging a candidate, search for a validation call **between** the response extraction and the sink use:
>
> - Python: `model_validate(`, `.model_validate(`, `Model(**data)`, `jsonschema.validate(`, `validate(data, schema)`
> - Node.js / TS: `Schema.parse(`, `Schema.safeParse(`, `ajv.compile(`, `validate(`, `Joi.object(`, `.validate(`
> - Java: `@Valid`, `validator.validate(`, `ObjectMapper.readValue(body, TypedClass.class)` with typed POJO (not raw Map)
> - PHP: `filter_var(`, explicit cast `(int)`, `(float)`, custom validator call
> - Ruby: explicit `.to_i`, `.to_f`, Dry-Validation, contract call
>
> If a validation call is found **between** the HTTP response extraction and the sink, skip that candidate. If the validation is present but only after the field is already used in the sink, still flag it.
>
> **Step 4 — Identify dangerous sinks receiving unvalidated fields**:
>
> Sinks to look for:
>
> 1. **SQL queries**: string concatenation or interpolation with a response field:
>    - Python: `cursor.execute(f"...{field}..."`, `cursor.execute("..." + field`, `db.session.execute(text(f"...{field}..."))`, `Model.objects.raw(f"...{field}...")`
>    - Node.js: `` db.query(`...${field}...`) ``, `db.query("..." + field`, `pool.query(template_with_var)`
>    - Java: `jdbcTemplate.query("..." + field`, `jdbcTemplate.queryForObject(sql_with_concat`
>    - PHP: `$pdo->query("..." . $field`, `$pdo->exec("..." . $field`
>    - Ruby: `find_by_sql("...#{field}..."`, `where("...#{field}...")`
>
> 2. **Shell commands**: response field passed to process execution:
>    - Python: `subprocess.run([..., field`, `subprocess.call([..., field`, `os.system(... + field`, `os.popen(f"...{field}...")`
>    - Node.js: `exec(field`, `spawn(..., [field`, `` execSync(`...${field}...`) ``
>    - Java: `Runtime.getRuntime().exec(new String[]{..., field`
>    - PHP: `shell_exec($field`, `exec($field`, `system($field`, `passthru($field`
>    - Ruby: `system(field`, `` `#{field}` ``, `IO.popen(field`
>
> 3. **Redirect URLs**: response field used as redirect target:
>    - Python: `redirect(field`, `return redirect(resp.json()['url']`
>    - Node.js: `res.redirect(field`, `response.redirect(field`
>    - Java: `response.sendRedirect(field`
>    - PHP: `header('Location: ' . $field`
>    - Ruby: `redirect_to field`
>
> 4. **HTML rendering without encoding**: response field embedded in HTML output:
>    - Python: `render(request, template, {key: field})` followed by `{{ field | safe }}` in template, or `return HttpResponse("<b>" + field + "</b>")`
>    - Node.js: `` res.send(`<div>${field}</div>`) ``, `res.write("<b>" + field`
>    - PHP: `echo $field`, `print $field` without `htmlspecialchars`
>
> 5. **File paths**: response field used in file open/write/delete:
>    - Python: `open(field`, `os.path.join(base, field)` then `open(`, `shutil.copy(field`
>    - Node.js: `fs.readFile(field`, `fs.writeFile(field`, `path.join(__dirname, field)`
>    - PHP: `file_get_contents($field`, `fopen($field`, `include($field`
>    - Ruby: `File.open(field`, `File.read(field`
>
> **Output format** — write to `sast/unsafeconsumption-recon.md`:
>
> ```markdown
> # Unsafe Consumption Recon: [Project Name]
>
> ## Summary
> Found [N] candidate sites where a third-party API response field reaches a dangerous sink without schema validation.
>
> ## External HTTP Call Sites
>
> [List the HTTP call sites identified, grouped by domain/service if recognizable. Brief — one line each.]
>
> ## Candidate Sink Sites
>
> ### 1. [Descriptive name — e.g., "Payment API userId field into raw SQL query"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **External call site**: [the fetch/get/post call, file and line]
> - **Response field extracted**: `data['field']` / `response.data.field` / etc.
> - **Sink type**: [sql | shell | redirect | html-render | file-path]
> - **Sink call**: [the dangerous sink call]
> - **Validation found**: none | [name of validation call if partial]
> - **Code snippet**:
>   ```
>   [the response extraction + (optional) any intermediate assignments + the sink call]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/unsafeconsumption-recon.md`. If the recon found **zero candidate sink sites** (the summary reports "Found 0" or the "Candidate Sink Sites" section is empty or absent), **skip Phase 2 entirely**. Instead:

1. Write the following to `sast/unsafeconsumption-results.md`:

```markdown
# Unsafe Consumption Analysis Results

No vulnerabilities found.
```

2. Write the following to `sast/unsafeconsumption-results.json`:

```json
{ "findings": [] }
```

3. Delete `sast/unsafeconsumption-recon.md` and stop.

Only proceed to Phase 2 if Phase 1 found at least one candidate sink site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/unsafeconsumption-recon.md` and split the candidate sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces the taint flow only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/unsafeconsumption-recon.md` and count the numbered site sections under "Candidate Sink Sites" (### 1., ### 2., etc.).
2. Divide into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/unsafeconsumption-batch-N.md` where N is the 1-based batch number.
6. From `sast/architecture.md`, identify the project's primary language/framework and select the matching language examples from the "Vulnerable vs. Secure Examples" section above. Include those in each subagent prompt where indicated by `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate site, confirm whether a field from a third-party API response reaches a dangerous sink without effective schema validation or type-safe interception. Write results to `sast/unsafeconsumption-batch-[N].md`.
>
> **Your assigned candidate sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand trust boundaries, which services are external, and what validation libraries are in use.
>
> **Verify question**: Does a field extracted from an external API response reach the identified sink without a validating step that would reject or constrain malicious values?
>
> **Taint analysis — trace the field forward from response to sink**:
>
> 1. **Direct extraction to sink** — the field is extracted from the response object and used immediately in the sink with no intermediate step:
>    ```
>    data = resp.json()
>    cursor.execute("SELECT * WHERE id = " + data["userId"])   # direct, no gap for validation
>    ```
>    Classify: **Vulnerable**.
>
> 2. **Extraction to intermediate variable to sink** — the field is assigned to a variable, possibly through helper functions, then reaches the sink:
>    ```
>    raw = resp.json()
>    user_id = raw.get("userId")         # still untrusted
>    q = build_query(user_id)            # trace into build_query — does it validate?
>    cursor.execute(q)
>    ```
>    Trace `user_id` through all intermediate assignments and function calls. If the chain reaches the sink without a validation call, classify: **Vulnerable**.
>
> 3. **Extraction to type cast to sink** (numeric):
>    ```
>    user_id = int(resp.json()["userId"])
>    cursor.execute("SELECT * WHERE id = %s", (user_id,))      # parameterized — safe
>    cursor.execute("SELECT * WHERE id = " + str(user_id))     # cast then concat — still injectable
>    ```
>    `int()`/`parseInt()` to a parameterized query: **Not Vulnerable** for SQL injection only. `int()` then string concatenation into SQL: **Vulnerable**. String fields cast with `.strip()` or `.lower()` only: still untrusted, **Vulnerable**.
>
> 4. **Extraction to schema validation to sink**:
>    ```
>    parsed = MyModel.model_validate(resp.json())    # Pydantic
>    parsed = Schema.parse(await res.json())         # Zod
>    ```
>    If the validation call appears **before** the field is accessed for the sink, the risk is eliminated for the types validated. Classify: **Not Vulnerable**. If the validation is present but only validates *other* fields, or the same field is also accessed via the raw response dict elsewhere, flag those access paths.
>
> 5. **Second-order path** — the response field is stored (DB, cache, file) and later retrieved and used in a sink:
>    - Trace from the storage write to the read and then to the sink.
>    - The storage/retrieval step does not sanitize — classify as **Vulnerable** if the retrieved value reaches a sink unvalidated.
>
> **False-positive killers** — reasons to classify as Not Vulnerable:
>
> - A strict schema validation call (`model_validate`, `parse`, `validate`, JSON Schema) is present between the HTTP response and the field access at the sink.
> - The field is used only in a parameterized query placeholder (not concatenated into the query string).
> - The field is used only as a logging argument with no injection capability.
> - The external URL is internal infrastructure documented in `sast/architecture.md` as within the trust boundary (e.g., same-org microservices with shared secret, service mesh mTLS, same deployment unit).
> - The response field is used only as a numeric constant that has been strictly cast and is passed to a fully parameterized API.
>
> **Severity and exploitability guidance**:
>
> | Sink type | Default severity | Exploitability | Notes |
> |---|---|---|---|
> | Shell command / RCE | critical | reachable | Direct code execution if upstream compromised |
> | File path (write / include) | critical | reachable | Arbitrary file write; PHP include = RCE |
> | SQL query (concat / interpolation) | high | reachable | SQL injection via supply-chain compromise |
> | HTML render (XSS) | high | reachable | Stored or reflected XSS via upstream |
> | Redirect URL (open redirect / SSRF) | high | reachable | Phishing or SSRF via upstream redirect |
> | File path (read) | medium | conditional | Information disclosure if upstream compromised |
> | Redirect URL (partial) | medium | conditional | Partial control; allowlist partially present |
>
> Set `exploitability: reachable` when the third-party service could be compromised or misconfigured (supply-chain threat model). Set `exploitability: conditional` when the attack requires the third-party service to be specifically targeted. Set `exploitability: unknown` when the trust boundary is ambiguous.
>
> Set `confidence: high` for a direct `response.field → sink` with no validation and no parameterization gap. Set `confidence: medium` when an intermediate assignment, helper function, or indirect flow obscures the taint path but the evidence still points to a real vulnerability. Set `confidence: low` for speculative flows or when the external service classification is uncertain.
>
> **chain_id values**:
>
> - `"upstream-sqli"` — unvalidated upstream field flows into a SQL query sink (chains with sast-sqli)
> - `"upstream-ssrf"` — unvalidated upstream redirect URL or URL field enables SSRF (chains with sast-ssrf)
> - `"upstream-rce"` — unvalidated upstream field flows into a shell command or file include (chains with sast-rce)
> - `"upstream-xss"` — unvalidated upstream field rendered into HTML without encoding (chains with sast-xss)
> - `"upstream-path-traversal"` — unvalidated upstream field used as a file path (chains with sast-pathtraversal)
> - `null` for standalone findings that do not compose with another skill's finding
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Unvalidated third-party field demonstrably reaches a dangerous sink.
> - **Likely Vulnerable**: Indirect taint flow where a step is opaque, or partial mitigation (custom escaping, non-strict cast) only.
> - **Not Vulnerable**: Effective schema validation before field access, OR field only used in a parameterized safe API, OR service is internal trust boundary.
> - **Needs Manual Review**: Trust boundary unclear, or validation library usage is present but scope cannot be confirmed without runtime information.
>
> **JSON finding object** — for each Vulnerable or Likely Vulnerable finding, produce a JSON object following the canonical schema (to be collected in Phase 3):
>
> ```json
> {
>   "id": "unsafeconsumption-<N>",
>   "skill": "sast-unsafeconsumption",
>   "severity": "critical|high|medium|low|info",
>   "title": "short one-line description",
>   "description": "full explanation including taint path and exploitability",
>   "location": { "file": "relative/path.ext", "line": 123, "column": 10 },
>   "remediation": "how to fix",
>   "exploitability": "reachable|conditional|unreachable|unknown",
>   "confidence": "high|medium|low",
>   "chain_id": "upstream-sqli|upstream-ssrf|upstream-rce|upstream-xss|upstream-path-traversal|null"
> }
> ```
>
> **Output format** — write to `sast/unsafeconsumption-batch-[N].md`:
>
> ```markdown
> # Unsafe Consumption Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **External API**: [domain / service name if identifiable]
> - **Response field**: [`data["field"]` / `resp.data.fieldName` / etc.]
> - **Sink type**: [sql | shell | redirect | html-render | file-path]
> - **Issue**: [e.g., "Upstream payment API `userId` field interpolated into raw SQL query"]
> - **Taint trace**: [Step-by-step: HTTP call → field extraction → (intermediate assignments) → sink call]
> - **Supply-chain impact**: [What an attacker who controls or compromises the upstream service could do]
> - **Remediation**: [Specific fix: add Pydantic/Zod validation, switch to parameterized query, add redirect allowlist, etc.]
> - **Severity**: [critical|high|medium]
> - **Exploitability**: reachable|conditional|unknown
> - **Confidence**: high|medium|low
> - **chain_id**: [upstream-sqli | upstream-ssrf | upstream-rce | upstream-xss | upstream-path-traversal | null]
> - **JSON finding**:
>   ```json
>   { "id": "unsafeconsumption-N", ... }
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **External API**: [domain / service name if identifiable]
> - **Response field**: [`data["field"]` / etc.]
> - **Sink type**: [sql | shell | redirect | html-render | file-path]
> - **Issue**: [e.g., "Indirect taint through helper function; validation not confirmed"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps with (?)]
> - **Concern**: [Why partial mitigation is insufficient or why the flow is suspicious]
> - **Remediation**: [Specific fix]
> - **Severity**: [high|medium]
> - **Exploitability**: conditional|unknown
> - **Confidence**: medium|low
> - **chain_id**: [appropriate value or null]
> - **JSON finding**:
>   ```json
>   { "id": "unsafeconsumption-N", ... }
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Pydantic model_validate enforces strict schema before field access" or "Parameterized query with integer cast"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [e.g., "Called service not documented in architecture.md — trust boundary unclear"]
> - **Suggestion**: [What to verify manually or at runtime]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/unsafeconsumption-batch-*.md` file and merge them into final output files. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/unsafeconsumption-batch-1.md`, `sast/unsafeconsumption-batch-2.md`, ... files.
2. Collect every finding from each batch, preserving classification and all detail fields.
3. Assign a global sequential `id` to each finding in the JSON output: `unsafeconsumption-1`, `unsafeconsumption-2`, etc., ordered VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
4. Write the merged human-readable report to `sast/unsafeconsumption-results.md`:

```markdown
# Unsafe Consumption Analysis Results: [Project Name]

## Executive Summary
- Candidate sites analyzed: [total from recon]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Key Risk

Third-party API responses are **untrusted input**. A compromised or misconfigured upstream service
can deliver payloads that propagate into SQL queries, shell commands, redirect URLs, or rendered HTML.
Validate every external response against an explicit schema before accessing individual fields.

## Findings

[All findings from all batches, ordered: VULNERABLE → LIKELY VULNERABLE → NEEDS MANUAL REVIEW → NOT VULNERABLE.
 Preserve every detail field from the batch results exactly as written.]
```

5. Write the canonical machine-readable output to `sast/unsafeconsumption-results.json`:

```json
{
  "findings": [
    {
      "id": "unsafeconsumption-1",
      "skill": "sast-unsafeconsumption",
      "severity": "...",
      "title": "...",
      "description": "...",
      "location": { "file": "relative/path.ext", "line": 0, "column": 0 },
      "remediation": "...",
      "exploitability": "reachable|conditional|unreachable|unknown",
      "confidence": "high|medium|low",
      "chain_id": "upstream-sqli|upstream-ssrf|upstream-rce|upstream-xss|upstream-path-traversal|null"
    }
  ]
}
```

Include only Vulnerable and Likely Vulnerable findings in the JSON `findings` array. If there are none, write `{ "findings": [] }`.

6. After writing both result files, **delete all intermediate files**: `sast/unsafeconsumption-recon.md` and all `sast/unsafeconsumption-batch-*.md` files.

---

## Chain IDs and Cross-Skill Correlation

This skill chains with the following detection skills. When a finding here shares a root cause with a finding from a sibling skill, use the same `chain_id` in both, so the triage and report phases can correlate them:

| chain_id | Sibling skill | Scenario |
|---|---|---|
| `upstream-sqli` | sast-sqli | The taint source is a third-party API response field instead of direct user input, but the SQL injection sink and fix are identical |
| `upstream-ssrf` | sast-ssrf | A redirect URL or outbound URL taken from a third-party response enables SSRF against internal services |
| `upstream-rce` | sast-rce | A shell command, `eval`, or `exec` receives a field from a third-party API response |
| `upstream-xss` | sast-xss | An HTML render or JavaScript context receives an unencoded field from a third-party API response |
| `upstream-path-traversal` | sast-pathtraversal | A file path is derived from a third-party API response field, enabling directory traversal |

When no sibling finding exists for a given unsafe-consumption finding, set `chain_id: null`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidate sites per subagent**. 1-3 sites → 1 subagent. 10 sites → 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text, not the entire recon file.
- **Phase 1 is structural**: find HTTP call sites and trace to sinks. Do not classify exploitability in Phase 1 — that is Phase 2's job.
- **Phase 2 is taint analysis**: confirm the data path from external API response to dangerous sink, and check for schema validation in between.
- The supply-chain threat model means `exploitability: reachable` is the correct default when the upstream service is a third party — attackers who compromise the upstream service can control the field value. Downgrade to `conditional` only when the architecture shows the called service is partially controlled or heavily monitored.
- A `int(field)` cast eliminates SQL injection only when the result is passed to a **parameterized** query placeholder. A cast followed by string concatenation into SQL is still injectable.
- Schema validation is only effective if it runs **before** the field is accessed for the sink. A validation call after the fact, or a validation that only checks *other* fields, does not mitigate the specific risk.
- Second-order unsafe consumption (store unvalidated upstream data → retrieve later → use in sink) is easy to miss. When a response field is written to the database, check whether the stored value is later read and used in a sink without re-validation.
- Clean up all intermediate files after writing the final result files.
- Always write `sast/unsafeconsumption-results.json` even when there are no findings (`{ "findings": [] }`), so the aggregator knows the scan ran.
