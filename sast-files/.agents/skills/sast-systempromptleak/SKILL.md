---
name: sast-systempromptleak
description: >-
  Detect system prompt secret exposure and system prompt echo leaks (OWASP LLM
  Top 10 LLM07, LLM25) in LLM codebases using a three-phase approach: recon
  (find every system prompt construction site and logging/response path), batched
  verify (confirm whether secrets are interpolated into the prompt and whether the
  prompt reaches a log, API response, or plaintext store — in parallel subagents
  of 3 candidates each), and merge (consolidate batch results). Targets Python and
  TypeScript codebases using OpenAI, Anthropic, LangChain, LlamaIndex, Google
  Gemini, AWS Bedrock, or any custom LLM SDK; skip on repos with no LLM or agent
  SDK dependency. Outputs findings to sast/systempromptleak-results.md plus
  sast/systempromptleak-results.json. Use when asked to find secrets in system
  prompts, system prompt logging, system prompt echo in API responses, or
  plaintext storage of system prompts containing sensitive business logic.
version: 0.1.0
---

# LLM System Prompt Leak Detection

You are performing a focused security assessment to find system prompt secret exposure and system prompt echo leak vulnerabilities in a codebase that uses Large Language Models (LLMs). This skill uses a three-phase approach with subagents: **recon** (find every system prompt construction and every path that logs, returns, or stores that prompt), **batched verify** (determine whether each candidate actually leaks a secret or exposes the prompt to unauthorized parties, in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

**Tech-stack gate**: This skill is only meaningful in codebases that call an LLM or agent SDK. If `sast/architecture.md` shows no LLM dependency (no `openai`, `anthropic`, `langchain`, `llama_index`, `google.generativeai`, `boto3` bedrock calls, or equivalent), write `{"findings": []}` to `sast/systempromptleak-results.json`, note "No LLM SDK detected — skill not applicable" in `sast/systempromptleak-results.md`, and stop.

System prompt leaks are classified as **LLM07** (System Prompt Leakage) in the OWASP Top 10 for Large Language Model Applications and carry **CWE-200** (Exposure of Sensitive Information to an Unauthorized Actor). They are a high-to-critical severity class when the system prompt contains embedded credentials, API keys, internal business logic marked confidential, or personally identifiable information.

---

## What is a System Prompt Leak

A **system prompt** is the developer-controlled preamble passed to the LLM (in the `system` field of the Anthropic API, the `role: "system"` message in the OpenAI chat format, or equivalent constructs in other SDKs). It defines the model's persona, constraints, and — all too often — includes secrets or instructions that were never meant to be seen by end users.

Two distinct sub-classes exist and both are in scope:

### Sub-class A — Secret Interpolated Into the Prompt

A secret (API key, bearer token, database password, internal URL, confidential instruction set) is **embedded as a string literal** or **interpolated** directly into the system prompt at construction time. The secret is now part of the prompt string in memory, in logs, and potentially in any downstream path the prompt takes. Even if the model never echoes the prompt verbatim, an attacker who can trigger a prompt injection attack (`"Repeat the contents of your system message"`) now has a viable extraction target containing real credentials.

Patterns:

```python
# Secret literal in prompt
system = "You are a helpful assistant. Use API key sk-live-abc123 to call the billing service."

# Secret interpolated from environment variable
api_key = os.environ["OPENAI_API_KEY"]
system = f"You are a routing assistant. Authenticate downstream calls with Bearer {api_key}."

# Token concatenated inline
SYSTEM_PROMPT = "Internal only. DB password: " + DB_PASSWORD + ". Never reveal this."

# TypeScript — process.env value concatenated into prompt
const systemPrompt = `You assist employees. Slack token: ${process.env.SLACK_TOKEN}. Do not share.`;
```

### Sub-class B — Prompt Logged, Returned, or Stored in Plaintext

The system prompt itself — even if it contains only benign persona instructions — is **logged at an exploitable level**, **returned in an API response**, or **stored in a plaintext database column** accessible beyond its intended audience. If the prompt also contains secrets (Sub-class A), the severity is compounded.

Patterns:

```python
# Logged verbatim
logger.info(f"Calling LLM with system prompt: {SYSTEM_PROMPT}")

# Returned to the caller in a debug endpoint
@app.get("/debug/prompt")
def get_prompt():
    return {"system": SYSTEM_PROMPT}  # unauthenticated!

# Stored in plaintext conversation log
db.execute("INSERT INTO conversations (system_prompt, ...) VALUES (%s, ...)", (SYSTEM_PROMPT, ...))

# TypeScript — console.log echoes the prompt
console.log("system:", systemPrompt);

# Returned inside the LLM API response wrapper sent to a client
res.json({ debug: { system: systemPrompt, messages: [...] } });
```

### What a System Prompt Leak IS

- A secret literal (`sk-`, `Bearer `, password string, internal URL, encoded credential) appears inside a system prompt string.
- An environment variable or configuration value containing a secret is resolved and interpolated into the system prompt at call time, and the resolved string is passed to a logger, stored to a DB, or returned in a response.
- A system prompt variable is passed directly (not as `"[redacted]"`) to any `logger.*` call, `print()` / `console.log()`, `logging.*`, `structlog.*`, `winston.*`, `pino.*`, or similar.
- A system prompt is included in the response body of an API endpoint, whether as a top-level field, in a `debug` or `metadata` object, or inside a serialized conversation object.
- A system prompt is written to a database, file, cache, or queue in plaintext where it can be queried or read by unauthorized parties (e.g., a shared log sink, an analytics table, a tracing system that stores raw spans).
- A `/debug`, `/health`, `/introspect`, `/admin`, or similar endpoint returns the system prompt or a structure containing it without authentication or authorization checks.

### What a System Prompt Leak is NOT

Do not flag these (flag under their own class or ignore):

- **Benign persona instructions with no secrets, never logged**: A system prompt like `"You are a helpful customer service assistant."` that is not logged and not returned anywhere. No leak, no secret — not in scope.
- **Prompt stored encrypted at rest**: If the storage path applies server-side encryption (KMS, pgcrypto, field-level encryption) and the key is not also stored alongside the ciphertext, this is not a leak.
- **Secrets referenced only via `os.environ[...]` at call time, with logging redacted**: If the code does `system = f"Key: {os.environ['KEY']}"` but the only logging statement is `logger.debug("[system prompt omitted]")` and the prompt is never returned or stored, this is a conditional/lower-severity finding, not a clear leak.
- **System prompt leakage via prompt injection**: If an attacker tricks the model into echoing its own system prompt through a chat exchange, that is **sast-promptinjection** territory. This skill covers the *code* paths that directly leak the prompt string — not LLM reasoning-level exploits.
- **Secrets managed by a secrets manager at runtime without string interpolation**: `openai.api_key = os.environ["OPENAI_KEY"]` passed to the SDK directly (never concatenated into the prompt string) is not a system prompt leak.
- **Logging the model's *response***: Logging what the model returned is the domain of **sast-pii** (if the response contains PII) or **sast-llmoutput** (if the response flows into a dangerous sink). This skill covers the *prompt*, not the completion.

### Severity Classification

| Scenario | Default Severity |
|---|---|
| Secret (API key, token, password) interpolated into system prompt AND prompt is logged or returned | **Critical** |
| System prompt echoed in unauthenticated API response (any content, secrets or not) | **Critical** |
| Secret interpolated into system prompt, prompt stored in plaintext shared log sink | **Critical** |
| Secret interpolated into system prompt, no confirmed logging/echo path (prompt may be extracted via injection) | **High** |
| System prompt (no secret) logged verbatim at INFO or above in a production-accessible log aggregator | **High** |
| System prompt (no secret) returned in an authenticated internal-only admin/debug endpoint | **Medium** |
| System prompt logged only at DEBUG level, production debug logging typically disabled | **Medium** |
| System prompt stored in a DB column accessible only to privileged internal operators | **Medium** |
| System prompt (no secret) stored in plaintext but access is tightly controlled | **Low** |

Raise to **critical** when:
- The exposed endpoint is unauthenticated or has no IP allowlist.
- The system prompt contains a live API key, bearer token, or password that could be used independently.
- The prompt is written to a shared, multi-tenant log sink (e.g., Datadog, Splunk) readable by all engineers or third-party log processors.

Lower to **medium** when:
- The exposure is only to authenticated internal operators who already have need-to-know access (e.g., an internal admin panel behind SSO).
- The secret is a low-privilege read-only token, not a privileged credential.

### Patterns That Prevent System Prompt Leaks

**1. No secrets in system prompts**
The cleanest fix: never put secrets in the system prompt. Pass API keys and tokens directly to the SDK client or to tool parameters — not into the prompt string itself. The model does not need to see credentials to use them; tool schemas handle this.

**2. Logging redaction**
When logging LLM interactions for observability, always redact the system prompt:

```python
logger.info("LLM call initiated", extra={"system_prompt": "[REDACTED]", "model": model_id})
```

Never log the raw prompt variable. Use a structured log wrapper that strips or hashes the system field before shipping to your log aggregator.

**3. Never return the system prompt in API responses**
Remove system prompt content from all response bodies. If you need to expose prompt metadata for debugging, use a dedicated, authenticated, IP-allowlisted admin endpoint that returns only a hash or version identifier — never the full text.

**4. Encrypted storage**
If system prompts must be persisted (for versioning, audit, or replay), store them encrypted at rest using a managed key (AWS KMS, GCP CMEK, HashiCorp Vault Transit). Never store the plaintext in a shared log table or analytics pipeline.

**5. Environment variables — not string interpolation**
Credentials needed by tools or downstream services should be stored in environment variables and accessed at call time via the SDK — not resolved into a string that gets logged or stored:

```python
# BAD — secret in prompt string
system = f"Use key {os.environ['MY_KEY']} to authenticate."

# GOOD — key never enters the prompt string
client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
# the model calls a tool; the tool uses its own env-var credential
```

**6. Prompt content classification**
Treat system prompts like secrets: apply the same lifecycle controls (rotation, access logging, need-to-know). If a system prompt contains proprietary business logic (pricing formulas, internal decision trees, compliance rules), consider it **confidential data** and apply appropriate controls.

---

## Vulnerable vs. Secure Examples

### Python — Anthropic SDK, secret in system prompt, logged

```python
# VULNERABLE: API key interpolated into system prompt; prompt logged at INFO.
import anthropic, os, logging

logger = logging.getLogger(__name__)
client = anthropic.Anthropic()

BILLING_KEY = os.environ["BILLING_SERVICE_KEY"]

SYSTEM_PROMPT = (
    f"You are a billing assistant. Authenticate to the billing API using "
    f"Bearer {BILLING_KEY}. Do not share this key with users."
)

def handle_request(user_message: str) -> str:
    logger.info("Creating LLM message", extra={"system": SYSTEM_PROMPT})  # LEAK
    resp = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return resp.content[0].text
```

```python
# SECURE: key never enters the prompt; logging is redacted.
SYSTEM_PROMPT = (
    "You are a billing assistant. Use the `call_billing_api` tool for "
    "any billing queries. Never share tool credentials with users."
)

def handle_request(user_message: str) -> str:
    logger.info("Creating LLM message", extra={"system": "[REDACTED]"})
    resp = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
        tools=[BILLING_TOOL_SCHEMA],
    )
    return resp.content[0].text
```

### Python — OpenAI SDK, system prompt echoed in API response

```python
# VULNERABLE: the raw system prompt is included in the JSON response body.
from openai import OpenAI
import os

client = OpenAI()
SYSTEM_PROMPT = "You are an internal pricing assistant. Margin table: [CONFIDENTIAL]..."

@app.post("/chat")
async def chat(body: ChatRequest):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": body.message},
        ],
    )
    return {
        "reply": resp.choices[0].message.content,
        "debug": {"system": SYSTEM_PROMPT},  # LEAK — sent to every caller
    }
```

```python
# SECURE: response body contains only the reply; debug info omitted or hashed.
@app.post("/chat")
async def chat(body: ChatRequest):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": body.message},
        ],
    )
    return {"reply": resp.choices[0].message.content}
```

### TypeScript — OpenAI SDK, secret interpolated and console.log'd

```typescript
// VULNERABLE: Slack token interpolated; systemPrompt logged via console.log.
import OpenAI from 'openai';

const openai = new OpenAI();
const SLACK_TOKEN = process.env.SLACK_TOKEN!;
const systemPrompt = `You are a Slack assistant. Post messages using token ${SLACK_TOKEN}.`;

async function handleMessage(userMsg: string): Promise<string> {
  console.log('system:', systemPrompt);   // LEAK — token in log
  const resp = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMsg },
    ],
  });
  return resp.choices[0].message.content ?? '';
}
```

```typescript
// SECURE: token never in prompt string; logging uses a redacted label.
const systemPrompt = 'You are a Slack assistant. Use the post_message tool for Slack actions.';

async function handleMessage(userMsg: string): Promise<string> {
  console.debug('system: [REDACTED]');
  const resp = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMsg },
    ],
  });
  return resp.choices[0].message.content ?? '';
}
```

### Python — LangChain, system prompt stored in plaintext DB

```python
# VULNERABLE: full system prompt (containing business logic) written to a
# shared PostgreSQL table readable by analytics team and third-party BI tool.
from langchain.prompts import SystemMessagePromptTemplate
import psycopg2

SYSTEM = SystemMessagePromptTemplate.from_template(
    "You are the {name} assistant. Internal pricing formula: margin = {margin}%. "
    "Discount codes for VIPs: {discount_codes}. Do not share these with users."
)

def log_conversation(session_id: str, system_text: str, conn):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO conversation_logs (session_id, system_prompt) VALUES (%s, %s)",
            (session_id, system_text),   # LEAK — plaintext, shared sink
        )
    conn.commit()
```

```python
# SECURE: only a versioned identifier is stored; actual prompt is encrypted
# at rest and accessed only by the LLM service.
def log_conversation(session_id: str, system_version: str, conn):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO conversation_logs (session_id, system_prompt_version) VALUES (%s, %s)",
            (session_id, system_version),   # only a version tag, never plaintext
        )
    conn.commit()
```

### Python — Bedrock, unauthenticated debug endpoint returns system prompt

```python
# VULNERABLE: /debug endpoint returns system prompt contents with no auth.
import boto3, json

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
SYSTEM_PROMPT = "Internal: employee salary data follows. [CONFIDENTIAL TABLE]"

@app.get("/debug/llm-config")   # no auth decorator
def debug_config():
    return {"system_prompt": SYSTEM_PROMPT}   # LEAK — unauthenticated

def query_model(user_input: str) -> str:
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_input}],
        "max_tokens": 512,
    })
    resp = bedrock.invoke_model(modelId="anthropic.claude-3-5-sonnet-20241022-v2:0", body=body)
    return json.loads(resp["body"].read())["content"][0]["text"]
```

```python
# SECURE: debug endpoint is removed in production; config inspection goes
# through an authenticated admin-only route that returns only a version hash.
@app.get("/admin/llm-config", dependencies=[Depends(require_admin)])
def llm_config_metadata():
    import hashlib
    return {"system_prompt_hash": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:16]}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find System Prompt Construction and Exposure Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase that (a) constructs a system prompt string, (b) logs a system prompt or a variable that contains one, (c) returns a system prompt in an API response, or (d) stores a system prompt in a database, file, or external service. Write results to `sast/systempromptleak-recon.md`.
>
> **Context**: You will receive `sast/architecture.md`. Use it to identify the LLM SDK(s) in use, the logging framework, the web framework (for route inspection), and the database/ORM layer.
>
> ---
>
> **Category 1 — System Prompt Construction Sites**
>
> Find every location where a system prompt string is built. Look for:
>
> - Python: variables named `system_prompt`, `system`, `SYSTEM_PROMPT`, `system_message`, `sys_prompt`, `instructions`, `preamble`, `persona`, `system_instruction` that are string literals, f-strings, or the result of string concatenation / `.format()` / `Template.substitute()`.
> - Python/Anthropic: `client.messages.create(system=...)` — the `system` keyword argument.
> - Python/OpenAI: `messages=[{"role": "system", "content": ...}]` — the content of the system role message.
> - Python/LangChain: `SystemMessage(content=...)`, `SystemMessagePromptTemplate.from_template(...)`, `ChatPromptTemplate` with a system slot.
> - Python/LlamaIndex: `system_prompt` parameter in `LLM(system_prompt=...)` or agent initialization.
> - Python/Google Generative AI: `model.generate_content(...)` with a `system_instruction` field; `genai.GenerativeModel(system_instruction=...)`.
> - Python/AWS Bedrock: the `system` field inside the JSON body passed to `invoke_model` or `converse`.
> - TypeScript/any: variables named `systemPrompt`, `systemMessage`, `system`, `SYSTEM_PROMPT`, `sysPrompt` that are template literals or string concatenations. The `role: "system"` message content field in any SDK call. The `system` parameter in `@anthropic-ai/sdk` calls.
> - Any framework: `PromptTemplate`, `FewShotPromptTemplate`, `ChatPromptTemplate` instances that render a system message.
>
> For each construction site, note:
> - Whether the string contains a **secret pattern**: `sk-`, `Bearer `, `password`, `token`, `key`, `secret`, `api_key`, `apiKey`, base64-encoded data of length >20, UUID-shaped strings in instruction context.
> - Whether any environment variable is **resolved** into the prompt string (via `os.environ[...]`, `os.getenv(...)`, `process.env.*`, `config.get(...)`, `settings.*`) at construction time.
> - Whether the prompt string is assigned to a module-level constant (evaluated once at import) or built per-request (evaluated on each call).
>
> **Category 2 — Logging Exposure Sites**
>
> Find every logging statement that references a variable that may contain a system prompt:
>
> - Python: `logger.debug/info/warning/error/critical(...)`, `logging.debug/info/...`, `structlog.get_logger().*(...)`, `print(...)` where the argument or a keyword in `extra={...}` includes any variable from Category 1 or a field called `system`, `system_prompt`, `prompt`, `instructions`.
> - TypeScript: `console.log/debug/info/warn/error(...)`, `logger.*(...)` (winston, pino, bunyan) where the argument includes any variable from Category 1.
> - Any: a string interpolation inside a log call that renders the full prompt (`f"Prompt: {SYSTEM_PROMPT}"`, `` `Prompt: ${systemPrompt}` ``).
> - Any: structured logging where the prompt variable is passed as a field value rather than a key, making redaction invisible from the call site.
>
> Flag only if the log call includes the raw resolved prompt — not if it logs `"[REDACTED]"`, `"[omitted]"`, or a hash.
>
> **Category 3 — API Response Exposure Sites**
>
> Find every web framework route handler (FastAPI, Flask, Django, Express, Fastify, NestJS, Hono, etc.) that:
>
> - Returns a response dict/object that includes a variable from Category 1, whether directly (`return {"system": SYSTEM_PROMPT}`) or nested inside a debug/metadata/context object.
> - Serializes a conversation or session object to JSON where the system prompt field is included.
> - Renders an HTML template that embeds the system prompt (Jinja2, Django templates, EJS, Handlebars).
> - Has a route path containing `debug`, `introspect`, `admin`, `config`, `prompt`, `health` that touches any Category 1 variable.
>
> For each route, note whether it has an authentication/authorization decorator or middleware.
>
> **Category 4 — Storage Exposure Sites**
>
> Find every database write, file write, cache set, or queue publish that includes a Category 1 variable in plaintext:
>
> - SQL ORM (SQLAlchemy, Django ORM, Prisma, TypeORM): a model field or raw query that stores a Category 1 variable.
> - Redis / Memcached: `redis.set(key, SYSTEM_PROMPT)` or similar.
> - File writes: `f.write(SYSTEM_PROMPT)` or `fs.writeFileSync(path, systemPrompt)`.
> - Message queues: a message payload that includes a system prompt field.
> - Tracing / APM: OpenTelemetry span attributes or Datadog/DD-trace annotations that include the prompt string.
>
> Flag if the value is stored as plaintext. Note whether encryption is applied before the write.
>
> ---
>
> **What to skip**
>
> - Logging of `"[REDACTED]"`, `"[omitted]"`, or hash values — these are not leaks.
> - Storage behind field-level encryption (pgcrypto, application-layer AES) where the key is not co-located with the ciphertext.
> - System prompts composed entirely of static strings with no secret patterns and that never appear in any log, response, or storage write.
>
> ---
>
> **Output format** — write to `sast/systempromptleak-recon.md`:
>
> ```markdown
> # System Prompt Leak Recon: [Project Name]
>
> ## Summary
> Found [N] candidates: [A] construction sites with possible secrets, [B] logging exposure sites, [C] API response exposure sites, [D] storage exposure sites.
>
> ## Candidates
>
> ### 1. [Descriptive name — e.g., "Billing assistant system prompt with Bearer token, logged at INFO"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sub-class**: [A: secret-in-prompt | B: logging | C: api-response | D: storage | combination]
> - **Secret pattern detected**: [yes — `Bearer`, `sk-`, env-var resolved inline | no]
> - **Construction site**: [file:line of the f-string / concat / template]
> - **Exposure path**: [file:line of the logger.info / return / db.execute that exposes it]
> - **Route auth**: [yes — @requires_auth / no — unauthenticated | N/A]
> - **Code snippet**:
>   ```
>   [the relevant code around the construction and the exposure]
>   ```
>
> [Repeat for each candidate]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/systempromptleak-recon.md`. If the recon found **zero candidates** (the summary reports "Found 0" or the "Candidates" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/systempromptleak-results.md`, write `{"findings": []}` to `sast/systempromptleak-results.json`, **delete** `sast/systempromptleak-recon.md`, and stop:

```markdown
# System Prompt Leak Analysis Results

No system prompt construction or exposure sites found — this class does not apply to this codebase.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate.

### Phase 2: Verify — Secret and Exposure Path Confirmation (Batched)

After Phase 1 completes, read `sast/systempromptleak-recon.md` and split the candidates into **batches of up to 3 candidates each** (numbered sections under `## Candidates`). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (the orchestrator does this — not a subagent):

1. Read `sast/systempromptleak-recon.md` and count the numbered candidate sections (`### 1.`, `### 2.`, ...).
2. Divide into batches of up to 3. For example, 7 candidates → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/systempromptleak-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate, determine whether it is a confirmed system prompt leak (secret-in-prompt, logging exposure, API response exposure, or storage exposure), a false positive, or a conditional risk. Write results to `sast/systempromptleak-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will receive `sast/architecture.md`. Use it to understand the logging infrastructure, the web framework's authentication model, the database access controls, and the deployment environment (prod log visibility, APM data retention, etc.).
>
> **For each candidate, answer these verification questions in order**:
>
> **Q1 (Sub-class A — Secret in Prompt)**:
> Does the system prompt string contain or resolve to a value that matches a secret pattern?
> - Explicit literal: `sk-`, `sk-proj-`, `Bearer `, `ghp_`, `xoxb-`, `xapp-`, `AKIA`, `password =`, `passwd`, `pwd`, `secret`, `/v1/keys/`, base64 string > 20 chars.
> - Resolved env var: `os.environ["KEY"]`, `os.getenv("TOKEN")`, `process.env.SECRET_*`, `config.SECRET`, `settings.API_KEY` interpolated into the prompt at construction time.
> - If yes → **secret-in-prompt confirmed**. Now answer Q2.
> - If no → sub-class A does not apply. Continue to Q2 for sub-class B only.
>
> **Q2 (Sub-class B — Exposure Path)**:
> Does the prompt variable (with or without a secret) reach any of these sinks?
>
> a. **Logger sink**: Is a logger call (any level) receiving the raw prompt string, or an object/dict that contains the raw prompt? Check whether a log framework's `extra={}` dict is passed through to the log processor verbatim (most structured loggers do). If the log level is INFO or above and the log aggregator is reachable beyond the engineering team, this is a high-severity path.
>
> b. **HTTP response sink**: Does any route handler include the prompt variable in the response body, a response header, a redirect URL, an HTML template, or a serialized object that is returned to API callers? If the route has no auth decorator, or if the auth decorator only checks "is authenticated" (not "is admin"), this is critical.
>
> c. **Database / storage sink**: Is the raw prompt string written to a SQL column, a NoSQL document field, a cache value, a message queue payload, or a file where access is not limited to the LLM service itself? Treat multi-tenant shared log tables and analytics databases as high-exposure sinks.
>
> d. **Tracing / APM sink**: Is the prompt added as an OpenTelemetry span attribute, a Datadog custom tag, a Sentry breadcrumb, or a similar observability artifact? These are often shipped to third-party SaaS platforms and retained for days to months.
>
> If no exposure path is confirmed → mark **Not Vulnerable** with rationale.
>
> **FP-killers (mandatory checks before marking Vulnerable)**:
>
> 1. **Logging redaction check**: Does the code use a log sanitizer, a custom `logging.Formatter` that strips `system_prompt` fields, or does the log call explicitly use a redacted string literal (`"[REDACTED]"`)? If yes → Not Vulnerable for the logging path.
>
> 2. **Env-var secret not resolved into string**: If the code does `client = OpenAI(api_key=os.environ["KEY"])` and the `KEY` value is never concatenated into the prompt string (the env var is only used by the SDK client), this is not a sub-class A finding.
>
> 3. **Response body does not include prompt**: If the response serializer uses a Pydantic/Zod schema that excludes the system prompt field, or if the route handler explicitly omits it from the returned dict, this is not a sub-class C finding. Verify by checking the response model's fields.
>
> 4. **Storage is encrypted**: If the DB column uses pgcrypto's `pgp_sym_encrypt`, SQLAlchemy's TypeDecorator with AES encryption, or Prisma's field-level encryption, and the key is not stored in the same table/row, this is not a sub-class D finding.
>
> 5. **Debug endpoint gated in production**: If the route is decorated with a `if settings.DEBUG:` guard, a `require_admin` dependency, or an IP allowlist middleware, and the production deployment has `DEBUG=False`, lower the severity. It is still a finding if the guard is misconfigured or easily bypassed.
>
> **Severity guidance** (resolve after FP-killers):
>
> | Condition | Severity | Exploitability |
> |---|---|---|
> | Secret in prompt AND prompt logged/returned/stored | critical | reachable |
> | Prompt (any content) in unauthenticated API response | critical | reachable |
> | Secret in prompt, no confirmed log/return/store path (extraction requires prompt injection) | high | conditional |
> | Prompt (no secret) logged at INFO+ in production-accessible aggregator | high | reachable |
> | Prompt (no secret) returned in authenticated but overly-broad admin endpoint | medium | conditional |
> | Prompt (no secret) logged at DEBUG only, prod debug logging disabled | medium | conditional |
> | Prompt (no secret) in APM tracing shipped to third-party (e.g., Datadog) | medium | reachable |
> | Prompt in plaintext DB, access restricted to internal operators | low | conditional |
>
> **chain_id assignment**:
> - Set `chain_id: "prompt-secret"` when a finding from this skill co-occurs with a finding from `sast-hardcodedsecrets` for the same secret value (the literal also appears directly in source).
> - Set `chain_id: "prompt-pii-log"` when the system prompt contains PII (name, email, SSN, medical data) and flows into a log or storage sink (co-occurs with `sast-pii`).
> - Set `chain_id: null` for standalone findings.
>
> **Output format** — write to `sast/systempromptleak-batch-[N].md`:
>
> ```markdown
> # System Prompt Leak Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE | severity: critical] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sub-class**: [A: secret-in-prompt | B-log | B-response | B-storage | A+B]
> - **Secret pattern**: [`Bearer `, `sk-`, env-var `BILLING_KEY` resolved inline, etc. | none]
> - **Exposure path**: [file:line of the logger.info / response return / db.execute]
> - **Route auth**: [none — unauthenticated | yes — @requires_auth | N/A]
> - **Taint trace**: [Prompt construction at file:line → exposure sink at file:line]
> - **FP-killers checked**: [List each check and its outcome — e.g., "No log redaction found", "No response schema exclusion"]
> - **Impact**: [Concrete impact — e.g., "Any caller to GET /debug/config receives the full system prompt including a live billing API key"]
> - **Remediation**: [Ordered fix list]
> - **Dynamic test**: [How to confirm — e.g., "curl -s http://localhost:8000/debug/llm-config | jq .system_prompt" or "Trigger a request and inspect the production log stream for the key pattern"]
> - **chain_id**: ["prompt-secret" | "prompt-pii-log" | null]
> - **exploitability**: [reachable | conditional | unreachable | unknown]
> - **confidence**: [high | medium | low]
>
> ### [LIKELY VULNERABLE | severity: high] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Sub-class**: [...]
> - **Secret pattern**: [...]
> - **Concern**: [Why it is a risk even with uncertainty — e.g., "Secret is interpolated at module load time; whether it reaches a log depends on dynamic log level configuration"]
> - **Remediation**: [...]
> - **chain_id**: [...]
> - **exploitability**: conditional
> - **confidence**: medium
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Reason**: [e.g., "Logging call uses '[REDACTED]' literal" or "Response schema excludes system_prompt field via Pydantic model"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [Why confirmation requires runtime inspection — e.g., "Log level is controlled by a config value resolved at startup; cannot determine from static analysis alone"]
> - **Suggestion**: [What to check at runtime or in the deployment config]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/systempromptleak-batch-*.md` file and merge them. The orchestrator does this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/systempromptleak-batch-1.md`, `sast/systempromptleak-batch-2.md`, ... files.
2. Collect every finding and combine them into one list, preserving classification, severity, and every detail field.
3. Count totals across all batches for the executive summary.
4. Write the merged report to `sast/systempromptleak-results.md` using this format:

```markdown
# System Prompt Leak Analysis Results: [Project Name]

## Executive Summary
- Candidates analyzed: [total across all batches]
- Vulnerable: [N]  (critical: [N], high: [N], medium: [N], low: [N])
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Sub-class Breakdown
- Secret-in-prompt findings: [N]
- Logging exposure findings: [N]
- API response exposure findings: [N]
- Storage exposure findings: [N]

## Findings

[All findings from all batches, grouped by classification then by severity:
 VULNERABLE (critical first) → LIKELY VULNERABLE → NEEDS MANUAL REVIEW → NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. **Also write the canonical machine-readable file** `sast/systempromptleak-results.json` with the canonical schema:

```json
{
  "findings": [
    {
      "id": "systempromptleak-1",
      "skill": "sast-systempromptleak",
      "severity": "critical",
      "title": "Bearer token interpolated into system prompt and logged at INFO level",
      "description": "The billing assistant system prompt resolves the BILLING_SERVICE_KEY environment variable into the prompt string at module load time (src/agents/billing.py line 14). The constructed string is then passed verbatim to logger.info() on line 22, shipping the live API key to the production log aggregator on every LLM call. Any engineer or third-party log processor with access to the log sink can extract the credential.",
      "location": { "file": "src/agents/billing.py", "line": 22, "column": 5 },
      "remediation": "1. Remove the secret from the system prompt entirely — pass the billing API key to the tool schema or SDK client instead. 2. Replace logger.info(\"system prompt: {SYSTEM_PROMPT}\") with logger.info(\"system prompt: [REDACTED]\"). 3. Rotate the exposed BILLING_SERVICE_KEY immediately.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "prompt-secret"
    }
  ]
}
```

If there are no findings, still emit `{"findings": []}`.

6. After writing `sast/systempromptleak-results.md` AND `sast/systempromptleak-results.json`, **delete all intermediate batch files** (`sast/systempromptleak-batch-*.md`) and **delete** `sast/systempromptleak-recon.md`.

---

## Findings Template

Each finding in the merged report should include these fields (preserved from the batch outputs):

- **Classification** (Vulnerable / Likely Vulnerable / Not Vulnerable / Needs Manual Review) + **severity** (critical / high / medium / low)
- **Sub-class** — A: secret-in-prompt / B-log / B-response / B-storage / A+B (combination)
- **Secret pattern** — the specific pattern detected (`Bearer `, `sk-`, env-var resolved inline) or "none"
- **File + line range**
- **Exposure path** — file:line of the logging call / route return / storage write
- **Route auth** — for API response findings: whether the route is authenticated
- **Taint trace** — prompt construction site → exposure sink, with file:line at each step
- **FP-killers checked** — evidence that each false-positive filter was evaluated
- **Impact** — concrete attacker scenario (e.g., "Any unauthenticated caller to GET /debug receives the system prompt containing a live API key that can be replayed against the billing API")
- **Remediation** — ordered, specific fix list (remove secret from prompt → redact logging → exclude from response → rotate credential)
- **Dynamic test** — a copy-pasteable command or step to confirm the finding at runtime
- **chain_id** — `"prompt-secret"`, `"prompt-pii-log"`, or `null`
- **exploitability** — `reachable` / `conditional` / `unreachable` / `unknown`
- **confidence** — `high` / `medium` / `low`

---

## chain_id Reference

| chain_id | Meaning | Partner skill |
|---|---|---|
| `prompt-secret` | A secret literal also found in source code (flagged by `sast-hardcodedsecrets`) is additionally embedded in a system prompt, compounding exposure. | `sast-hardcodedsecrets` |
| `prompt-pii-log` | PII data (name, email, SSN, health info) appears in a system prompt and flows into a log or storage sink. | `sast-pii` |

A `chain_id` value shared between two findings means the findings compose into a single attack chain: fix both to remediate the chain.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Apply the **tech-stack gate** first: if no LLM SDK is present, emit empty results and stop.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- **The two sub-classes are independent and may overlap**: a single finding can be both A (secret in prompt) and B (prompt logged). When both apply, mark the sub-class as `A+B` and use the higher severity.
- **Module-level constant vs. per-request construction matters**: a secret resolved into a module-level constant is evaluated once at import time. This means the secret is embedded in the string that is reused for every LLM call — every one of which may be logged. This is typically higher severity than a per-request construction that is harder to aggregate.
- **Log level is not a complete mitigation**: `logger.debug(SYSTEM_PROMPT)` is a finding if debug logging is enabled in production (which it often is in staging/preview deployments that share the same log aggregator). Note the level but do not drop the finding — mark `exploitability: conditional` and `severity: medium` rather than dismissing it.
- **APM tracing is a commonly overlooked sink**: OpenTelemetry spans, Datadog custom attributes, Sentry breadcrumbs, and New Relic custom events frequently ship to third-party SaaS platforms with multi-month retention. Treat them as high-exposure sinks when they include the raw prompt string.
- **Rotation is always part of remediation**: when a secret-in-prompt finding is confirmed, the remediation must include rotating the exposed credential — removing it from the prompt alone does not address the fact that it may already appear in historical logs or APM data.
- **Do not flag prompt injection extraction** (attacker tricking the model into echoing its system prompt through the chat interface). That is `sast-promptinjection` territory. This skill covers *code-level* paths only.
- When in doubt, classify as **Needs Manual Review** rather than Not Vulnerable. Log level configuration, dynamic response serializers, and ORM field exclusions all require runtime confirmation.
- Clean up intermediate files: delete `sast/systempromptleak-recon.md` and all `sast/systempromptleak-batch-*.md` after both result files are written (Phase 3 step 6).
