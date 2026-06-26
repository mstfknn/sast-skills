# Milestone 4 — LLM / agentic semantic (Tier C)

6 Tier-C skills. See [../ROADMAP.md](../ROADMAP.md) and the per-skill task in it.

> **Note.** All six skills require the LLM-driven verify phase and aggressive `sast-triage`
> to manage false-positive volume. Gate them behind the tech-stack router so they never run
> on codebases with no LLM/agent dependencies.

---

## sast-excessiveagency — Excessive agent authority

**Framework:** LLM25 LLM06 / ASI26 ASI02 · **Tier:** C · **CWE:** CWE-250

**Scope.** A tool or function with write, delete, or spend authority is wired to the model
with no human-in-the-loop approval gate; or the agent's tool surface is over-exposed (tools
granted that the task does not require). NOT: read-only tool schemas; tools gated by an
explicit approval callback; sandboxed demo agents with no real side effects.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Python / LangChain | `tools=[...]` lists containing `write`, `delete`, `send`, `execute`, `pay`, `charge`; `AgentExecutor(allow_dangerous_requests=True)`; `handle_tool_error=False` |
| Python / LlamaIndex | `FunctionTool` / `QueryEngineTool` wrapping state-mutating functions with no `before_action` hook |
| Python / OpenAI SDK | `tools=[{"type":"function","function":{...}}]` with `write`/`delete` in name or description, dispatched without a human-approval layer |
| TypeScript / Vercel AI | `tools:{}` map with destructive actions; `maxSteps` set high with no `onStepFinish` guard |
| Any | `allow_dangerous`, `auto_approve`, `bypass_confirmation`, `skip_human_review` flags set truthy |

**Verify.** Does the tool schema grant a state-changing action (filesystem write, DB mutation,
email/SMS send, financial transaction, process spawn)? Is there an approval callback, a
human-in-the-loop step, or a sandboxing layer between the model decision and the tool
execution? FP-killers: explicit `confirm_before_run` / `require_approval` hook; tool wrapped
in a dry-run mode with no real side effects; read-only tools misnamed with destructive verbs.
`exploitability: reachable` when a direct model→tool→side-effect path exists with no approval
gate; `confidence: high` for explicit `allow_dangerous=True`, `medium` when inferred from
schema alone.

**Severity.** Default **high** (unintended data loss, spend, or privilege escalation). Raise
to **critical** when financial or irreversible actions (delete all, bulk send) are reachable
in production; lower to **medium** when the agent runs in a sandboxed environment with
external undo capability.

**Remediation.** Apply least-privilege tool scoping — expose only the tools the current task
requires. Add a human-approval callback for all state-changing tools
(`confirm_action_hook`, `hitl_middleware`). Prefer `dry_run=True` mode by default, switching
to live only after explicit confirmation. Audit tool schemas to remove unused capabilities.

**Chains with.** `sast-toolcalling` (over-permissioned schema + unsafe dispatch) →
`chain_id` "agent-authority"; `sast-missingauth` (no auth on the agent endpoint compounds
blast radius) → `chain_id` "unauth-agency".

**Test fixture.** TP: `AgentExecutor(tools=[delete_file_tool], allow_dangerous_requests=True)`
with no approval hook. TN: same executor with `confirm_before_run=approval_callback`. TN:
read-only `search_tool` with write verb in name but no side effects. Assert only the TP is
flagged, `reachable`, `high`.

---

## sast-ragleak — RAG cross-tenant / indirect injection leak

**Framework:** LLM25 LLM08 / LLM01 · **Tier:** C · **CWE:** CWE-200

**Scope.** A retrieval-augmented generation pipeline queries a vector store or document index
without per-user / per-tenant access-control filtering, allowing documents belonging to other
tenants to flow into the LLM context (cross-tenant leak), or allowing adversarially crafted
documents in the index to inject instructions into the model (indirect prompt injection). NOT:
single-tenant deployments where all retrieved documents are owned by the caller; retrieval
pipelines that apply a mandatory `filter={"tenant_id": current_user}` on every query.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Python / LangChain | `vectorstore.similarity_search(query)` or `.as_retriever()` with no `filter` kwarg; `RetrievalQA` / `ConversationalRetrievalChain` with no `search_kwargs={"filter":...}` |
| Python / LlamaIndex | `index.as_query_engine()` with no `node_postprocessors` enforcing ACL; `VectorIndexRetriever` missing `filters=MetadataFilters(...)` |
| Python / Chroma | `collection.query(query_embeddings=..., where={})` — empty or absent `where` clause |
| Python / Pinecone | `index.query(vector=..., filter=None)` |
| TypeScript / LangChain.js | `vectorStore.similaritySearch(query)` without `filter` argument |
| Any | Retrieved chunk assembled into `system_prompt` or `context` without sanitization or source attribution |

**Verify.** Is the vector-store query executed in a multi-tenant context where different users
own different documents? Is a per-user/per-tenant filter applied on every query path (not just
some)? Is retrieved content treated as trusted instructions rather than data? FP-killers:
verified single-tenant deployment; mandatory ACL filter enforced at the collection/index level
(not just application code); retrieved content wrapped in an untrusted-content fence
(`<retrieved>...</retrieved>`) and the system prompt instructs the model to treat it as data.
`exploitability: reachable` when multi-tenant context is confirmed and filter is absent;
`confidence: high` for missing `filter` in Pinecone/Chroma/Weaviate query, `medium` when
tenancy is inferred from upstream context.

**Severity.** Default **high** (cross-tenant PII exposure). Raise to **critical** when
financial records, health data, or credentials are in the index; lower to **medium** when the
retrieval result is shown only to the querying user (no cross-tenant path confirmed).

**Remediation.** Apply a mandatory metadata filter on every vector-store query keyed to the
authenticated user's tenant ID. Enforce the filter at the collection/namespace level as a
default, not only in application code. Wrap retrieved content in an explicit untrusted-data
fence in the system prompt. Validate that injected content cannot override model instructions
by placing system instructions after retrieved context.

**Chains with.** `sast-promptinjection` (retrieved document contains injection payload) →
`chain_id` "rag-injection"; `sast-pii` (retrieved PII leaks cross-tenant) →
`chain_id` "rag-pii-leak".

**Test fixture.** TP: `vectorstore.similarity_search(user_query)` in a multi-tenant handler
with no `filter`. TN: `vectorstore.similarity_search(user_query, filter={"tenant": tid})`.
TN: single-tenant fixture with no other users in the index. Assert only the TP is flagged,
`reachable`, `high`.

---

## sast-systempromptleak — System prompt secret / echo leak

**Framework:** LLM25 LLM07 · **Tier:** C · **CWE:** CWE-200

**Scope.** A secret (API key, password, token, internal instruction) is embedded as a string
literal inside a system prompt; or a system prompt is logged, returned to the caller, or
stored in a way that exposes it to unauthorized parties. NOT: system prompts containing only
benign persona instructions with no secrets; prompts stored encrypted at rest and never
logged.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Pattern | Sinks |
|---|---|
| Python / any SDK | `system=f"...{API_KEY}..."`, `system_prompt = "...Bearer " + token + "..."` — secret interpolated into prompt string |
| Python / OpenAI | `messages=[{"role":"system","content": SYSTEM_PROMPT}]` where `SYSTEM_PROMPT` is logged via `logger.info(...)` or returned in an API response |
| Python / Anthropic | `client.messages.create(system=PROMPT, ...)` followed by `print(PROMPT)` or `return PROMPT` |
| TypeScript / any | `systemPrompt` variable containing `process.env.SECRET` concatenated inline; `console.log(systemPrompt)` |
| Any | System prompt content stored in a DB column without encryption; system prompt echoed back in a `/debug` or `/health` endpoint |

**Verify.** Does the system prompt string contain a secret pattern (key-like entropy, `sk-`,
`Bearer` prefix, password field, internal instruction marked confidential)? Is the prompt variable
passed to a logger, returned in a response, or stored in plaintext? FP-killers: secret stored
in env var and injected only at runtime with no logging of the resolved value; prompt stored
encrypted; no logging statement touches the prompt variable. `exploitability: reachable` when
a log or response path is confirmed; `confidence: high` for direct `logger.info(system_prompt)`
pattern, `medium` when the prompt flows into a generic object that may be logged downstream.

**Severity.** Default **high** (secret exposure via logs or response). Raise to **critical**
when the prompt is echoed in an unauthenticated API response or stored in plaintext in a
shared log sink; lower to **medium** when exposure is only to authenticated internal operators
with need-to-know access.

**Remediation.** Never embed secrets in system prompts — inject them into the runtime
environment and reference via `os.environ` at call time without logging the resolved value.
Redact or omit system prompt content from all logs (`logger.debug("[system prompt redacted]")`).
Never return the system prompt in API responses. Store system prompts encrypted at rest if
they contain sensitive business logic.

**Chains with.** `sast-hardcodedsecrets` (secret literal in source also appears in prompt) →
`chain_id` "prompt-secret"; `sast-pii` (PII in system prompt leaks via log) →
`chain_id` "prompt-pii-log".

**Test fixture.** TP: `system = f"Use key {os.environ['OPENAI_KEY']} for auth"; logger.info(system)`.
TN: `system = "You are a helpful assistant."; logger.info("[system prompt omitted]")`. TN:
secret in env var, prompt logged only as `"[redacted]"`. Assert only the TP is flagged,
`reachable`, `high`.

---

## sast-toolcalling — Unsafe LLM tool dispatch

**Framework:** LLM25 LLM06 / ASI26 ASI02 · **Tier:** C · **CWE:** CWE-829

**Scope.** Model output is dispatched to a tool or function call without an allow-list of
permitted tool names/arguments; or the tool schema is over-permissioned, granting access to
capabilities the task does not require. This skill covers the tool-dispatch path specifically.
`sast-llmoutput` covers LLM output flowing to code eval, HTML render, SQL, or shell — do not
duplicate those sinks here.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Python / OpenAI | `tool_name = response.choices[0].message.tool_calls[0].function.name; getattr(module, tool_name)()` — dynamic dispatch without allow-list check |
| Python / LangChain | `agent.run(input)` where the tool registry contains tools not scoped to the current user role |
| Python / any | `eval(tool_call.arguments)`, `exec(tool_call.code)`, `subprocess.run(tool_call.command)` driven by model output |
| TypeScript / Vercel AI | `tools[toolName].execute(args)` without `if (ALLOWED_TOOLS.includes(toolName))` guard |
| Any | Tool argument schema with `type: "string"` and no `enum` or `pattern` constraint on safety-critical fields |

**Verify.** Is the tool name resolved from model output without checking against an explicit
allow-list? Are tool arguments passed to the implementation without schema validation? Can the
model construct a tool call that invokes a tool not intended for the current context or user
role? FP-killers: allow-list check before dispatch (`if tool_name not in ALLOWED_TOOLS: raise`);
Pydantic / Zod schema validation of arguments before execution; tool registry scoped to the
authenticated user's role. `exploitability: reachable` when model output directly drives
function dispatch; `confidence: high` for `getattr(module, model_output)()` pattern,
`medium` when dispatch goes through a framework abstraction that may have internal guards.

**Severity.** Default **high** (arbitrary function invocation, data exfiltration, privilege
escalation). Raise to **critical** when dispatch can reach filesystem, shell, or network
primitives; lower to **medium** when tools are read-only and sandboxed.

**Remediation.** Maintain an explicit allow-list of permitted tool names and validate against
it before dispatch. Validate all tool arguments with a strict schema (Pydantic, Zod) before
passing to the implementation. Scope the tool registry to the minimum set required for the
authenticated user's role and current task. Never use `getattr`, `eval`, or `exec` on
model-generated strings.

**Chains with.** `sast-excessiveagency` (over-permissioned schema + unsafe dispatch) →
`chain_id` "agent-authority"; `sast-rce` (dispatch reaches shell/exec) →
`chain_id` "tool-rce".

**Test fixture.** TP: `fn = getattr(tools_module, response.tool_name); fn(response.args)` with
no allow-list. TN: `assert response.tool_name in ALLOWED_TOOLS; fn = TOOL_REGISTRY[response.tool_name]; fn(validated_args)`.
Assert only the TP is flagged, `reachable`, `high`.

---

## sast-memorypoison — Agent memory poisoning

**Framework:** ASI26 ASI06 · **Tier:** C · **CWE:** CWE-349

**Scope.** Untrusted data originating from user input or external tool output is written to
persistent agent memory (long-term context, vector memory, session store) and subsequently
retrieved and trusted as authoritative in future turns or agent sessions. NOT: ephemeral
in-context data that does not persist beyond the current turn; memory stores that apply
content validation or human review before persistence; read-only memory retrieval with no
write path from untrusted sources.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Python / LangChain | `memory.save_context(inputs, outputs)` where `outputs` is derived from tool output or user content without sanitization |
| Python / LlamaIndex | `chat_store.set_messages(session_id, messages)` fed from untrusted input |
| Python / Mem0 | `memory.add(user_message, user_id=uid)` — raw user content written to persistent store |
| Python / any | `agent_memory.append({"role":"user","content": user_input})` persisted to a DB or file |
| TypeScript / any | `memoryStore.set(key, llmOutput)` where `llmOutput` is unvalidated model or tool response |
| Any | Vector DB `.upsert` / `.add` call where the document content comes from `request.body`, tool response, or web-scraped content |

**Verify.** Does the data written to memory originate from an untrusted source (user input,
external tool response, web content)? Is this persisted data later retrieved and used to
influence model behavior or application decisions without re-validation? FP-killers: content
validation or sanitization applied before persistence; human review step before memory
commit; memory used only for logging, not for influencing future model prompts;
ephemeral session memory that is discarded after the session. `exploitability: reachable`
when a write-then-retrieve path is confirmed with no validation gap; `confidence: high` for
direct `memory.add(user_input)` with confirmed retrieval, `medium` when persistence is
inferred from framework defaults.

**Severity.** Default **high** (persistent injection influencing future agent behavior). Raise
to **critical** when poisoned memory can redirect the agent to exfiltrate data or take
unauthorized actions in future sessions; lower to **medium** when memory influence is limited
to personalization with no security-relevant decisions downstream.

**Remediation.** Treat all content written to persistent memory as untrusted. Apply content
validation and sanitization before persistence. Mark memory entries with their trust level and
source provenance. Apply a human-review or confidence-threshold gate before persisting
agent-generated conclusions. Scope memory retrieval with access controls so one user cannot
poison another user's memory store.

**Chains with.** `sast-promptinjection` (poisoned memory contains injection payload that
activates on retrieval) → `chain_id` "memory-injection"; `sast-ragleak` (cross-tenant memory
retrieval) → `chain_id` "memory-rag-leak".

**Test fixture.** TP: `memory.add(request.json()["message"], user_id=uid)` with no validation,
followed by `memory.search(query, user_id=uid)` feeding the result into the next prompt. TN:
`memory.add(sanitize(request.json()["message"]), user_id=uid)`. TN: ephemeral in-memory list
discarded after the response. Assert only the TP is flagged, `reachable`, `high`.

---

## sast-llmdos — LLM denial-of-wallet / unbounded resource

**Framework:** LLM25 LLM10 · **Tier:** C · **CWE:** CWE-770

**Scope.** An LLM API call has no `max_tokens` cap, a recursive or looping agent has no
iteration/depth limit, or user-controlled input can force unbounded token generation or agent
cycles — enabling denial-of-wallet or compute exhaustion. NOT: batch jobs with intentionally
large token budgets that are not user-driven; agents with explicit step limits enforced in
code; calls where the model provider enforces a hard cap independently of the application.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Python / OpenAI | `client.chat.completions.create(model=..., messages=...)` with no `max_tokens` / `max_completion_tokens` argument |
| Python / Anthropic | `client.messages.create(model=..., messages=...)` with no `max_tokens` argument |
| Python / LangChain | `AgentExecutor(max_iterations=None)` or `max_iterations` absent; `while True:` agent loop with no break condition |
| Python / LlamaIndex | `agent.chat(msg)` with `max_function_calls` unset |
| TypeScript / Vercel AI | `streamText({model, messages})` with no `maxTokens`; `generateObject` with no token cap |
| Any | Recursive agent-spawning pattern (`agent.run` calls `agent.run`) with no depth counter or budget guard |

**Verify.** Is `max_tokens` / `max_completion_tokens` absent or set to an unbounded value on a
user-reachable code path? Does an agent loop lack a `max_iterations`, `max_steps`, or
equivalent hard stop? Can a user-supplied prompt (long document, adversarial repetition)
trigger unbounded generation? FP-killers: `max_tokens` set at the model client level as a
default for all calls; framework-level `max_iterations` enforced upstream; non-user-reachable
internal batch call with a controlled prompt. `exploitability: reachable` when the call site
is on a user-facing request path; `confidence: high` for absent `max_tokens` on an HTTP
handler, `medium` when the call is behind an abstraction layer that may set defaults.

**Severity.** Default **medium** (cost overrun, degraded availability). Raise to **high** when
the endpoint is unauthenticated or rate-limit-free and direct user input controls prompt
length; raise to **critical** when a recursive agent loop with no depth limit is confirmed,
enabling exponential cost growth.

**Remediation.** Always set `max_tokens` / `max_completion_tokens` explicitly on every LLM
API call. Set `max_iterations` / `max_steps` on every agent executor (recommend ≤25 for
production). Implement per-user token-budget tracking and reject requests that would exceed
the budget. Apply rate limiting at the API gateway level. Validate and truncate user-supplied
context before including in prompts.

**Chains with.** `sast-missingauth` (unauthenticated endpoint removes rate-limit protection)
→ `chain_id` "unauth-dos"; `sast-excessiveagency` (recursive agent with write tools
compounds cost and damage) → `chain_id` "agent-dos".

**Test fixture.** TP: `openai.chat.completions.create(model="gpt-4o", messages=msgs)` with no
`max_tokens` on a POST handler fed by `request.json()["prompt"]`. TN: same call with
`max_tokens=2048`. TN: internal batch job with hardcoded prompt and `max_tokens=4096`. Assert
only the TP is flagged, `reachable`, `medium`.
