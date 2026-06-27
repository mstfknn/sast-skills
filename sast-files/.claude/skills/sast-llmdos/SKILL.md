---
name: sast-llmdos
description: >-
  Detect unbounded LLM API calls and agent loops in LLM/agent codebases that
  lack hard token caps or iteration limits on user-reachable paths, enabling
  denial-of-wallet attacks and compute exhaustion (CWE-770, LLM10, LLM25).
  Covers Python (OpenAI, Anthropic, LangChain, LlamaIndex), TypeScript (Vercel
  AI SDK), and any recursive agent-spawning pattern. Skip this skill on repos
  with no LLM API calls or agent orchestration — the stack router will mark it
  out-of-scope if no LLM framework is detected.
version: 0.1.0
---

# LLM Denial-of-Wallet / Unbounded Resource Detection

You are performing a focused security assessment to find LLM API calls and agent loops that lack hard caps on token generation or iteration count on user-reachable code paths. This skill uses a three-phase approach with subagents: **recon** (map every LLM call site and agent loop, note whether a cap is present), **batched verify** (confirm exploitation in parallel batches of 3 candidates each), and **merge** (consolidate batch results into the final report and JSON).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What This Skill Covers

### Unbounded Token Generation
An LLM API call on a user-reachable path omits `max_tokens` / `max_completion_tokens` (or passes `null` / `0`), allowing the model to generate an arbitrarily long response. A user who can control the prompt — even indirectly via a document they upload or a message they send — can drive generation to tens of thousands of tokens per request and repeat the request at will, exhausting the application's LLM budget.

### Unbounded Agent Iteration
An agent executor loop (`AgentExecutor`, `while True:` ReAct loop, recursive `agent.run` call) has no `max_iterations`, `max_steps`, or equivalent hard stop. A crafted tool-call sequence, adversarial input, or model hallucination can cause the loop to run indefinitely, consuming tokens and compute on every iteration, and in the worst case spawning child agents that repeat the pattern exponentially.

### User-Controlled Prompt Length
User-supplied content (chat history, uploaded documents, search results) is concatenated into a prompt without length validation or truncation before being sent to the LLM. A user who sends a 200 KB document can force a proportionally large completion on every turn.

### What This Skill Is NOT

Do not flag:
- **Batch jobs with intentionally large token budgets**: Internal pipelines processing known-bounded documents with a hardcoded `max_tokens` set to a large but intentional value.
- **Agent loops with an explicit step limit enforced in code**: `AgentExecutor(max_iterations=25)`, `max_steps=50` in a LangGraph node, `for step in range(max_steps)` loops.
- **Provider-enforced caps that the application relies on knowingly**: Some providers enforce a model-level context window; this is not an application-level control and should not substitute for one, but it does prevent truly infinite generation. Note it as a partial mitigator, not a full TN.
- **Non-user-reachable internal calls**: Background jobs, data-ingestion pipelines, or admin tooling where the prompt is fully controlled by the operator and not influenced by end-user input.

---

## Vulnerability Classes

### Class 1: LLM API Call Without `max_tokens`

The most common and directly exploitable form. The call site omits the token cap entirely or passes an unbounded value.

```python
# Python / OpenAI SDK — missing max_tokens
response = client.chat.completions.create(
    model="gpt-4o",
    messages=messages,   # messages includes user-controlled content
)                        # <- no max_tokens; model generates until it stops itself

# Python / Anthropic SDK — missing max_tokens (required field is omitted at runtime
# via a code path that bypasses the default)
message = client.messages.create(
    model="claude-opus-4-5",
    messages=messages,
)  # <- Anthropic's SDK raises if max_tokens is absent, but a try/except that
   # retries with a large default can mask this

# TypeScript / Vercel AI SDK — missing maxTokens on streamText
const result = await streamText({
    model: openai("gpt-4o"),
    messages,             // <- user-controlled
})                        // <- no maxTokens; streams until model stops
```

### Class 2: Agent Executor Without Iteration Limit

An agent loop can run an unbounded number of tool calls, each consuming tokens and potentially triggering expensive side effects.

```python
# LangChain — max_iterations absent (default is None -> unlimited)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    # max_iterations not set — defaults to None
)

# LangChain — explicit None (worse: developer acknowledged the field but disabled it)
agent_executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)

# ReAct loop with no break condition
while True:
    thought, action, observation = step(agent, tools, state)
    if action == "Final Answer":
        break
    # <- no iteration counter; adversarial tool responses can prevent "Final Answer"
```

### Class 3: Recursive Agent Spawning Without Depth Guard

An agent that can spawn sub-agents (or call itself) without a depth counter leads to exponential cost growth.

```python
# Recursive spawn — no depth limit
async def run_agent(task: str) -> str:
    result = await agent.run(task)
    if needs_refinement(result):
        return await run_agent(refine(task, result))  # <- unbounded recursion
    return result

# Multi-agent fan-out without a budget guard
async def orchestrate(tasks: list[str]) -> list[str]:
    return await asyncio.gather(*[agent.run(t) for t in tasks])
    # <- tasks list is user-controlled; fan-out is unbounded
```

### Class 4: User-Supplied Context Without Truncation

```python
@app.post("/chat")
async def chat(body: ChatRequest):
    # body.document is uploaded by the user — could be megabytes
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": body.document + "\n\n" + body.question},
    ]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=2048,   # <- max_tokens set, but input is unbounded
                           # very long input still exhausts context window budget
    )
```

---

## Token Cap Controls That PREVENT Vulnerabilities

When you see the following patterns applied **at or before the call site**, the finding is a True Negative:

**1. OpenAI SDK — `max_tokens` or `max_completion_tokens` present**
```python
response = client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    max_tokens=2048,          # classic cap — not vulnerable
)

# GPT-4o and later: max_completion_tokens is the recommended field
response = client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    max_completion_tokens=4096,  # not vulnerable
)

# Set at client construction as a default for all calls
client = OpenAI(default_query={"max_tokens": 2048})
# Then later calls inherit it — conditional TN; verify no call-site override
```

**2. Anthropic SDK — `max_tokens` present (required by the SDK)**
```python
message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=1024,
    messages=messages,
)  # not vulnerable
```

**3. LangChain — `max_iterations` set to a finite value**
```python
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=25,      # hard stop — not vulnerable
    early_stopping_method="generate",
)

# LangGraph node with max_steps
graph = StateGraph(AgentState)
graph.add_node("agent", call_model)
compiled = graph.compile(
    checkpointer=MemorySaver(),
    interrupt_before=["tools"],
)
# Caller passes config={"recursion_limit": 25} — conditional TN
```

**4. LlamaIndex — `max_function_calls` set**
```python
agent = ReActAgent.from_tools(
    tools,
    llm=llm,
    max_function_calls=10,   # not vulnerable
    verbose=True,
)
```

**5. Vercel AI SDK — `maxTokens` set on the call**
```typescript
const result = await streamText({
    model: openai("gpt-4o"),
    messages,
    maxTokens: 2048,           // not vulnerable
});

const obj = await generateObject({
    model: openai("gpt-4o"),
    schema: z.object({ answer: z.string() }),
    prompt,
    maxTokens: 1024,           // not vulnerable
});
```

**6. Per-user budget tracking middleware**
```python
# Application-level budget guard before the LLM call
async def call_llm_with_budget(user_id: str, messages: list, max_tokens: int = 2048):
    remaining = await budget_store.get_remaining(user_id)
    if remaining < max_tokens:
        raise BudgetExceededError(f"User {user_id} has exhausted their token budget")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=max_tokens,
    )
    await budget_store.deduct(user_id, response.usage.total_tokens)
    return response
```

**7. Input truncation before the call**
```python
MAX_CONTEXT_TOKENS = 4096

def truncate_context(text: str, max_tokens: int = MAX_CONTEXT_TOKENS) -> str:
    tokens = tokenizer.encode(text)
    if len(tokens) > max_tokens:
        tokens = tokens[:max_tokens]
    return tokenizer.decode(tokens)

messages = [
    {"role": "user", "content": truncate_context(user_document) + "\n" + question}
]
```

---

## Vulnerable vs. Secure Examples

### Python — OpenAI SDK

```python
# VULNERABLE: no max_tokens on a user-facing POST handler
from flask import Flask, request, jsonify
import openai

app = Flask(__name__)
client = openai.OpenAI()

@app.post("/api/chat")
def chat():
    data = request.get_json()
    messages = [{"role": "user", "content": data["prompt"]}]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,    # user-controlled
        # <- no max_tokens — model generates until stop token
    )
    return jsonify({"reply": response.choices[0].message.content})

# SECURE: explicit cap on the same handler
@app.post("/api/chat")
def chat_safe():
    data = request.get_json()
    messages = [{"role": "user", "content": data["prompt"]}]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=2048,       # hard cap
    )
    return jsonify({"reply": response.choices[0].message.content})

# TRUE NEGATIVE: internal batch job, no user interaction, controlled prompt
def nightly_summarize(articles: list[str]) -> list[str]:
    summaries = []
    for article in articles:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": f"Summarize: {article[:3000]}"}],
            max_tokens=512,    # intentional large-but-bounded budget
        )
        summaries.append(response.choices[0].message.content)
    return summaries
# Not vulnerable: prompt is operator-controlled and cap is set
```

### Python — Anthropic SDK

```python
# VULNERABLE: max_tokens set to an effectively unbounded value on a user call
import anthropic

client = anthropic.Anthropic()

@app.post("/api/assistant")
async def assistant(body: dict):
    # Anthropic's SDK will raise if max_tokens is absent — but a pattern
    # like the one below effectively removes the cap:
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=100_000,        # <- effectively unbounded on a user call
        messages=[{"role": "user", "content": body["prompt"]}],
    )
    return {"reply": message.content[0].text}

# SECURE
message = client.messages.create(
    model="claude-opus-4-5",
    max_tokens=2048,
    messages=[{"role": "user", "content": body["prompt"]}],
)
```

### Python — LangChain AgentExecutor

```python
# VULNERABLE: max_iterations not set (defaults to None = unlimited)
from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o")
agent = create_react_agent(llm, tools, prompt)

# User POST /api/agent -> body["task"] controls agent input
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    # max_iterations missing — defaults to None
)
result = executor.invoke({"input": user_task})

# VULNERABLE: explicit None
executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)

# SECURE: finite iteration cap
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=15,
    early_stopping_method="generate",
)
```

### Python — LlamaIndex ReActAgent

```python
# VULNERABLE: max_function_calls not set
from llama_index.core.agent import ReActAgent
from llama_index.llms.openai import OpenAI

llm = OpenAI(model="gpt-4o")
agent = ReActAgent.from_tools(tools, llm=llm, verbose=True)
# max_function_calls defaults to DEFAULT_MODEL_NUM_OUTPUT (no hard stop)

@app.post("/api/agent")
def run_agent(body):
    response = agent.chat(body["message"])   # <- user-controlled, no step limit
    return {"reply": str(response)}

# SECURE
agent_safe = ReActAgent.from_tools(
    tools,
    llm=llm,
    max_function_calls=10,
    verbose=True,
)
```

### TypeScript — Vercel AI SDK

```typescript
// VULNERABLE: no maxTokens on streamText
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { NextRequest } from "next/server";

export async function POST(req: NextRequest) {
    const { messages } = await req.json();  // user-controlled

    const result = await streamText({
        model: openai("gpt-4o"),
        messages,
        // <- no maxTokens — streams until model EOS
    });

    return result.toDataStreamResponse();
}

// VULNERABLE: generateObject without maxTokens
import { generateObject } from "ai";
import { z } from "zod";

export async function analyzeDocument(document: string) {
    const result = await generateObject({
        model: openai("gpt-4o"),
        schema: z.object({ summary: z.string(), tags: z.array(z.string()) }),
        prompt: `Analyze this document:\n\n${document}`,  // user-uploaded
        // <- no maxTokens
    });
    return result.object;
}

// SECURE: explicit maxTokens
const result = await streamText({
    model: openai("gpt-4o"),
    messages,
    maxTokens: 2048,
    maxSteps: 5,   // if using multi-step tool calls
});
```

### Any Framework — Recursive Agent Spawning

```python
# VULNERABLE: recursive agent.run with no depth guard
async def agent_loop(task: str, depth: int = 0) -> str:
    result = await agent.run(task)
    if not is_complete(result):
        return await agent_loop(refine(result), depth)  # <- depth never checked

# VULNERABLE: fan-out without task count limit
async def multi_agent(user_tasks: list[str]) -> list[str]:
    # user_tasks comes from request body — could be thousands of tasks
    return await asyncio.gather(*[agent.run(t) for t in user_tasks])

# SECURE: depth guard + task limit
MAX_DEPTH = 3
MAX_TASKS = 10

async def agent_loop_safe(task: str, depth: int = 0) -> str:
    if depth >= MAX_DEPTH:
        return "Max refinement depth reached."
    result = await agent.run(task)
    if not is_complete(result):
        return await agent_loop_safe(refine(result), depth + 1)
    return result

async def multi_agent_safe(user_tasks: list[str]) -> list[str]:
    if len(user_tasks) > MAX_TASKS:
        raise ValueError(f"Too many tasks: {len(user_tasks)} > {MAX_TASKS}")
    return await asyncio.gather(*[agent.run(t) for t in user_tasks[:MAX_TASKS]])
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Map LLM Call Sites and Agent Loops

Launch a subagent with the following instructions:

> **Goal**: Build a complete inventory of (1) all LLM API call sites in the codebase, noting whether a token cap is present, and (2) all agent loop patterns, noting whether an iteration or depth limit is present. Write results to `sast/llmdos-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand which LLM frameworks, agent libraries, and API clients are in use before beginning your search.
>
> **What to search for**:
>
> 1. **LLM API call sites** — collect every call matching these patterns:
>
>    **Python / OpenAI SDK**
>    - `client.chat.completions.create(` — look for `max_tokens=` or `max_completion_tokens=` in the keyword arguments; flag if absent
>    - `openai.ChatCompletion.create(` (legacy) — look for `max_tokens=`
>    - `AsyncOpenAI().chat.completions.create(` (async variant)
>
>    **Python / Anthropic SDK**
>    - `client.messages.create(` — look for `max_tokens=`; the SDK requires it, but values above ~16000 on a user-facing path are effectively unbounded
>    - `AsyncAnthropic().messages.create(` (async variant)
>
>    **Python / LangChain**
>    - `AgentExecutor(` — look for `max_iterations=` with a finite integer
>    - `AgentExecutor.from_agent_and_tools(` — same
>    - `create_react_agent(` / `create_openai_tools_agent(` initializers
>    - `while True:` loops in files that import `langchain` or `langchain_core`
>    - `LLMChain(` / `chain.run(` / `chain.invoke(` — look for `max_tokens` on the LLM object passed in
>    - LangGraph: `graph.compile(` — look for `recursion_limit` in the compile call or `config` dict
>
>    **Python / LlamaIndex**
>    - `ReActAgent.from_tools(` — look for `max_function_calls=`
>    - `agent.chat(` / `agent.query(` — check the agent's construction
>    - `QueryEngine` wrappers with `llm=` parameter
>
>    **TypeScript / Vercel AI SDK**
>    - `streamText({` — look for `maxTokens:` in the options object
>    - `generateText({` — look for `maxTokens:`
>    - `generateObject({` — look for `maxTokens:`
>    - `streamObject({` — look for `maxTokens:`
>    - Multi-step calls: look for `maxSteps:` alongside `maxTokens:`
>
>    **TypeScript / LangChain.js**
>    - `new AgentExecutor({` — look for `maxIterations:` with a finite integer
>    - `AgentExecutor.fromAgentAndTools({` — same
>
>    **TypeScript / AI SDK (anthropic provider)**
>    - `anthropic("claude-opus-4-5")` usage in `streamText` / `generateText` — same maxTokens check
>
>    **Any framework — recursive agent patterns**
>    - Functions that call themselves with an `agent.run(` / `agent.chat(` / `agent.invoke(` inside
>    - `asyncio.gather(` where the task list is derived from user input
>    - `Promise.all(` where the array is derived from user input to an agent
>
> 2. **For each candidate call site, note**:
>    - File path and line number of the call
>    - The function or route handler containing the call
>    - Whether the call is on a user-reachable path (HTTP handler, WebSocket handler, CLI command accepting user input) vs. an internal background job
>    - `max_tokens` / `max_completion_tokens` / `maxTokens` value if present (or its absence)
>    - `max_iterations` / `max_steps` / `max_function_calls` value if present (or its absence)
>    - Whether user input can influence the prompt sent to the LLM
>    - Whether a per-user token budget is checked before the call
>    - Whether input is truncated before being included in the prompt
>
> 3. **Also collect** any global LLM client construction that sets defaults (e.g., `OpenAI(default_query={"max_tokens": 2048})`), since these create call-level defaults that may make individual missing `max_tokens` arguments safe.
>
> **What to ignore**:
> - LLM calls in test files (`**/test_*`, `**/*.test.ts`, `**/*.spec.ts`, `**/tests/**`) unless the test file itself exposes an endpoint.
> - LLM calls with `max_tokens=0` (some SDKs treat this as "use model default" — flag it, but lower confidence).
> - Read-only documentation or example files that are never executed.
>
> **Output format** — write to `sast/llmdos-recon.md`:
>
> ```markdown
> # LLM DoS Recon: [Project Name]
>
> ## LLM Framework Summary
> - Frameworks detected: [e.g. openai 1.x, anthropic 0.x, langchain 0.x]
> - Global token cap defaults: [yes/no — describe if yes]
> - Per-user budget tracking: [yes/no — describe if yes]
> - Input truncation helpers: [yes/no — describe if yes]
>
> ## Candidate Call Sites
>
> ### 1. [Short description, e.g. "POST /api/chat — OpenAI call without max_tokens"]
> - **File**: `path/to/file.py` (line X)
> - **Handler/Function**: `function_name`
> - **Framework**: OpenAI / Anthropic / LangChain / LlamaIndex / Vercel AI / other
> - **Call type**: LLM completion / agent executor / recursive spawn / fan-out
> - **Token cap present**: yes (max_tokens=2048) / no / unclear
> - **Iteration limit present**: yes (max_iterations=25) / no / N/A
> - **User-reachable**: yes / no / conditional
> - **User controls prompt**: yes / no / partial
> - **Input truncation**: yes / no
> - **Code snippet**:
>   ```
>   [the call site + surrounding route handler, ~10 lines]
>   ```
>
> [Repeat for each candidate]
> ```

### Phase 2: Verify — Confirm Unbounded Calls (Batched)

After Phase 1 completes, read `sast/llmdos-recon.md` and split the candidate inventory into **batches of up to 3 call sites each** (each numbered `### N.` under **Candidate Call Sites**). Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/llmdos-recon.md` and count the numbered sections under **Candidate Call Sites** (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1–3, 4–6, 7).
3. For each batch, extract the full text of those sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/llmdos-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and include only the matching examples from the "Vulnerable vs. Secure Examples" section above in each subagent's instructions under `[TECH-STACK EXAMPLES]`.

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: Verify the following LLM call sites for missing token caps or iteration limits. Write results to `sast/llmdos-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the framework, middleware, and any global defaults that may apply.
>
> **The core verify question**:
> Is this LLM call or agent loop reachable from user-supplied input with no hard cap on token generation or iteration count enforced at the call site or through a verified upstream control?
>
> **False-positive killers — if ANY of the following are true, classify as NOT VULNERABLE**:
>
> 1. `max_tokens` / `max_completion_tokens` / `maxTokens` is set to a reasonable finite value (<=16384 for completions, <=4096 recommended for interactive use) at the call site.
> 2. A global client default sets `max_tokens` for all calls made through that client instance, and this call site uses the same client — verify the client construction.
> 3. `max_iterations` / `max_steps` / `max_function_calls` is set to a finite integer on the agent executor or agent constructor.
> 4. The call is inside a function that is only invoked by a background task manager (Celery beat, cron, BullMQ scheduled job) with a fully operator-controlled prompt and a bounded input size.
> 5. The prompt is constructed exclusively from application-owned content (database records, templates) with no user-supplied free-text, and the total prompt length is bounded by a constant.
> 6. A per-user token budget check explicitly rejects requests that would exceed a cap, and this check runs before the LLM call.
> 7. Input to the prompt is explicitly truncated (by token count or character count) before being appended, AND a `max_tokens` cap is also set on the completion.
>
> **Severity guidance**:
> - **critical**: Recursive or fan-out agent loop with no depth limit or task count cap on a user-reachable path; cost can grow exponentially per request.
> - **high**: Agent executor with no `max_iterations` on a user-reachable path; cost grows linearly but is still unbounded and directly exploitable.
> - **high**: LLM call with no `max_tokens` on an unauthenticated user-facing endpoint; any visitor can trigger full-context completions.
> - **medium**: LLM call with no `max_tokens` on an authenticated user-facing endpoint; cost overrun is possible but requires valid credentials.
> - **medium**: Input concatenated without truncation even when `max_tokens` is set; very long inputs exhaust prompt budget and can trigger context-overflow errors or extremely expensive completions.
> - Lower severity by one level when the endpoint is behind authentication AND a per-user rate limit is in place (reduces blast radius).
>
> **Exploitability**:
> - `reachable`: Call is directly on an HTTP handler, WebSocket handler, or CLI command that accepts user input, with no token cap at any layer.
> - `conditional`: Call is behind authentication or an abstraction layer that may impose implicit limits; needs review.
> - `unreachable`: Confirmed internal/background call with operator-controlled prompt.
> - `unknown`: Cannot determine reachability from static analysis alone.
>
> **Confidence**:
> - `high`: Call site is directly in a route handler body, no `max_tokens` argument, no global client default found.
> - `medium`: Call site is in a helper function called from a route handler; the helper's signature does not expose a token cap parameter and none was found in the calling code.
> - `low`: Multiple layers of abstraction obscure whether a cap is set; no evidence either way.
>
> **Chain IDs**:
> - Endpoint also lacks authentication -> `chain_id: "unauth-dos"` (chains with sast-missingauth)
> - Recursive or fan-out agent loop with tool write access -> `chain_id: "agent-dos"` (chains with sast-excessiveagency)
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **For each assigned candidate, evaluate**:
>
> 1. **Token cap check** — is `max_tokens` / `max_completion_tokens` / `maxTokens` set to a finite value at this call site? Trace any variable references to confirm the value is bounded and not user-supplied.
>
> 2. **Iteration cap check** — if this is an agent executor or loop, is `max_iterations` / `max_steps` / `max_function_calls` set to a finite positive integer? Confirm the value is not `None` and not derived from user input.
>
> 3. **Global default check** — does the LLM client or framework have a global default that caps tokens for all calls? Locate the client constructor and confirm the default applies to this call.
>
> 4. **Reachability check** — trace the call chain from the nearest HTTP/WebSocket handler or CLI entry point to this call site. Confirm whether user-supplied data reaches the `messages` / `prompt` / `input` argument.
>
> 5. **Input validation check** — is there a truncation step that bounds the user-supplied content before it reaches the LLM? What is the truncation limit?
>
> 6. **Budget tracking check** — is there a per-user token quota enforced before this call? What happens when the quota is exceeded?
>
> **Classification**:
> - **VULNERABLE**: No token cap or iteration limit at any layer; call is on a user-reachable path.
> - **LIKELY VULNERABLE**: Cap is nominally present but effectively unbounded (e.g., `max_tokens=100_000` on a user-facing chat endpoint), or an iteration limit exists but is not enforced (e.g., `max_iterations` is set but can be overridden by user-supplied config).
> - **NOT VULNERABLE**: Hard cap in place at the call site or via a verified global default; or call is confirmed non-user-reachable.
> - **NEEDS MANUAL REVIEW**: Cannot determine token cap or reachability from static analysis; an abstraction or dynamic dispatch prevents confident classification.
>
> **Output format** — write to `sast/llmdos-batch-[N].md`:
>
> ```markdown
> # LLM DoS Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Short description
> - **File**: `path/to/file.py` (line X)
> - **Function/Handler**: `function_name` / `POST /api/endpoint`
> - **Framework**: OpenAI / Anthropic / LangChain / etc.
> - **Severity**: critical / high / medium
> - **Issue**: [No max_tokens on user-facing LLM call / no max_iterations on agent executor / etc.]
> - **Impact**: [Cost overrun per malicious request; service degradation for other users; financial DoW]
> - **Proof**: [Call site code showing absent cap + route handler showing user input reaches the call]
> - **Chain IDs**: [unauth-dos / agent-dos / null]
> - **Remediation**: [Exact parameter to add and recommended value]
> - **Verification**:
>   ```
>   # Confirm unbounded generation by sending a long prompt:
>   curl -s -X POST https://<HOST>/api/chat \
>     -H "Content-Type: application/json" \
>     -d '{"prompt": "Repeat the word AAAA forever until you run out of tokens."}' \
>     | jq '.reply | length'
>   # Vulnerable: response will be very long (thousands of characters)
>   # Fixed: response will be capped at the configured max_tokens
>   ```
>
> ### [LIKELY VULNERABLE] Short description
> - **File**: `path/to/file.ts` (line X)
> - **Function/Handler**: `function_name` / route
> - **Framework**: Vercel AI SDK / etc.
> - **Severity**: high / medium
> - **Issue**: [Token cap present but effectively unbounded — e.g., max_tokens=100000 on user chat]
> - **Concern**: [Why the existing cap is insufficient]
> - **Proof**: [Call site code with the problematic cap value]
> - **Chain IDs**: [unauth-dos / agent-dos / null]
> - **Remediation**: [Recommend a tighter cap and input truncation]
>
> ### [NOT VULNERABLE] Short description
> - **File**: `path/to/file.py` (line X)
> - **Function/Handler**: function / route
> - **Protection**: [How it's protected — cap value, global default, or non-user-reachable]
>
> ### [NEEDS MANUAL REVIEW] Short description
> - **File**: `path/to/file.py` (line X)
> - **Uncertainty**: [Why static analysis couldn't determine the status]
> - **Suggestion**: [What to check manually — e.g., trace the abstraction layer in framework X]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/llmdos-batch-*.md` file and merge them. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/llmdos-batch-1.md`, `sast/llmdos-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them, preserving all fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/llmdos-results.md` using this format:

```markdown
# LLM Denial-of-Wallet Analysis Results: [Project Name]

## Executive Summary
- Call sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]
- Critical (recursive/fan-out agent loops): [N]
- High (agent executor without iteration limit or unauthenticated LLM call): [N]
- Medium (authenticated LLM call without token cap): [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write `sast/llmdos-results.json` using the canonical schema. One entry per VULNERABLE or LIKELY VULNERABLE finding. Use `"findings": []` if no vulnerabilities were found.

```json
{
  "findings": [
    {
      "id": "llmdos-1",
      "skill": "sast-llmdos",
      "severity": "medium",
      "title": "No max_tokens on POST /api/chat — OpenAI call",
      "description": "The chat endpoint at src/routes/chat.py:34 calls client.chat.completions.create() with no max_tokens argument. The messages parameter includes user-controlled content from request.json()[\"prompt\"]. An authenticated user can send a prompt designed to elicit the longest possible response (e.g., 'repeat X forever') and repeat the request in a tight loop, exhausting the application's OpenAI token budget and causing denial-of-service for other users via API rate limiting or cost-triggered suspension.",
      "location": { "file": "src/routes/chat.py", "line": 34, "column": 15 },
      "remediation": "Add max_tokens=2048 (or an appropriate cap for your use case) to the create() call. Additionally implement per-user token budget tracking and input truncation before the messages list is constructed. Example: response = client.chat.completions.create(model='gpt-4o', messages=messages, max_tokens=2048)",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    }
  ]
}
```

**Canonical field values for this skill**:
- `id`: `llmdos-<N>` (sequential, 1-based)
- `skill`: `"sast-llmdos"`
- `severity`: `"critical"` (recursive/fan-out agent no depth limit) | `"high"` (agent no max_iterations or unauthenticated LLM call no max_tokens) | `"medium"` (authenticated LLM call no max_tokens or effectively unbounded cap)
- `exploitability`: `"reachable"` when call is directly on a user-facing handler with no cap; `"conditional"` when behind auth or abstraction; `"unreachable"` when confirmed internal; `"unknown"` when static analysis cannot determine
- `confidence`: `"high"` for direct call site in route handler with no cap; `"medium"` for abstracted helper; `"low"` when multiple indirection layers
- `chain_id`: `"unauth-dos"` (no auth + no token cap) | `"agent-dos"` (recursive agent with tool write access) | `null`

6. After writing both output files, **delete all intermediate files**: `sast/llmdos-recon.md` and `sast/llmdos-batch-*.md`.

---

## Chain IDs Reference

| chain_id | Description | Co-occurring skill |
|---|---|---|
| `unauth-dos` | LLM call has no token cap AND the endpoint has no authentication, enabling any internet visitor to trigger unbounded generation | sast-missingauth |
| `agent-dos` | Recursive or fan-out agent loop has no iteration/depth limit AND the agent has write-capable tools, compounding financial cost with potential side effects | sast-excessiveagency |

A finding with `chain_id` set indicates the vulnerability is more severe when combined with the co-occurring finding. The triage and report skills use `chain_id` to correlate and elevate grouped findings.

---

## Test Fixture Reference

When calibrating detection, apply these as ground-truth cases:

**True Positive** — must be flagged, `exploitability: reachable`, `severity: medium`:
```python
# Flask POST handler — user prompt -> OpenAI call, no max_tokens
@app.post("/api/chat")
def chat():
    data = request.get_json()
    msgs = [{"role": "user", "content": data["prompt"]}]
    response = openai.chat.completions.create(model="gpt-4o", messages=msgs)
    return jsonify({"reply": response.choices[0].message.content})
```

**True Negative** — must NOT be flagged:
```python
# Same handler with max_tokens=2048
@app.post("/api/chat")
def chat():
    data = request.get_json()
    msgs = [{"role": "user", "content": data["prompt"]}]
    response = openai.chat.completions.create(
        model="gpt-4o", messages=msgs, max_tokens=2048
    )
    return jsonify({"reply": response.choices[0].message.content})
```

**True Negative** — must NOT be flagged:
```python
# Internal nightly batch job — operator-controlled prompt, max_tokens set
def nightly_digest():
    articles = db.get_today_articles()
    for article in articles:
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": f"Summarize: {article.body[:2000]}"}],
            max_tokens=512,
        )
        db.save_summary(article.id, response.choices[0].message.content)
```

**Only the first case is flagged — `exploitability: reachable`, `severity: medium`.**

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1–3 candidates total, use a single subagent.
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file.
- **Global client defaults are the most common source of false negatives**: an `OpenAI(default_query={"max_tokens": 2048})` client construction will cap all calls on that client even if individual call sites omit the argument. Always check the client constructor before flagging.
- **Anthropic SDK requires `max_tokens`** at the Python type level in recent versions; however, a very high value (e.g., `max_tokens=100_000`) on a user-facing endpoint is a LIKELY VULNERABLE finding. Flag and recommend a tighter limit.
- **LangChain's `max_iterations` defaults to `None`** — absence of this field is not a code author oversight; it is the framework's default behavior. Always flag its absence on user-reachable paths.
- **Recursive agent patterns** require both a depth counter guard AND a base-case check that cannot be bypassed by adversarial model output. If the only stopping condition is the model choosing "Final Answer", it is vulnerable.
- **Input length is a separate concern from output length**: even with `max_tokens` set, unbounded input can exhaust the context window, cause expensive token counting, and trigger provider-level rate limiting. Flag large untruncated inputs as medium severity.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". Abstracted LLM helpers may hide cap logic that is not visible in the call site.
- Always emit `sast/llmdos-results.json` even when no findings exist (`"findings": []`) so the aggregator can confirm the scan ran.
- Clean up intermediate files: delete `sast/llmdos-recon.md` and all `sast/llmdos-batch-*.md` files after both output files are written.
- This skill is not useful on codebases with no LLM API calls or agent frameworks. If `sast/architecture.md` shows no LLM integration, write an empty `sast/llmdos-results.json` (`"findings": []`) and exit.
