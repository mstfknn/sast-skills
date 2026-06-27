---
name: sast-elinj
description: >-
  Detect Expression Language / OGNL / SpEL Injection vulnerabilities (CWE-917)
  in a codebase using a three-phase approach: recon (find programmatic
  expression-evaluator API calls that accept dynamic strings), batched verify
  (trace user input to those evaluation sinks in parallel subagents, 3
  candidates each), and merge (consolidate batch results). Targets Java Spring
  SpEL, Struts OGNL, MVEL, JEXL, JSP EL, and Python simpleeval/asteval
  programmatic APIs. Distinct from sast-ssti (CWE-94): sast-ssti covers
  template-engine rendering pipelines; this skill covers EL/OGNL/SpEL
  evaluator API calls only. Requires sast/architecture.md (run sast-analysis
  first). Outputs findings to sast/elinj-results.md.
version: 0.1.0
---

# Expression Language / OGNL / SpEL Injection (EL Injection) Detection

You are performing a focused security assessment to find Expression Language Injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find candidate expression-evaluator API calls where the expression string is dynamic), **batched verify** (trace whether user input reaches each site's expression argument, in parallel batches of 3), and **merge** (consolidate batch results into the final report).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is EL Injection

Expression Language Injection (CWE-917) occurs when user-supplied input is passed as the **expression string** to a programmatic evaluator API — such as Spring SpEL's `ExpressionParser.parseExpression()`, Struts' OGNL `getValue()`, MVEL's `MVEL.eval()`, JEXL's `JexlEngine.createExpression()`, or JSP EL's `ExpressionFactory.createValueExpression()`. Unlike SSTI (CWE-94), the attack surface here is not a template-rendering pipeline but a direct call to an expression-evaluator API with a user-controlled string. Depending on the evaluator's capabilities and configuration, the attacker can execute arbitrary Java code, read the filesystem, invoke OS commands, or dump the JVM environment.

The core pattern: *unvalidated user input is used as the expression string passed to an expression-evaluator API, not merely as a context variable or data value.*

### Scope Boundary vs. sast-ssti

| | sast-elinj (this skill) | sast-ssti |
|---|---|---|
| **CWE** | CWE-917 (Improper Neutralization of Special Elements in Expression Language) | CWE-94 (Code Injection via Template Engine) |
| **Attack surface** | Programmatic EL/OGNL/SpEL/MVEL/JEXL evaluator API calls | Template-engine render/compile/evaluate pipelines (Jinja2, FreeMarker, Velocity, Thymeleaf, Twig, etc.) |
| **Triggering API** | `SpelExpressionParser.parseExpression(expr)`, `MVEL.eval(expr, …)`, `JexlEngine.createExpression(expr)`, `OGNL.getValue(expr, ctx)`, `ExpressionFactory.createValueExpression(ctx, expr, …)`, `simple_eval(expr)` | `render_template_string(tmpl)`, `ejs.render(tmpl)`, `Handlebars.compile(tmpl)`, `ERB.new(tmpl)`, etc. |
| **Skip** | Template-engine rendering calls | EL evaluator API calls |

Both skills may co-exist on the same stack; use `chain_id: "code-injection-surface"` when both surface findings in the same application.

### What EL Injection IS

- Passing user input as the expression string to an EL/OGNL/SpEL evaluator API:
  - `new SpelExpressionParser().parseExpression(req.getParameter("expr")).getValue()` — Spring SpEL direct user input
  - `parser.parseExpression(name + "." + req.getParameter("field")).getValue(ctx)` — concatenation with user input
  - `MVEL.eval(req.getParameter("rule"), context)` — MVEL evaluation of request parameter
  - `MVEL.compileExpression(userString)` followed by `MVEL.executeExpression(compiled, ctx)` — two-step compile+execute
  - `engine.createExpression(req.getParameter("expr")).evaluate(ctx)` — JEXL evaluation
  - `new JexlBuilder().create().createScript(userInput).execute(ctx)` — JEXL scripting
  - `OGNL.getValue(req.getParameter("expr"), context, root)` — raw OGNL evaluation
  - `Ognl.getValue(userExpr, ognlContext, actionObject)` — Struts-style OGNL on action object
  - `ExpressionFactory.newInstance().createValueExpression(elCtx, req.getParameter("el"), Object.class).getValue(elCtx)` — JSP EL programmatic evaluation
  - `simple_eval(request.args.get("expr"))` — Python simpleeval with user input
  - `aeval = asteval.Interpreter(); aeval(request.form.get("expr"))` — Python asteval on untrusted input

- Second-order: user-controlled expression stored in DB/config and later evaluated:
  - User submits a "custom rule expression" that is saved to the database
  - Application later loads and evaluates that expression via SpEL/MVEL/JEXL without sanitisation
  - Lower privilege users can modify configuration files read by `MVEL.eval()` at runtime

### What EL Injection is NOT

Do not flag these patterns:

- **Constant expression strings** (no user input involved):
  ```java
  // Safe — expression is a compile-time constant
  parser.parseExpression("user.name").getValue(ctx);
  parser.parseExpression("#root.authorities.?[authority == 'ADMIN']").getValue(ctx);
  ```

- **SpEL with `SimpleEvaluationContext` and no method invocations allowed**:
  ```java
  // Reduced risk — SimpleEvaluationContext restricts to property reads only;
  // method invocations and class access are blocked by default
  ExpressionParser parser = new SpelExpressionParser();
  SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
  parser.parseExpression(userInput).getValue(ctx, myBean);
  // Still flag if method invocations are explicitly re-enabled on the context
  ```

- **Expressions validated against a strict allowlist before evaluation**:
  ```java
  private static final Pattern SAFE_EXPR = Pattern.compile("^[a-zA-Z0-9_.]+$");
  if (!SAFE_EXPR.matcher(userExpr).matches()) throw new IllegalArgumentException("bad expr");
  parser.parseExpression(userExpr).getValue(ctx);
  // Allowlist prevents shell metacharacters and Java class navigation — still review carefully
  ```

- **EL used on server-side data only** (no user influence on the expression string):
  ```java
  String expr = config.getStaticRuleExpression();  // loaded from application.yml at startup
  MVEL.eval(expr, ctx);  // config file is not editable by end users
  ```

- **XSS via EL output**: if an EL result is rendered in HTML without escaping — that is XSS, not EL injection.

### Patterns That Prevent EL Injection

**1. SimpleEvaluationContext (Spring SpEL — restricted evaluation)**
```java
// Restricts to property access on provided bean; no T(java.lang.Runtime) possible
SimpleEvaluationContext evalCtx = SimpleEvaluationContext
    .forReadOnlyDataBinding()
    .withInstanceMethods()   // instance methods allowed — still review
    .build();
// vs. forReadOnlyDataBinding().build() — no methods at all, safer
Expression expr = parser.parseExpression(userInput);
Object result = expr.getValue(evalCtx, myBean);
```

**2. Strict allowlist validation before evaluation**
```java
private static final Set<String> ALLOWED_FIELDS =
    Set.of("order.total", "user.tier", "product.price");

if (!ALLOWED_FIELDS.contains(userInput)) {
    throw new AccessDeniedException("Expression not permitted: " + userInput);
}
parser.parseExpression(userInput).getValue(ctx);
```

**3. Sandboxed JEXL with security manager**
```java
JexlSandbox sandbox = new JexlSandbox(false);  // whitelist-only sandbox
sandbox.allow(Math.class.getName());
JexlEngine jexl = new JexlBuilder().sandbox(sandbox).strict(true).create();
JexlExpression expr = jexl.createExpression(userInput);
// Only Math class methods accessible — arbitrary reflection blocked
```

**4. MVEL with sandboxed class resolver**
```java
ParserConfiguration pconf = new ParserConfiguration();
pconf.setClassLoader(sandboxedLoader);  // loader with restricted class visibility
ParserContext pctx = new ParserContext(pconf);
MVEL.compileExpression(userInput, pctx);
// Restricts which classes are resolvable in the expression
```

---

## Vulnerable vs. Secure Examples

### Java — Spring SpEL

```java
// VULNERABLE: HTTP parameter flows directly into SpEL evaluator
@GetMapping("/search")
public Object search(@RequestParam String filter, HttpServletRequest request) {
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext ctx = new StandardEvaluationContext(dataService);
    Expression expr = parser.parseExpression(filter);
    return expr.getValue(ctx);
    // Payload: ?filter=T(java.lang.Runtime).getRuntime().exec('id')
    // Full class access via StandardEvaluationContext — arbitrary RCE
}

// SECURE: expression is a compile-time constant, user input only in context
@GetMapping("/search")
public Object search(@RequestParam String userId) {
    ExpressionParser parser = new SpelExpressionParser();
    EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    ctx.setVariable("userId", userId);
    return parser.parseExpression("#root.findById(#userId)").getValue(ctx, dataService);
}
```

```java
// VULNERABLE: string concatenation produces user-controlled expression
@PostMapping("/rule")
public boolean evaluateRule(@RequestBody RuleRequest req) {
    String expr = "order." + req.getField() + " > " + req.getThreshold();
    // If req.getField() = "class.classLoader.urls[0]" -> class loading gadget
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext ctx = new StandardEvaluationContext(order);
    return (Boolean) parser.parseExpression(expr).getValue(ctx);
}

// SECURE: allowlist the field name, build expression from constants
private static final Set<String> ALLOWED_FIELDS = Set.of("total", "quantity", "discount");

@PostMapping("/rule")
public boolean evaluateRule(@RequestBody RuleRequest req) {
    if (!ALLOWED_FIELDS.contains(req.getField())) throw new IllegalArgumentException();
    String expr = "order." + req.getField() + " > " + req.getThreshold();
    SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    return (Boolean) new SpelExpressionParser().parseExpression(expr).getValue(ctx, order);
}
```

### Java — Struts OGNL

```java
// VULNERABLE: Struts 2 action with user-controlled redirect expression
// (Classic CVE-2013-1966, CVE-2017-5638 pattern)
// Typically in struts.xml or via redirect parameter:
//   action?redirect:${@java.lang.Runtime@getRuntime().exec('id')}
// Or programmatic:
String expr = request.getParameter("expr");
Object value = Ognl.getValue(expr, ognlContext, root);
// OGNL gives full Java reflection access by default

// SECURE: upgrade to Struts >= 2.5.x with OGNL sandbox controls;
// never interpolate request parameters into action names or redirect values;
// configure ExcludedClasses and ExcludedPackages in struts.xml:
//   <constant name="struts.excludedClasses" value="java.lang.Object,..."/>
```

```java
// VULNERABLE: dynamic OGNL expression from a config editable by untrusted admins
String ruleExpr = adminConfigService.get("notification.rule");
// If lower-privilege admin can write this field, they can inject OGNL
Object result = Ognl.getValue(ruleExpr, ognlContext, rootObject);

// SECURE: expressions in config files should be treated as code;
// store only data values in config; build expressions from constants server-side
```

### Java — MVEL

```java
// VULNERABLE: MVEL evaluates a request parameter
@PostMapping("/calculate")
public Object calculate(@RequestParam String expression) {
    Map<String, Object> vars = new HashMap<>();
    vars.put("orderTotal", currentOrder.getTotal());
    return MVEL.eval(expression, vars);
    // Payload: expression = "System.exit(1)"  or
    //          "new java.lang.ProcessBuilder('id').start().text()"
}

// SECURE: accept only arithmetic; validate with strict pattern; reject others
private static final Pattern ARITHMETIC = Pattern.compile("^[\\d+\\-*/().\\s]+$");

@PostMapping("/calculate")
public Object calculate(@RequestParam String expression) {
    if (!ARITHMETIC.matcher(expression).matches()) {
        throw new IllegalArgumentException("Only arithmetic expressions permitted");
    }
    Map<String, Object> vars = Map.of("orderTotal", currentOrder.getTotal());
    return MVEL.eval(expression, vars);
}
```

### Java — JEXL

```java
// VULNERABLE: JEXL engine with unrestricted class access
@GetMapping("/formula")
public Object formula(@RequestParam String expr) {
    JexlEngine jexl = new JexlBuilder().create();
    JexlContext ctx = new MapContext(Map.of("data", dataBean));
    return jexl.createExpression(expr).evaluate(ctx);
    // Payload: "data.class.forName('java.lang.Runtime').getMethod('exec',String.class)
    //           .invoke(data.class.forName('java.lang.Runtime').getMethod('getRuntime')
    //           .invoke(null), 'id')"
}

// SECURE: sandbox JexlEngine to allow only specific classes and properties
@GetMapping("/formula")
public Object formula(@RequestParam String expr) {
    JexlSandbox sandbox = new JexlSandbox(false);  // deny by default
    sandbox.allow(DataBean.class.getName());
    JexlEngine jexl = new JexlBuilder().sandbox(sandbox).strict(true).silent(false).create();
    JexlContext ctx = new MapContext(Map.of("data", dataBean));
    return jexl.createExpression(expr).evaluate(ctx);
}
```

### Java — JSP EL (programmatic API)

```java
// VULNERABLE: JSP EL evaluated programmatically with user-controlled expression
@RequestMapping("/preview")
public String preview(HttpServletRequest request) {
    String elExpr = request.getParameter("el");
    ExpressionFactory factory = ExpressionFactory.newInstance();
    ELContext elCtx = new SimpleELContext();
    ValueExpression ve = factory.createValueExpression(elCtx, elExpr, Object.class);
    Object result = ve.getValue(elCtx);
    return String.valueOf(result);
    // JSP EL 3.0 supports lambda expressions and stream operations;
    // earlier versions are more limited but can still expose implicit objects
}

// SECURE: only evaluate EL expressions from static resources (JSP files);
// never pass request parameters into createValueExpression() or createMethodExpression()
```

### Python — simpleeval

```python
# VULNERABLE: evaluating arbitrary user-supplied expression
from simpleeval import simple_eval

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    result = simple_eval(expr)  # simpleeval is safer than eval() but not a sandbox
    return str(result)
    # simpleeval restricts to arithmetic by default but allows attribute access;
    # with certain inputs it can still access __class__, __subclasses__ etc.

# SECURE: restrict operators and names explicitly
from simpleeval import EvalWithCompoundTypes, NameNotDefined
import ast
import operator

ALLOWED_NAMES = {'pi': 3.14159, 'e': 2.71828}
ALLOWED_OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub,
                     ast.Mult: operator.mul, ast.Div: operator.truediv}

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    s = EvalWithCompoundTypes(operators=ALLOWED_OPERATORS, names=ALLOWED_NAMES)
    try:
        return str(s.eval(expr))
    except (NameNotDefined, AttributeError):
        abort(400)
```

```python
# VULNERABLE: asteval Interpreter on user input
from asteval import Interpreter

@app.route('/script')
def run_script():
    code = request.form.get('code', '')
    aeval = Interpreter()
    result = aeval(code)
    # asteval blocks only the most obvious attacks;
    # __import__, os module may still be accessible depending on version/config
    return str(result)

# SECURE: do not use asteval for untrusted input;
# use a purpose-built safe arithmetic library or server-side logic instead
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find Expression-Evaluator API Calls Using Dynamic Strings

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a programmatic expression-evaluator API is invoked with a **dynamically built string** as the expression argument — rather than a compile-time string literal. Write results to `sast/elinj-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, languages, and frameworks in use. This skill targets EL/OGNL/SpEL/MVEL/JEXL programmatic evaluator APIs. It does NOT target template-engine rendering pipelines (Jinja2, FreeMarker, Thymeleaf, Twig, etc.) — those are handled by `sast-ssti`.
>
> **What to search for — vulnerable expression-evaluator call patterns**:
>
> Flag any call where the expression string argument is a variable, a concatenated string, or any non-literal value. Do not yet check whether that variable comes from user input — that is Phase 2's job.
>
> 1. **Java — Spring SpEL**:
>    - `new SpelExpressionParser().parseExpression(var)` — any non-literal argument
>    - `parser.parseExpression(var)` where `parser` is an `ExpressionParser`
>    - `expressionParser.parseExpression(a + b)` — concatenation involving any variable
>    - `parser.parseRaw(var)` — less common SpEL raw parse
>    - Look for import of `org.springframework.expression.ExpressionParser` or `SpelExpressionParser`
>
> 2. **Java — Struts OGNL**:
>    - `Ognl.getValue(var, context, root)` — any non-literal first argument
>    - `Ognl.setValue(var, context, root, value)`
>    - `ognl.getValue(var, ctx)` using an `OgnlContext`
>    - Look for import of `ognl.Ognl` or `com.opensymphony.xwork2.ognl`
>    - Redirect parameters in `struts.xml` using `${...}` with dynamic values from requests (note: this is configuration injection, still flag it)
>
> 3. **Java — MVEL**:
>    - `MVEL.eval(var, ...)` — any non-literal first argument
>    - `MVEL.eval(var, ctx)`, `MVEL.eval(var, base, ctx)`
>    - `MVEL.compileExpression(var)` or `MVEL.compileSetExpression(var)`
>    - `MVEL.executeExpression(compiled, ...)` following a compile of a non-literal
>    - Look for import of `org.mvel2.MVEL`
>
> 4. **Java — JEXL (Apache Commons JEXL)**:
>    - `jexl.createExpression(var)` — any non-literal argument
>    - `engine.createScript(var)`, `jexl.createScript(var)`
>    - `new JexlBuilder().create().createExpression(var)`
>    - `JexlScript script = jexl.createScript(var)` — variable argument
>    - Look for import of `org.apache.commons.jexl3` or `org.apache.commons.jexl2`
>
> 5. **Java — JSP EL (programmatic)**:
>    - `factory.createValueExpression(elCtx, var, type)` — non-literal second argument
>    - `factory.createMethodExpression(elCtx, var, returnType, paramTypes)` — non-literal
>    - `ExpressionFactory.newInstance().createValueExpression(ctx, var, ...)`
>    - Look for import of `javax.el.ExpressionFactory` or `jakarta.el.ExpressionFactory`
>
> 6. **Python — simpleeval**:
>    - `simple_eval(var)` — any non-literal argument
>    - `simple_eval(var, operators=..., names=...)` — non-literal first argument
>    - `EvalWithCompoundTypes().eval(var)` — non-literal argument
>    - `s = SimpleEval(); s.eval(var)` — non-literal
>    - Look for `from simpleeval import` or `import simpleeval`
>
> 7. **Python — asteval**:
>    - `Interpreter()(var)` — non-literal argument
>    - `aeval = Interpreter(); aeval(var)` — non-literal
>    - `aeval.eval(var)` — non-literal
>    - Look for `from asteval import Interpreter` or `import asteval`
>
> **What to skip** (safe patterns — do not flag):
> - Calls where the expression argument is a **string literal**: `parser.parseExpression("user.name")`, `MVEL.eval("total > 100", ctx)`, `simple_eval("2 + 2")`
> - Template-engine rendering calls (Jinja2, FreeMarker, Thymeleaf, Velocity, Twig, ERB, EJS, etc.) — those belong to `sast-ssti`
> - Expression engine configuration/setup calls that do not evaluate user-supplied strings: `new JexlBuilder().strict(true).create()`, `new SpelExpressionParser(config)`
> - `@Value("${config.property}")` Spring annotations — these are configuration injection from trusted `application.properties`, not user EL injection (unless you can confirm the property originates from a user-editable store)
>
> **Output format** — write to `sast/elinj-recon.md`:
>
> ```markdown
> # EL Injection Recon: [Project Name]
>
> ## Summary
> Found [N] locations where an expression-evaluator API is called with a dynamic (non-literal) expression string.
>
> ## Candidate Evaluation Sites
>
> ### 1. [Descriptive name — e.g., "SpEL parseExpression in /search endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Evaluator**: [SpEL / OGNL / MVEL / JEXL / JSP EL / simpleeval / asteval]
> - **Evaluation call**: [parser.parseExpression / MVEL.eval / jexl.createExpression / etc.]
> - **Dynamic argument**: `var_name` — [brief note on what it appears to represent]
> - **Code snippet**:
>   ```
>   [the evaluation call with the dynamic argument]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/elinj-recon.md`. If the recon found **zero candidate evaluation sites** (the summary reports "Found 0" or the "Candidate Evaluation Sites" section is empty or absent), **skip Phase 2 and Phase 3 entirely**. Instead, write the following content to `sast/elinj-results.md` and also write `sast/elinj-results.json` with `{"findings": []}`, then stop:

```markdown
# EL Injection Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one candidate evaluation site.

### Phase 2: Verify — Trace User Input (Batched)

After Phase 1 completes, read `sast/elinj-recon.md` and split the candidate evaluation sites into **batches of up to 3 candidates each**. Launch **one subagent per batch in parallel**. Each subagent traces taint for only its assigned candidates and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/elinj-recon.md` and count the numbered candidate sections under "Candidate Evaluation Sites" (`### 1.`, `### 2.`, etc.).
2. Divide them into batches of up to 3. For example, 7 candidates → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those candidate sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned candidates.
5. Each subagent writes to `sast/elinj-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned candidate evaluation site, determine whether a user-supplied value reaches the dynamic expression string argument. Our goal is to find EL Injection vulnerabilities (CWE-917). Write results to `sast/elinj-batch-[N].md`.
>
> **Your assigned candidates** (from the recon phase):
>
> [Paste the full text of the assigned candidate sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, and how data flows through the application.
>
> **EL Injection reference — what to trace**:
>
> For each evaluation site, trace the **dynamic expression argument** backwards to its origin.
>
> 1. **Direct user input** — the argument is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.getParameter(...)`, `req.query.x`, `request.args.get(...)`, `c.Query("x")`
>    - Path parameters: `@PathVariable String expr`, `req.params.id`
>    - Request body / JSON fields: `@RequestBody`, `req.body.expr`, `request.form.get(...)`
>    - HTTP headers: `request.getHeader(...)`, `req.headers['X-Expression']`
>    - Cookies: `request.getCookies()`, `req.cookies.get(...)`
>
> 2. **Indirect user input** — the argument is derived from user input through transformations, function calls, or intermediate assignments. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - String concatenation where any part comes from user input: `"order." + req.getParameter("field")`
>    - Variable read from a DTO/POJO field → check how the DTO was populated
>    - Variable conditionally assigned — check all branches
>
> 3. **Second-order input** — the expression string is read from the database, a configuration store, or a file, but the stored value originally came from user input (e.g., user-submitted "custom rule" or "notification condition" feature):
>    - Find where this value was written — was it stored from a user-supplied field?
>    - Was it validated or sanitised before storage? Note: sanitising EL payloads is unreliable — still flag.
>    - Confidence should be `medium` for second-order cases unless the write path is confirmed.
>
> 4. **Server-side / hardcoded value** — the expression string comes from application source code, a compile-time constant, `application.yml`/`application.properties` loaded at startup with no user-editable path, or server-side logic with no user influence — this site is NOT exploitable.
>
> **Evaluator risk level** (for severity assignment):
>
> | Evaluator | Default severity | Notes |
> |---|---|---|
> | Spring SpEL with `StandardEvaluationContext` | **Critical** | Full Java reflection, arbitrary class access, RCE |
> | Struts OGNL (unpatched or misconfigured) | **Critical** | Full Java class access, historic RCE CVEs |
> | MVEL | **Critical** | Scripting language with full Java interop |
> | JEXL (unrestricted engine) | **Critical** | Class access via `new`, reflection gadgets |
> | JSP EL (programmatic, EL 3.0) | **High** | Lambda and stream support in EL 3.0 enables complex gadgets |
> | Spring SpEL with `SimpleEvaluationContext` (property access only) | **High** | No method invocations; can still leak sensitive properties |
> | JEXL with sandbox (allow-listed classes only) | **Medium** | Significantly restricted; verify sandbox configuration |
> | Python simpleeval (restricted operators/names) | **Medium** | Default mode restricts operators; custom config may expand it |
> | Python simpleeval (default, no restrictions on names) | **High** | `__class__`, `__subclasses__` attribute access possible |
> | Python asteval | **High** | Blocks `__import__` by default but not all dangerous operations |
>
> **Mitigations to check** (FP-killers):
>
> - **`SimpleEvaluationContext` (Spring SpEL)**: Does the code use `SimpleEvaluationContext` vs `StandardEvaluationContext`? If `SimpleEvaluationContext` with `forReadOnlyDataBinding().build()` (no instance methods), downgrade severity from critical to high — property traversal is still possible and may leak sensitive data.
> - **Are instance methods re-enabled on `SimpleEvaluationContext`?** Look for `.withInstanceMethods()` or `.withMethodResolvers(...)` — if so, keep severity at critical.
> - **Strict allowlist before evaluation**: Is the expression validated against a strict allowlist (e.g., `Set.of("order.total", "user.tier")`) before being passed to the evaluator? If the allowlist covers the full expression and does not allow class navigation characters (`.class`, `T(`, `#root`), downgrade severity and set exploitability to `conditional`.
> - **JEXL sandbox (`JexlSandbox`)**: Is `new JexlBuilder().sandbox(sandbox).create()` used with a restrictive deny-by-default sandbox? If confirmed, downgrade severity and set exploitability to `conditional`.
> - **Blocklist filtering is NOT a mitigation**: attempts to strip `T(`, `#`, `{`, `}` from user input are bypassed via encoding or alternate syntax. Do not classify as "Not Vulnerable" solely because filtering is present.
> - **MVEL sandboxed class loader**: Does the code pass a restricted `ParserConfiguration` with a sandboxed `ClassLoader`? If confirmed, downgrade severity and set exploitability to `conditional`.
>
> **Exploitability and confidence assignment**:
>
> - `exploitability: reachable` — user-controlled input flows directly into the evaluator with no meaningful barrier.
> - `exploitability: conditional` — there is a mitigation (allowlist, sandbox) but it may be incomplete or bypassable; or the source is second-order.
> - `exploitability: unreachable` — the expression is provably not user-controlled (constant, startup config).
> - `exploitability: unknown` — cannot determine the argument's origin with confidence.
>
> - `confidence: high` — source is a direct request parameter/body field, taint trace is clear and unambiguous.
> - `confidence: medium` — source is indirect (helper function, second-order, or partial concatenation), or a mitigation is present but unverified.
> - `confidence: low` — origin is unclear; requires manual review.
>
> **chain_id**: Set to `"code-injection-surface"` when both SSTI and EL injection findings are found in the same application, to indicate they share the same attack surface. Set to `null` otherwise.
>
> **Vulnerable vs. secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the expression string argument with no effective mitigation.
> - **Likely Vulnerable**: User input probably reaches the evaluator (indirect flow, second-order, or concatenation) or only a weak/blocklist mitigation is in place.
> - **Not Vulnerable**: Expression string is server-side only (constant, startup config) OR a confirmed restrictive sandbox/allowlist is in place with no bypass path.
> - **Needs Manual Review**: Cannot determine the argument's origin with confidence, or a mitigation is present but its scope is unclear.
>
> **Output format** — write to `sast/elinj-batch-[N].md`:
>
> ```markdown
> # EL Injection Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Evaluator**: [SpEL / OGNL / MVEL / JEXL / JSP EL / simpleeval / asteval] (severity: Critical/High)
> - **Issue**: [e.g., "HTTP query parameter `filter` flows directly into SpelExpressionParser.parseExpression() with StandardEvaluationContext"]
> - **Taint trace**: [Step-by-step from entry point to the evaluation call — e.g., "req.getParameter('filter') → filter → parser.parseExpression(filter).getValue(standardCtx)"]
> - **Exploitability**: reachable
> - **Confidence**: high | medium
> - **chain_id**: "code-injection-surface" | null
> - **Impact**: Remote code execution — attacker can execute arbitrary Java/OS commands, read files, exfiltrate secrets, or enumerate the JVM environment.
> - **Proof-of-concept payload**:
>   ```
>   [Evaluator-specific payload.
>    SpEL/Standard: ?filter=T(java.lang.Runtime).getRuntime().exec('id')
>    SpEL/Simple (property leak): ?filter=password  (exposes bean property)
>    OGNL: expr=${@java.lang.Runtime@getRuntime().exec('id')}
>    MVEL: ?expression=System.exit(1)
>    JEXL: ?expr="".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)
>    simpleeval: ?expr=__import__('os').system('id')  (may fail depending on version/config)
>    asteval: code=import('os'); os.system('id')  (blocked in newer versions — test first)]
>   ```
> - **Remediation**: Never pass user-controlled strings to an expression evaluator. For Spring SpEL, use `SimpleEvaluationContext.forReadOnlyDataBinding().build()` and build expressions from constants, passing user data only as context variables. For MVEL/JEXL, apply a strict allowlist on the expression string or use a sandboxed engine configuration. For Struts OGNL, upgrade to a patched version and configure `ExcludedClasses`/`ExcludedPackages`. For simpleeval/asteval, restrict operators and names and apply strict input validation.
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Evaluator**: [evaluator name] (severity: High/Medium)
> - **Issue**: [e.g., "Expression string likely sourced from user input via helper function" or "Second-order: user-submitted rule expression stored in DB then evaluated server-side via MVEL"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Exploitability**: conditional | unknown
> - **Confidence**: medium | low
> - **chain_id**: "code-injection-surface" | null
> - **Concern**: [Why it's still a risk — e.g., "Second-order EL injection: user can craft a MVEL payload at submission time that executes when the rule is evaluated later"]
> - **Proof-of-concept payload**:
>   ```
>   [payload for the evaluator]
>   ```
> - **Remediation**: [Specific fix]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Expression string is a compile-time constant" or "SimpleEvaluationContext.forReadOnlyDataBinding().build() confirmed with no method resolvers; no user input in expression argument"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the argument's origin could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `getRuleExpression()` in services/RuleService.java to confirm whether its return value originates from a user-editable config store"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/elinj-batch-*.md` file and merge them into a single `sast/elinj-results.md` and a canonical `sast/elinj-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/elinj-batch-1.md`, `sast/elinj-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/elinj-results.md` using this format:

```markdown
# EL Injection Analysis Results: [Project Name]

## Executive Summary
- Evaluation sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable `sast/elinj-results.json` following the schema below. Assign sequential `id` values (`elinj-1`, `elinj-2`, ...) across all findings, ordered by severity (critical first, then high, medium, low, info). Include NOT VULNERABLE findings only as `exploitability: unreachable`. Omit NEEDS MANUAL REVIEW findings (leave them in the `.md` only — their confidence is too low for automated aggregation):

```json
{
  "findings": [
    {
      "id": "elinj-1",
      "skill": "sast-elinj",
      "severity": "critical",
      "title": "SpEL injection via HTTP query parameter in /search endpoint",
      "description": "The HTTP query parameter 'filter' is passed directly to SpelExpressionParser.parseExpression() with a StandardEvaluationContext, which provides full Java class access. An attacker can evaluate T(java.lang.Runtime).getRuntime().exec('id') to achieve remote code execution.",
      "location": { "file": "src/main/java/com/example/SearchController.java", "line": 42, "column": 12 },
      "remediation": "Replace StandardEvaluationContext with SimpleEvaluationContext.forReadOnlyDataBinding().build() and build the expression from constants, passing user data only as named variables in the context.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    }
  ]
}
```

If no Vulnerable or Likely Vulnerable findings exist, write `{ "findings": [] }`.

6. After writing `sast/elinj-results.md` and `sast/elinj-results.json`, **delete all intermediate files**: `sast/elinj-recon.md` and all `sast/elinj-batch-*.md` files.

---

## chain_id Values

| chain_id | Meaning |
|---|---|
| `"code-injection-surface"` | Finding is part of a broader code-injection attack surface in the same application. Use when both `sast-elinj` and `sast-ssti` surface findings in the same codebase, or when EL injection co-exists with RCE findings from `sast-rce`. |
| `null` | Finding is standalone; no related chain. |

---

## Test Fixtures

The following patterns illustrate what the skill should and should not flag. Use them to validate Phase 2 reasoning.

**True Positive (TP) — must be flagged, `exploitability: reachable`, `severity: critical`**:
```java
// src/main/java/com/example/SearchController.java, line 42
@GetMapping("/search")
public Object search(@RequestParam String filter) {
    ExpressionParser parser = new SpelExpressionParser();
    StandardEvaluationContext ctx = new StandardEvaluationContext(dataService);
    return parser.parseExpression(filter).getValue(ctx);
    // filter = req param -> parser.parseExpression(filter) -> StandardEvaluationContext -> RCE
}
```

**True Negative (TN1) — constant expression, must NOT be flagged**:
```java
// Safe — expression string is a compile-time constant
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext ctx = new StandardEvaluationContext(user);
parser.parseExpression("user.name").getValue(ctx);
```

**True Negative (TN2) — `SimpleEvaluationContext` restricts method calls, must NOT be flagged as critical** (may be flagged as high/medium if user input reaches the expression for property traversal):
```java
SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
// forReadOnlyDataBinding() + no withMethodResolvers() -> no T(...) class access possible
// Only flag if user input reaches the expression string AND property leakage is a concern
parser.parseExpression(userInput).getValue(ctx, safeBean);
// If flagged: severity: high (property leak), exploitability: conditional, confidence: medium
```

**True Negative (TN3) — strict allowlist, must NOT be flagged as exploitable** (flag as `conditional` only if allowlist is weak or incomplete):
```java
private static final Set<String> ALLOWED = Set.of("order.total", "order.quantity");
if (!ALLOWED.contains(userExpr)) throw new IllegalArgumentException();
parser.parseExpression(userExpr).getValue(ctx);
// Allowlist is strict and covers complete expression — exploitability: unreachable
```

Only the TP is flagged reachable/critical. TN1 is not flagged. TN2 may be flagged conditional/high only if user input is confirmed to reach `userInput`. TN3 is flagged unreachable/medium if the allowlist is incomplete or the evaluator can navigate outside the allowed set.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 candidates per subagent**. If there are 1-3 candidates total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned candidates' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any dynamic (non-literal) variable used as the expression string argument to an EL/OGNL/SpEL/MVEL/JEXL evaluator API. Do not attempt to trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each site assigned to a batch, trace the dynamic expression argument back to its origin. If it comes from a user-controlled source without an effective sandbox or allowlist, the site is a real vulnerability.
- **The critical distinction is evaluator context vs. data context**: user input passed as a *data value* to `ctx.setVariable("userId", userId)` is safe — the expression string is constant. User input passed as *the expression string itself* to `parser.parseExpression(userId)` is dangerous.
- **`SimpleEvaluationContext` is not a complete fix**: it blocks `T(...)` type references and class access, but does not prevent property traversal. If the evaluated bean exposes sensitive properties (passwords, tokens), property traversal is still a concern. Flag these at high/medium rather than dismissing them.
- **Struts OGNL injection is historically severe**: CVE-2013-1966, CVE-2017-5638, and many subsequent CVEs share the same root cause — user input interpolated into OGNL expressions. Even on a patched Struts version, any programmatic `Ognl.getValue(userInput, ...)` call warrants scrutiny.
- **Second-order EL injection is easy to miss**: a "custom rule expression" feature may let users store SpEL/MVEL syntax in the database. When that stored expression is later loaded and evaluated server-side without sandboxing, it's EL injection. In Phase 2, treat database-read expression strings as potentially tainted.
- **Blocklist filtering is not a mitigation**: attempts to strip `T(`, `#`, `.class`, `getRuntime` from user input are bypassed via encoding, nested syntax, or alternative gadgets. Do not classify a finding as "Not Vulnerable" solely because filtering is present.
- **Do not confuse with SSTI**: FreeMarker, Velocity, Thymeleaf, Jinja2, Twig, EJS, Handlebars, ERB rendering calls are handled by `sast-ssti`. This skill covers only programmatic EL/OGNL/SpEL/MVEL/JEXL/simpleeval/asteval API calls.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Include evaluator-appropriate proof-of-concept payloads for all Vulnerable and Likely Vulnerable findings.
- Clean up intermediate files: delete `sast/elinj-recon.md` and all `sast/elinj-batch-*.md` files after the final `sast/elinj-results.md` and `sast/elinj-results.json` are written.
- Always write `sast/elinj-results.json` even when no findings exist (`{"findings": []}`), so the `sast-skills export` aggregator can verify the scan ran.
