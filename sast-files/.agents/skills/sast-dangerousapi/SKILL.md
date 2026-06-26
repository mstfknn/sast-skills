---
name: sast-dangerousapi
description: >-
  Inventory inherently dangerous API sinks — dynamic code evaluation (eval,
  Function, exec, compile), reflective class/method invocation, native-code
  bridges (JNI, ctypes, cffi), and process-spawning functions — regardless of
  proven taint, because every occurrence requires explicit human review.
  Covers JavaScript/Node, Python, Java, PHP, Ruby, .NET, and Go. Uses a
  three-phase approach: recon (find every dangerous sink), batched verify
  (taint analysis + severity calibration in parallel, 3 sinks each), and merge
  (consolidate into sast/dangerousapi-results.md + sast/dangerousapi-results.json).
  Maps to OWASP Web25 A05, CWE-95 / CWE-470.
version: 0.1.0
---

# Dangerous API Inventory (dangerousapi)

You are performing a focused security assessment to inventory every inherently dangerous API sink in a codebase. This skill uses a three-phase approach with subagents: **recon** (find all dangerous sink call sites), **batched verify** (taint analysis and severity calibration in parallel batches of 3), and **merge** (consolidate batch reports into `sast/dangerousapi-results.md` and `sast/dangerousapi-results.json`).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

**This is an inventory skill.** Every dangerous sink occurrence is recorded — even when the argument appears constant — because these APIs require human review as part of a secure code baseline. Constant-argument calls are downgraded to `confidence: low` / `severity: low` (informational), not dropped.

---

## What is a Dangerous API

A dangerous API is one where a misuse — or any use with attacker-controlled input — can result in arbitrary code execution, arbitrary class/method dispatch, native-library loading, or arbitrary OS command execution. The mere presence of these APIs in a codebase is a risk signal that demands review, because the line between "safe usage" and "exploitable usage" is easily crossed.

Categories covered by this skill:

- **Dynamic code evaluation**: `eval`, `new Function`, `exec`, `compile`, `vm.runInNewContext`, `ScriptEngine.eval`, `CSharpCodeProvider`
- **Reflective dispatch**: `Method.invoke`, `Class.forName`, `call_user_func`, `send`, `public_send`, `constantize`, `Activator.CreateInstance`, `Type.GetType`
- **Native-code bridges**: JNI `System.loadLibrary`, Python `ctypes.CDLL`, `cffi`, Ruby FFI
- **Dynamic module loading**: `require(userInput)`, `__import__(userInput)`, `importlib.import_module`, `plugin.Open`
- **Process spawning**: `child_process.exec`/`execSync` (JS string arg), `os.system`, `subprocess.Popen(shell=True)`, `Runtime.exec`, `os/exec.Command` (variable first arg), `Kernel.system`
- **PHP code execution**: `preg_replace` with `/e` modifier, `create_function`

### What this skill IS

- **CWE-95 (Eval Injection)**: Any call to `eval`/`exec`/`compile`/`Function` where the argument contains a variable, regardless of traceability to user input
- **CWE-470 (Reflection)**: Any use of reflective dispatch where the class/method name is a variable
- **Inventory findings** for constant-argument calls (informational — confirms the pattern exists and should be reviewed)
- **High/critical findings** when taint from user input to the sink argument is confirmed

### What this skill is NOT

Do not flag as dangerous API:

- `eval` called with a verified string literal: `eval("1 + 1")` — record as `confidence: low`, `severity: low` informational only
- `Class.forName` with a hard-coded class name: `Class.forName("com.example.MyClass")` — record as informational
- `subprocess.run(['ls', '-la'], shell=False)` — safe list-form with no user input; **skip entirely**
- `subprocess.Popen(['command', arg], shell=False)` where `arg` is a validated local variable — **skip entirely**
- Normal use of `send` on a fixed symbol in Ruby (e.g., `user.send(:save)`) — skip
- `os/exec.Command("git", "status")` in Go with all literal args — **skip entirely**

### Patterns that make a call safe (FP-killers)

When you observe these patterns, the risk is materially reduced — **but still record for inventory at reduced severity/confidence**:

1. **Allowlist before eval**: The argument is validated against a strict set of permitted values before reaching the sink.
2. **Compiled regex or operator map instead of eval**: A mapping of string keys to pre-compiled operations replaces dynamic evaluation.
3. **Factory pattern instead of reflection**: A registry maps string keys to known constructors.
4. **List-form subprocess**: `subprocess.run(["cmd", arg], shell=False)` with no user input in the list — **not flagged** (safe pattern, skip entirely).

---

## Vulnerable vs. Secure Examples

### Python — eval injection

```python
# VULNERABLE: user input reaches eval directly (critical)
@app.route('/calculate')
def calculate():
    expr = request.args.get('expr')
    result = eval(expr)                  # CWE-95: expr flows from HTTP query param
    return str(result)

# INFORMATIONAL: constant argument — still record, severity=low
config_version = eval("{'version': 1}")

# SECURE: replace eval with a safe operator dispatch
import operator
OPS = {'add': operator.add, 'sub': operator.sub, 'mul': operator.mul}
@app.route('/calculate')
def calculate():
    op = request.args.get('op')
    a = float(request.args.get('a'))
    b = float(request.args.get('b'))
    if op not in OPS:
        return abort(400)
    return str(OPS[op](a, b))
```

### Python — exec and compile

```python
# VULNERABLE: exec with user-controlled code string
def run_script(request):
    code = request.form.get('script')
    exec(code)                           # CWE-95: arbitrary code execution

# VULNERABLE: compile then eval with user input
def eval_expr(user_input):
    code = compile(user_input, '<string>', 'eval')
    return eval(code)

# VULNERABLE: subprocess.Popen with shell=True (process injection)
def run_cmd(command):
    proc = subprocess.Popen(command, shell=True)   # CWE-78
    return proc.wait()

# SECURE: list form, no shell
def run_cmd(args: list[str]):
    proc = subprocess.Popen(args, shell=False)
    return proc.wait()
```

### Python — dynamic import

```python
# VULNERABLE: user-controlled module name
def load_plugin(request):
    plugin_name = request.args.get('plugin')
    module = importlib.import_module(plugin_name)   # CWE-470: arbitrary module load
    return module.run()

# VULNERABLE: __import__ with user input
def get_module(name):
    return __import__(name)                          # CWE-470

# SECURE: allowlist of permitted modules
ALLOWED_PLUGINS = {'csv_exporter': 'plugins.csv_exporter',
                   'pdf_exporter': 'plugins.pdf_exporter'}
def load_plugin(request):
    key = request.args.get('plugin')
    if key not in ALLOWED_PLUGINS:
        return abort(400)
    module = importlib.import_module(ALLOWED_PLUGINS[key])
    return module.run()
```

### Python — ctypes native bridge

```python
# VULNERABLE: user-controlled library path
def load_native(request):
    lib_path = request.args.get('lib')
    lib = ctypes.CDLL(lib_path)           # CWE-470: arbitrary native code load
    lib.run()

# INFORMATIONAL: hard-coded path (record, severity=low)
ssl_lib = ctypes.CDLL('/usr/lib/libssl.so')
```

### Python — os.system

```python
# VULNERABLE: string interpolation into os.system
def convert(request):
    filename = request.args.get('filename')
    os.system(f"convert {filename} output.pdf")   # CWE-78: command injection

# SECURE: list form with validation
import re
ALLOWED_FILES_RE = re.compile(r'^[a-zA-Z0-9_\-]+\.pdf$')
def convert(request):
    filename = request.args.get('filename')
    if not ALLOWED_FILES_RE.match(filename):
        return abort(400)
    subprocess.run(['convert', filename, 'output.pdf'], shell=False, check=True)
```

### JavaScript/Node — eval and new Function

```javascript
// VULNERABLE: eval with user input (critical)
app.post('/eval', (req, res) => {
  const code = req.body.code;
  const result = eval(code);           // CWE-95
  res.json({ result });
});

// VULNERABLE: new Function from user input
app.get('/formula', (req, res) => {
  const formula = req.query.formula;
  const fn = new Function('x', formula);   // CWE-95
  res.json({ result: fn(42) });
});

// VULNERABLE: setTimeout with string argument (acts like eval)
app.get('/delay', (req, res) => {
  const code = req.query.code;
  setTimeout(code, 1000);              // CWE-95: string arg evaluated as JS
  res.send('ok');
});

// SECURE: pre-compiled expression map
const FORMULAS = {
  double: (x) => x * 2,
  square: (x) => x * x,
};
app.get('/formula', (req, res) => {
  const key = req.query.formula;
  if (!FORMULAS[key]) return res.status(400).json({ error: 'unknown formula' });
  res.json({ result: FORMULAS[key](42) });
});
```

### JavaScript/Node — require and child_process

```javascript
// VULNERABLE: require with user-controlled module name
app.get('/plugin', (req, res) => {
  const plugin = req.query.name;
  const mod = require(plugin);         // CWE-470: arbitrary module load
  res.json(mod.run());
});

// VULNERABLE: child_process.exec with string arg containing user input
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {  // CWE-78
    res.send(stdout);
  });
});

// VULNERABLE: execSync with template literal
const { execSync } = require('child_process');
function runTool(userArg) {
  return execSync(`tool --input ${userArg}`);    // CWE-78
}

// SECURE: execFile (array args, no shell)
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) return res.status(400).send('invalid');
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout);
  });
});
```

### JavaScript/Node — vm module

```javascript
// VULNERABLE: vm.runInNewContext with user input
const vm = require('vm');
app.post('/sandbox', (req, res) => {
  const code = req.body.code;
  const result = vm.runInNewContext(code, {});   // CWE-95: vm is NOT a security boundary
  res.json({ result });
});
// NOTE: vm.runInNewContext is not a sandbox — escape attacks are well-documented.
```

### Java — reflection and exec

```java
// VULNERABLE: Class.forName with user input (CWE-470)
@GetMapping("/load")
public ResponseEntity<?> loadClass(@RequestParam String className) throws Exception {
    Class<?> clazz = Class.forName(className);        // CWE-470
    Object instance = clazz.getDeclaredConstructor().newInstance();
    return ResponseEntity.ok(instance.toString());
}

// VULNERABLE: Method.invoke with user-supplied method name (CWE-470)
public Object invokeMethod(Object target, String methodName, Object[] args)
        throws Exception {
    Method method = target.getClass().getMethod(methodName);
    return method.invoke(target, args);               // CWE-470
}

// VULNERABLE: Runtime.exec with string concatenation (CWE-78)
public String runCommand(String userInput) throws Exception {
    Process p = Runtime.getRuntime().exec("tool " + userInput);
    return new String(p.getInputStream().readAllBytes());
}

// VULNERABLE: ScriptEngine.eval with user input (CWE-95)
ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
String code = request.getParameter("code");
engine.eval(code);                                    // CWE-95

// VULNERABLE: System.loadLibrary with variable name (JNI)
String libName = request.getParameter("lib");
System.loadLibrary(libName);                          // CWE-470

// SECURE: factory pattern for reflection
private static final Map<String, Supplier<Plugin>> REGISTRY = Map.of(
    "csv", CsvPlugin::new,
    "pdf", PdfPlugin::new
);
public Plugin loadPlugin(String key) {
    Supplier<Plugin> factory = REGISTRY.get(key);
    if (factory == null) throw new IllegalArgumentException("Unknown plugin: " + key);
    return factory.get();
}
```

### PHP — eval, preg_replace /e, call_user_func

```php
// VULNERABLE: eval with user input (CWE-95)
$code = $_GET['code'];
eval($code);

// VULNERABLE: preg_replace with /e modifier (deprecated but may exist in legacy code)
$pattern = $_GET['pattern'];
$replacement = $_GET['replacement'];
$result = preg_replace("/$pattern/e", $replacement, $subject);  // /e evaluates as PHP

// VULNERABLE: call_user_func with user-controlled callable
$func = $_GET['action'];
call_user_func($func, $arg);            // CWE-470

// VULNERABLE: call_user_func_array with user input
$method = $_POST['method'];
call_user_func_array([$obj, $method], $params);   // CWE-470

// VULNERABLE: create_function (eval wrapper)
$func = create_function('$x', $_GET['body']);   // CWE-95

// SECURE: allowlist of callable actions
const ALLOWED_ACTIONS = ['export_csv', 'export_pdf', 'export_json'];
$action = $_GET['action'];
if (!in_array($action, ALLOWED_ACTIONS, true)) {
    http_response_code(400);
    exit('Invalid action');
}
call_user_func($action, $data);
```

### Ruby — eval, send, constantize, system

```ruby
# VULNERABLE: eval with user input (CWE-95)
get '/calculate' do
  expr = params[:expr]
  eval(expr)                           # CWE-95
end

# VULNERABLE: send with user-controlled method name (CWE-470)
def dispatch(obj, method_name, args)
  obj.send(method_name, *args)         # CWE-470
end

# VULNERABLE: public_send with user input
user.public_send(params[:action])      # CWE-470

# VULNERABLE: constantize with user input (Rails)
klass = params[:class_name].constantize   # CWE-470
klass.new.run

# VULNERABLE: Kernel.system with user input (CWE-78)
filename = params[:file]
Kernel.system("process #{filename}")   # CWE-78

# SECURE: dispatch table instead of send
ACTIONS = {
  'activate' => ->(u) { u.activate! },
  'deactivate' => ->(u) { u.deactivate! },
}.freeze
action = ACTIONS[params[:action]]
return render status: 400 unless action
action.call(current_user)
```

### .NET — CSharpCodeProvider, Assembly.Load, Activator.CreateInstance

```csharp
// VULNERABLE: compile and execute user code (CWE-95)
using Microsoft.CSharp;
var provider = new CSharpCodeProvider();
var result = provider.CompileAssemblyFromSource(parameters, userCode);
var instance = result.CompiledAssembly.CreateInstance("UserClass");

// VULNERABLE: Assembly.Load with user-supplied bytes (CWE-470)
byte[] assemblyBytes = Convert.FromBase64String(Request.Form["assembly"]);
Assembly asm = Assembly.Load(assemblyBytes);   // CWE-470

// VULNERABLE: Activator.CreateInstance with Type.GetType on user input (CWE-470)
string typeName = Request.QueryString["type"];
Type t = Type.GetType(typeName);              // CWE-470
object instance = Activator.CreateInstance(t);

// SECURE: plugin registry with known types
private static readonly Dictionary<string, Type> _registry = new()
{
    ["csv"] = typeof(CsvExporter),
    ["pdf"] = typeof(PdfExporter),
};
public IExporter Create(string key)
{
    if (!_registry.TryGetValue(key, out var type))
        throw new ArgumentException($"Unknown exporter: {key}");
    return (IExporter)Activator.CreateInstance(type)!;
}
```

### Go — plugin.Open and os/exec.Command

```go
// VULNERABLE: plugin.Open with user-supplied path (CWE-470)
func loadPlugin(w http.ResponseWriter, r *http.Request) {
    pluginPath := r.URL.Query().Get("plugin")
    p, err := plugin.Open(pluginPath)   // CWE-470: arbitrary .so load
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    sym, _ := p.Lookup("Run")
    sym.(func())()
}

// VULNERABLE: exec.Command with variable first arg (CWE-78)
func runTool(w http.ResponseWriter, r *http.Request) {
    toolName := r.URL.Query().Get("tool")
    cmd := exec.Command(toolName, "--help")   // CWE-78: first arg is user-controlled
    out, _ := cmd.Output()
    w.Write(out)
}

// SECURE: allowlist of permitted tools
var allowedTools = map[string]bool{
    "jq": true,
    "yq": true,
}
func runTool(w http.ResponseWriter, r *http.Request) {
    toolName := r.URL.Query().Get("tool")
    if !allowedTools[toolName] {
        http.Error(w, "tool not permitted", http.StatusBadRequest)
        return
    }
    cmd := exec.Command(toolName, "--help")
    out, _ := cmd.Output()
    w.Write(out)
}
```

---

## Severity and Exploitability Matrix

| Scenario | severity | exploitability | confidence |
|---|---|---|---|
| User input flows directly to sink with no allowlist or escaping | critical | reachable | high |
| User input flows through intermediate variable/function to sink | high | reachable | high |
| Sink argument origin opaque (helper function, config, complex flow) | high | unknown | medium |
| Sink argument constrained by allowlist before reaching sink | medium | conditional | medium |
| Sink argument appears to be a constant/literal | low | unreachable | low |

---

## Chain IDs

This skill participates in two cross-skill chains:

| chain_id | Description |
|---|---|
| `dangerousapi-rce` | Dangerous API with confirmed user-input taint pairs with sast-rce findings on the same sink site to form a confirmed RCE chain |
| `eval-proto` | JavaScript `eval` or `new Function` sink in a context where prototype pollution (sast-prototype) can influence object properties flowing into the sink argument |

Set `chain_id` to one of the above when the merge phase has evidence from a complementary scan (`sast/rce-results.json` or `sast/prototype-results.json`) confirming the chain. Otherwise set to `null`.

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Every Dangerous Sink Call Site

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a dangerous API sink is called. Record ALL occurrences including those with constant arguments — this is an inventory skill. Write results to `sast/dangerousapi-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, language(s), frameworks, and module structure.
>
> **What to search for — dangerous API sinks by language**:
>
> Scan ALL source files for calls to the following sinks. A sink is any call matching the patterns below, regardless of what its argument is. Use grep/search broadly:
>
> **JavaScript / Node.js**:
>
> 1. `eval(` — any call to the global `eval` function
> 2. `new Function(` — any `Function` constructor call
> 3. `setTimeout(` and `setInterval(` — where the first argument is a variable or string expression (not an arrow function or named function reference); string-arg `setTimeout`/`setInterval` evaluates code like `eval`
> 4. `vm.runInNewContext(`, `vm.runInContext(`, `vm.runInThisContext(`, `vm.Script(` — Node.js vm module
> 5. `require(` — where the argument is a variable rather than a string literal: `require(pluginName)`, `require(userInput)`, `require(config.module)`
> 6. `child_process.exec(`, `execSync(`, `.exec(` — any invocation where the first argument is not a pure string literal (i.e., contains template literals, string concatenation, or a variable)
>
> **Python**:
>
> 1. `eval(` — any call
> 2. `exec(` — any call
> 3. `compile(` — any call
> 4. `__import__(` — any call where the argument is not a string literal
> 5. `importlib.import_module(` — any call
> 6. `ctypes.CDLL(`, `ctypes.cdll.`, `ctypes.WinDLL(`, `ctypes.LibraryLoader(` — any call
> 7. `subprocess.Popen(` with `shell=True` — grep for `Popen(` and then check for `shell=True` in the same call
> 8. `os.system(` — any call
>
> **Java**:
>
> 1. `.invoke(` after `Method` — `Method.invoke(`, `method.invoke(`
> 2. `Class.forName(` — any call
> 3. `Runtime.getRuntime().exec(`, `process.exec(` — any call
> 4. `ScriptEngine` `.eval(` — any `ScriptEngine` method call to `eval`
> 5. `System.loadLibrary(` — where the argument is not a string literal
>
> **PHP**:
>
> 1. `eval(` — any call
> 2. `preg_replace(` — any call; will filter for `/e` modifier in Phase 2
> 3. `call_user_func(` — any call
> 4. `call_user_func_array(` — any call
> 5. `create_function(` — any call
>
> **Ruby**:
>
> 1. `eval(` or `Kernel.eval(` — any call
> 2. `.send(` — where the first argument is a variable: `obj.send(method_name, ...)`, `obj.send(params[:action])`
> 3. `.public_send(` — same as send
> 4. `.constantize` — any Rails call (often chained: `params[:class].constantize`)
> 5. `Kernel.system(`, `system(`, backtick expressions `` `...` `` — any call where the argument contains a variable
>
> **.NET (C#)**:
>
> 1. `CSharpCodeProvider` — any instantiation or method call
> 2. `Assembly.Load(`, `Assembly.LoadFrom(`, `Assembly.LoadFile(` — where the argument is a variable (not a string literal path)
> 3. `Type.GetType(` — where the argument is a variable
> 4. `Activator.CreateInstance(` — where the type argument comes from a variable
>
> **Go**:
>
> 1. `plugin.Open(` — any call where the argument is a variable
> 2. `exec.Command(` — where the FIRST argument (the binary) is a variable, not a string literal
>
> **What to skip entirely (safe patterns — do not record)**:
>
> - `subprocess.run(['cmd', arg], shell=False)` or `subprocess.Popen(['cmd', arg], shell=False)` — list-form with shell=False is safe; skip
> - `exec.Command("git", "status")` — Go call with all string-literal args; skip
> - `obj.send(:save)` — Ruby send with a symbol literal; skip
> - `setTimeout(() => doThing(), 1000)` — callback form is not eval; skip
>
> Note: `Class.forName("com.example.FixedClass")` with a hard-coded string literal should still be recorded as an informational entry (argument-type: constant-literal) — do not skip it.
>
> **Output format** — write to `sast/dangerousapi-recon.md`:
>
> ```markdown
> # Dangerous API Recon: [Project Name]
>
> ## Summary
> Found [N] dangerous API sink call sites.
>
> ## Sink Call Sites
>
> ### 1. [Descriptive name — e.g., "eval() in calculate endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name, route, or class method]
> - **Sink type**: [eval / exec / compile / new Function / vm.runInNewContext / require-dynamic / child_process.exec / ctypes.CDLL / subprocess.Popen-shell / os.system / Method.invoke / Class.forName / Runtime.exec / ScriptEngine.eval / System.loadLibrary / call_user_func / preg_replace-e / create_function / Ruby-eval / Ruby-send / Ruby-constantize / Assembly.Load / Activator.CreateInstance / plugin.Open / exec.Command-variable]
> - **Argument type**: [variable / template-literal / string-concat / constant-literal / opaque-helper]
> - **Code snippet**:
>   ```
>   [the sink call with surrounding context, ~5 lines]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/dangerousapi-recon.md`. If the recon found **zero sink call sites** (the summary reports "Found 0" or the "Sink Call Sites" section is empty or absent), **skip Phase 2 entirely**. Write the following to `sast/dangerousapi-results.md` and `sast/dangerousapi-results.json`, then stop:

```markdown
# Dangerous API Analysis Results

No dangerous API sinks found.
```

```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one sink call site.

### Phase 2: Verify — Taint Analysis and Severity Calibration (Batched)

After Phase 1 completes, read `sast/dangerousapi-recon.md` and split the sink call sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent performs taint analysis for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/dangerousapi-recon.md` and count the numbered site sections under "Sink Call Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/dangerousapi-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language(s) from `sast/architecture.md` and include **only the matching examples** from the "Vulnerable vs. Secure Examples" section above in each subagent's instructions (replace `[TECH-STACK EXAMPLES]` below).

Give each batch subagent the following instructions (substitute batch-specific values):

> **Goal**: For each assigned dangerous API sink, perform taint analysis and severity calibration. Determine whether the sink argument is derived from user-controllable input. Even when the argument is constant or origin is opaque, record the finding (downgraded appropriately). Write results to `sast/dangerousapi-batch-[N].md`.
>
> **Your assigned sink call sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, authentication layers, and data flow.
>
> **This is an inventory skill — every sink is reported.** Classification affects `severity`, `exploitability`, and `confidence`, but nothing is dropped.
>
> **Taint analysis — trace the sink argument backwards to its origin**:
>
> 1. **Direct user input** — the argument is assigned directly from a request source:
>    - HTTP query params: `request.args.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `c.Query("x")`
>    - Request body / form fields: `request.form.get(...)`, `req.body.x`, `$_POST['x']`
>    - Path parameters: `request.path_params['id']`, `req.params.id`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.cookies.get(...)`, `req.cookies.x`
>
> 2. **Indirect user input** — derived from user input through transformations or intermediate variables:
>    - Assigned from a function return value → trace that function's inputs
>    - Passed through layers of helpers or middleware → follow the call chain
>    - Read from a DB field that was originally stored from user input → second-order
>    - Conditionally assigned — check all branches
>
> 3. **Opaque origin** — cannot determine with confidence from static analysis alone:
>    - Function signature accepts a parameter from an external caller
>    - Config or environment value that may be influenced externally
>    - Value loaded from a file or DB without clear upstream source
>
> 4. **Constant / literal origin** — the argument is demonstrably a hard-coded value:
>    - String literal: `eval("1 + 1")`, `Class.forName("com.example.Fixed")`
>    - A named constant defined in the same file with a literal value
>    - Server-side config value with no external write path
>
> **FP-killers — check even when taint is present**:
>
> - **Allowlist before sink**: Does code validate the argument against a strict set of permitted values before calling the sink? If yes → `exploitability: conditional`, `severity: medium`.
> - **Operator/factory dispatch instead**: Is there a map/switch that resolves the argument to a pre-compiled operation before the dangerous sink is reached? If so, the sink may not be reachable.
> - **`php preg_replace` without `/e` modifier**: `preg_replace` is not dangerous unless the pattern ends with `e`; if the `/e` modifier is not present, classify this site as NOT a finding and omit it from results.
> - **Go `exec.Command` with all string-literal args**: If the first argument is a string literal (e.g., `exec.Command("git", ...)`), record as informational only (severity: low, confidence: low).
>
> **Classification rules**:
>
> | Scenario | severity | exploitability | confidence |
> |---|---|---|---|
> | Direct user input → sink, no allowlist | critical | reachable | high |
> | Indirect user input (traced) → sink | high | reachable | high |
> | Opaque origin — cannot trace | high | unknown | medium |
> | Allowlist constrains argument before sink | medium | conditional | medium |
> | Constant / literal argument | low | unreachable | low |
>
> **Chain IDs**:
> - If `sast/rce-results.json` exists and contains a finding at the same file+line, set `chain_id: "dangerousapi-rce"`.
> - If `sast/prototype-results.json` exists and this is a JS `eval`/`new Function` site where an object property flows into the argument, set `chain_id: "eval-proto"`.
> - Otherwise set `chain_id: null`.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Output format** — write to `sast/dangerousapi-batch-[N].md`:
>
> ```markdown
> # Dangerous API Batch [N] Results
>
> ## Findings
>
> ### [CRITICAL] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [eval / exec / etc.]
> - **Issue**: [e.g., "HTTP query param `expr` flows directly into eval() call"]
> - **Taint trace**: [Step-by-step from entry point to the sink argument]
> - **Impact**: [What an attacker can do — e.g., arbitrary Python code execution as the web process user]
> - **Remediation**: [Specific fix — operator map, subprocess list-form, factory pattern, etc.]
> - **severity**: critical
> - **exploitability**: reachable
> - **confidence**: high
> - **chain_id**: [dangerousapi-rce | eval-proto | null]
>
> ### [HIGH] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink type]
> - **Issue**: [e.g., "Indirect flow through helper function to exec()"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps with "?"]
> - **Impact**: [likely impact]
> - **Remediation**: [specific fix]
> - **severity**: high
> - **exploitability**: reachable | unknown
> - **confidence**: high | medium
> - **chain_id**: [or null]
>
> ### [MEDIUM] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink type]
> - **Issue**: [e.g., "Allowlist present but incomplete — only 3 of 10 operators validated"]
> - **Taint trace**: [trace]
> - **Concern**: [why it remains a risk despite mitigations]
> - **Remediation**: [tighten the allowlist or replace with factory pattern]
> - **severity**: medium
> - **exploitability**: conditional
> - **confidence**: medium
> - **chain_id**: null
>
> ### [LOW / INFORMATIONAL] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink type]
> - **Issue**: [e.g., "Constant literal argument — informational inventory only"]
> - **Argument value**: [the literal value or constant name]
> - **Remediation**: [Document and confirm this is intentional; consider replacing with a safer pattern]
> - **severity**: low
> - **exploitability**: unreachable
> - **confidence**: low
> - **chain_id**: null
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/dangerousapi-batch-*.md` file and merge them into `sast/dangerousapi-results.md` (human-readable) and `sast/dangerousapi-results.json` (canonical machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/dangerousapi-batch-1.md`, `sast/dangerousapi-batch-2.md`, ... files.
2. Collect all findings from every batch file.
3. Count totals for the executive summary: sinks analyzed (total from recon), by severity (critical / high / medium / low).
4. Write `sast/dangerousapi-results.md` using this format:

```markdown
# Dangerous API Analysis Results: [Project Name]

## Executive Summary
- Sinks analyzed: [total from recon]
- Critical: [N]
- High: [N]
- Medium: [N]
- Low / Informational: [N]

## Findings

[All findings from all batches, ordered: Critical first, then High, then Medium, then Low/Informational.
 Preserve every field from the batch results exactly as written.]
```

5. Write `sast/dangerousapi-results.json` using the canonical schema. Assign sequential IDs starting from `dangerousapi-001`. Example:

```json
{
  "findings": [
    {
      "id": "dangerousapi-001",
      "skill": "sast-dangerousapi",
      "severity": "critical",
      "title": "eval() called with user-supplied HTTP query parameter",
      "description": "The /calculate endpoint reads the 'expr' query parameter directly and passes it to Python's eval() without any sanitization or allowlist. An attacker can execute arbitrary Python code as the web process user, enabling full server compromise.",
      "location": { "file": "app/routes/calculator.py", "line": 14, "column": 18 },
      "remediation": "Replace eval() with a pre-compiled operator dispatch map. Define ALLOWED_OPS = {'add': operator.add, ...} and resolve the operation by key lookup, rejecting unknown keys with HTTP 400.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "dangerousapi-rce"
    },
    {
      "id": "dangerousapi-002",
      "skill": "sast-dangerousapi",
      "severity": "low",
      "title": "eval() called with hard-coded constant string (informational)",
      "description": "eval() is called with a constant string literal. No taint path exists. Recorded for inventory — the pattern should be replaced with ast.literal_eval() or a direct dict literal.",
      "location": { "file": "app/config.py", "line": 7, "column": 22 },
      "remediation": "Replace eval() with ast.literal_eval() for safe literal parsing, or use a direct Python dict literal.",
      "exploitability": "unreachable",
      "confidence": "low",
      "chain_id": null
    }
  ]
}
```

If no findings exist (recon returned zero), write:

```json
{
  "findings": []
}
```

6. After writing both output files, **delete all intermediate files**: `sast/dangerousapi-recon.md` and all `sast/dangerousapi-batch-*.md` files.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 sink sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **This is an inventory skill**: every dangerous sink occurrence is reported. Do not drop findings because the argument looks constant — downgrade severity/confidence instead.
- **`preg_replace` exception**: The recon phase casts a wide net on `preg_replace`. In Phase 2, discard any `preg_replace` call that does NOT have the `/e` modifier in its pattern string — it is not a dangerous API invocation and should not appear in results.
- **subprocess/exec list-form is safe**: `subprocess.Popen(args_list, shell=False)` and `exec.Command("literal", ...)` are not flagged. If one slips through recon, classify as not a finding and omit from results.
- **vm.runInNewContext is NOT a sandbox**: Node.js `vm` module is explicitly not a security boundary. Well-known escapes exist. Always flag `vm.runInNewContext` as at least `high` severity, even with an empty sandbox object.
- **Second-order taint**: A method name, class name, or code string read from the database may have been written there by a user. Trace back to the write path to determine whether it was user-supplied.
- When in doubt, classify as `confidence: medium` / `exploitability: unknown` rather than dropping the finding.
- Check `sast/rce-results.json` and `sast/prototype-results.json` (if they exist) for chain opportunities during merge — set `chain_id` appropriately.
- Clean up all intermediate files: delete `sast/dangerousapi-recon.md` and all `sast/dangerousapi-batch-*.md` after `sast/dangerousapi-results.md` and `sast/dangerousapi-results.json` are written.
