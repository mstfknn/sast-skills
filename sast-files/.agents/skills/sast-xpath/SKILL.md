---
name: sast-xpath
description: >-
  Detect XPath injection vulnerabilities in a codebase using a three-phase approach:
  recon (find unsafe XPath expression construction sites), batched verify (trace user input
  to those sites in parallel subagents, 3 sites each), and merge (consolidate batch
  results). Covers string concatenation, f-strings, format strings, and interpolated
  XPath expressions across Java, .NET, Python, PHP, and Ruby. Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/xpath-results.md. Use when asked to
  find XPath injection or XML query injection bugs.
version: 0.1.0
---

# XPath Injection Detection

You are performing a focused security assessment to find XPath injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find vulnerable XPath expression construction sites), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is XPath Injection

XPath injection occurs when user-supplied input is incorporated into an XPath expression through string concatenation or interpolation rather than parameterised variable binding. An attacker who can inject into an XPath string can alter query logic, bypass authentication (when XPath is used to look up users or credentials), extract arbitrary nodes from XML documents, and sometimes enumerate the full document structure through boolean-blind techniques analogous to SQL blind injection.

The core pattern: *unvalidated, unparameterised user input reaches an XPath evaluation call.*

### What XPath Injection IS

- Concatenating user input directly into an XPath string: `"//user[name='" + req.getParameter("user") + "']"`
- Using f-strings or format strings to build XPath: `etree.XPath(f"//item[@id='{user_id}']")`
- Using `%` formatting to build XPath: `doc.xpath("//user[login='%s']" % username)`
- Interpolating a Ruby string into Nokogiri: `doc.xpath("//account[name='#{params[:name]}']")`
- PHP concatenating user input: `$xpath->query("//users/user[name='" . $_GET['name'] . "']")`
- Building an XPath string from components where one component is user-controlled, even via intermediate variables

### What XPath Injection is NOT

Do not flag these as XPath injection:

- **Constant XPath expressions**: expressions that contain no dynamic parts at all (`"//users/user[@active='1']"`)
- **Parameterised variable binding**: Java `XPathVariableResolver`, .NET `XsltContext` variable binding, or similar APIs where the XPath string itself contains the variable placeholder and user data is bound as a typed value — not concatenated
- **Strictly integer-validated input**: a path segment built from `int(user_input)` where only the decimal-integer value can flow into a purely numeric context (e.g. `//item[@id=42]` where `42` is produced by a strict integer cast and no quoting or operator context exists around it)
- **Server-side constants that look dynamic**: values read from application config files, hard-coded enum maps, or values chosen by server-side logic with no user-supplied component
- **IDOR on XPath results**: the XPath query is safe but returns data from another user — that is an access-control issue, not injection
- **XSS via XML**: data extracted from XML is rendered unescaped — that is XSS, not XPath injection

### Patterns That Prevent XPath Injection

When you see these patterns, the code is likely **not vulnerable**:

**1. Java — XPathVariableResolver (parameterised binding)**
```java
// SECURE: user data is bound as a typed variable, not concatenated into the expression
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.setXPathVariableResolver(varName -> {
    if ("username".equals(varName.getLocalPart())) return userInput;
    return null;
});
// The XPath string itself contains $username — no user data in the string
XPathExpression expr = xpath.compile("//user[name=$username]");
NodeList result = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
```

**2. .NET — XsltContext variable binding**
```csharp
// SECURE: custom XsltContext resolves $user variable from a typed binding
XPathNavigator nav = doc.CreateNavigator();
XPathExpression expr = nav.Compile("//user[name=$user]");
CustomXsltContext ctx = new CustomXsltContext();
ctx.AddVariable("user", userInput);
expr.SetContext(ctx);
XPathNodeIterator iter = nav.Select(expr);
```

**3. Strict integer validation before interpolation**
```python
# SECURE: only when the value is purely numeric and there is no quoting context
item_id = int(request.args.get("id"))  # raises ValueError if non-integer
result = doc.xpath(f"//item[@id={item_id}]")
# Still prefer the variable-binding approach; integer casting is fragile mitigation
```

**4. Allowlist validation for field selectors**
```python
# SECURE: field name is validated against a hardcoded allowlist before use
ALLOWED_FIELDS = {"name", "email", "department"}
field = request.args.get("field")
if field not in ALLOWED_FIELDS:
    raise ValueError("Invalid field")
results = doc.xpath(f"//user[{field}=$val]", val=safe_value)
```

---

## Vulnerable vs. Secure Examples

### Java — javax.xml.xpath

```java
// VULNERABLE: string concatenation of request parameter into XPath
@GetMapping("/search")
public List<String> searchUsers(@RequestParam String username, Document doc) throws Exception {
    XPath xpath = XPathFactory.newInstance().newXPath();
    // Attacker input: ' or '1'='1  ->  selects ALL users
    String expression = "//user[name='" + username + "']";
    NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
    return extractNames(nodes);
}

// SECURE: XPathVariableResolver -- user data never enters the expression string
@GetMapping("/search")
public List<String> searchUsers(@RequestParam String userInput, Document doc) throws Exception {
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.setXPathVariableResolver(varName -> {
        if ("username".equals(varName.getLocalPart())) return userInput;
        return null;
    });
    XPathExpression expr = xpath.compile("//user[name=$username]");
    NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
    return extractNames(nodes);
}
```

### Java — compiled XPathExpression (authentication bypass)

```java
// VULNERABLE: compile() is called with a dynamically built string
public boolean authenticate(String user, String pass, Document store) throws Exception {
    XPath xpath = XPathFactory.newInstance().newXPath();
    // Payload: ' or '1'='1' or ''='  bypasses the password check entirely
    XPathExpression expr = xpath.compile(
        "//accounts/user[login='" + user + "' and password='" + pass + "']"
    );
    NodeList matches = (NodeList) expr.evaluate(store, XPathConstants.NODESET);
    return matches.getLength() > 0;
}

// SECURE: bind via resolver; expression string is a compile-time constant
public boolean authenticate(String user, String pass, Document store) throws Exception {
    XPath xpath = XPathFactory.newInstance().newXPath();
    xpath.setXPathVariableResolver(varName -> {
        return switch (varName.getLocalPart()) {
            case "user" -> user;
            case "pass" -> pass;
            default -> null;
        };
    });
    XPathExpression expr = xpath.compile("//accounts/user[login=$user and password=$pass]");
    NodeList matches = (NodeList) expr.evaluate(store, XPathConstants.NODESET);
    return matches.getLength() > 0;
}
```

### .NET — XPathNavigator / XmlNode

```csharp
// VULNERABLE: XPathNavigator.Select with a concatenated string
public IEnumerable<string> GetRoles(string username, XmlDocument doc) {
    XPathNavigator nav = doc.CreateNavigator();
    // Attacker: admin' or '1'='1  ->  returns all roles
    XPathNodeIterator iter = nav.Select($"//user[@name='{username}']/role");
    while (iter.MoveNext()) yield return iter.Current.Value;
}

// VULNERABLE: XmlNode.SelectNodes with string interpolation
public XmlNodeList FindUser(string login, XmlDocument doc) {
    return doc.SelectNodes($"//users/user[login='{login}']");
}

// VULNERABLE: XmlNode.SelectSingleNode with concatenation
public XmlNode GetAccount(string id, XmlDocument doc) {
    return doc.SelectSingleNode("//accounts/account[@id='" + id + "']");
}

// SECURE .NET: use XsltContext for variable resolution
public XPathNodeIterator FindUserSafe(string login, XmlDocument doc) {
    XPathNavigator nav = doc.CreateNavigator();
    XPathExpression expr = nav.Compile("//users/user[login=$login]");
    CustomXsltContext ctx = new CustomXsltContext();
    ctx.AddVariable("login", login);
    expr.SetContext(ctx);
    return nav.Select(expr);
}
```

### Python — lxml

```python
# VULNERABLE: f-string inside lxml xpath() call
from lxml import etree
from flask import request, jsonify

@app.route('/lookup')
def lookup():
    username = request.args.get('user')
    tree = etree.parse('users.xml')
    # Attacker: ' or '1'='1' or ''='  -> leaks all user nodes
    results = tree.xpath(f"//user[name='{username}']")
    return jsonify([r.text for r in results])

# VULNERABLE: % formatting
@app.route('/lookup2')
def lookup2():
    username = request.args.get('user')
    tree = etree.parse('users.xml')
    results = tree.xpath("//user[name='%s']" % username)
    return jsonify([r.text for r in results])

# VULNERABLE: lxml XPath constructor with f-string
def compile_query(field: str) -> etree.XPath:
    return etree.XPath(f"//record[@type='{field}']")

# SECURE: lxml variable binding via keyword arguments
@app.route('/lookup')
def lookup_safe():
    username = request.args.get('user')
    tree = etree.parse('users.xml')
    # Variables are passed as keyword arguments; the expression string is a constant
    results = tree.xpath("//user[name=$uname]", uname=username)
    return jsonify([r.text for r in results])
```

### Python — ElementTree (stdlib)

```python
# NOTE: xml.etree.ElementTree is vulnerable to XXE and billion-laughs attacks by default.
# Use defusedxml.ElementTree as a drop-in replacement when parsing untrusted XML.
import defusedxml.ElementTree as ET  # pip install defusedxml
from flask import request, abort, jsonify

# VULNERABLE: string concat in ElementTree find/findall (no parameterisation support)
@app.route('/user')
def get_user():
    uid = request.args.get('id')
    root = ET.parse('data.xml').getroot()
    # ElementTree has no variable binding; the only safe approach is strict validation
    user = root.find(f"./user[@id='{uid}']")
    return user.text if user is not None else 'not found'

# VULNERABLE: findall with format string
@app.route('/items')
def get_items():
    category = request.args.get('cat')
    root = ET.parse('catalog.xml').getroot()
    items = root.findall("./item[category='%s']" % category)
    return jsonify([i.text for i in items])

# SECURE: strict integer cast (weak but common for ID lookups)
@app.route('/user')
def get_user_safe():
    try:
        uid = int(request.args.get('id', ''))
    except ValueError:
        abort(400)
    root = ET.parse('data.xml').getroot()
    # No quoting context around the integer predicate — injection is blocked
    # but this is still fragile; prefer switching to lxml for variable binding
    user = root.find(f"./user[@id='{uid}']")
    return user.text if user is not None else 'not found'
    # Best practice: switch to lxml + xpath("...$x...", x=val) variable binding
    # and use defusedxml or lxml's resolver restrictions for the parser itself
```

### PHP — DOMXPath

```php
// VULNERABLE: DOMXPath::query with concatenated input
function findUser(string $name): ?DOMNode {
    $doc = new DOMDocument();
    $doc->load('users.xml');
    $xpath = new DOMXPath($doc);
    // Attacker: ' or '1'='1' or ''='  -> selects all users
    $results = $xpath->query("//user[name='" . $name . "']");
    return $results->item(0);
}

// VULNERABLE: DOMXPath::evaluate with interpolation
function getUserEmail(string $login): string {
    $doc = new DOMDocument();
    $doc->load('accounts.xml');
    $xpath = new DOMXPath($doc);
    return $xpath->evaluate("string(//account[login='{$login}']/email)");
}

// VULNERABLE: SimpleXMLElement xpath() with concatenation
function checkAccess(string $role): bool {
    $xml = simplexml_load_file('permissions.xml');
    $nodes = $xml->xpath("//permission[role='" . $role . "' and @active='1']");
    return count($nodes) > 0;
}

// SECURE: PHP has no native XPath variable binding; use strict allowlist
function findUserSafe(string $name): ?DOMNode {
    $allowed = ['alice', 'bob', 'carol'];
    if (!in_array($name, $allowed, true)) {
        throw new InvalidArgumentException('Unknown user');
    }
    $doc = new DOMDocument();
    $doc->load('users.xml');
    $xpath = new DOMXPath($doc);
    // Safe only because $name is guaranteed to be in the allowlist
    return $xpath->query("//user[name='" . $name . "']")->item(0);
}
```

### Ruby — Nokogiri

```ruby
# VULNERABLE: string interpolation in Nokogiri xpath()
get '/search' do
  username = params[:name]
  doc = Nokogiri::XML(File.read('users.xml'))
  # Attacker: ' or '1'='1' or ''='  -> returns all nodes
  nodes = doc.xpath("//user[name='#{username}']")
  nodes.map(&:text).to_json
end

# VULNERABLE: xpath() with concatenation
get '/account' do
  account_id = params[:id]
  doc = Nokogiri::XML(File.read('accounts.xml'))
  result = doc.xpath("//account[@id='" + account_id + "']")
  result.first&.text
end

# SECURE: Nokogiri variable binding (Nokogiri >= 1.6)
get '/search' do
  username = params[:name]
  doc = Nokogiri::XML(File.read('users.xml'))
  # Variable binding -- the expression string is a constant
  nodes = doc.xpath('//user[name=$name]', nil, name: username)
  nodes.map(&:text).to_json
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Vulnerable XPath Construction Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where an XPath expression is constructed in a vulnerable way — using string concatenation, interpolation, or formatting with any variable (regardless of where that variable comes from). Write results to `sast/xpath-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, XML processing libraries, and XPath evaluation patterns.
>
> **What to search for — vulnerable XPath construction patterns**:
>
> Look for XPath evaluation calls where the expression string argument is built dynamically rather than being a static string with parameterised variable placeholders. Flag ANY dynamic variable embedded into the expression — you are not yet tracing whether the variable is user-controlled; that is Phase 2's job.
>
> 1. **String concatenation into an XPath evaluation call**:
>    - Java: `xpath.evaluate("//user[name='" + var + "']", doc, XPathConstants.NODESET)`
>    - Java: `xpath.compile("//accounts/user[login='" + user + "']")`
>    - .NET: `nav.Select("//user[@id='" + id + "']")`
>    - .NET: `doc.SelectNodes("//user[name='" + name + "']")`
>    - .NET: `node.SelectSingleNode("//item[id='" + itemId + "']")`
>    - PHP: `$xpath->query("//user[name='" . $name . "']")`
>    - PHP: `$xpath->evaluate("string(//account[login='" . $login . "'])")`
>    - PHP: `$xml->xpath("//item[id='" . $id . "']")`
>    - Ruby: `doc.xpath("//user[name='" + username + "']")`
>
> 2. **F-strings / string interpolation used as an XPath argument**:
>    - Python (lxml): `tree.xpath(f"//user[name='{var}']")`
>    - Python (lxml): `element.xpath(f"//item[@id='{uid}']")`
>    - Python (lxml): `etree.XPath(f"//record[@type='{field}']")`
>    - Python (ElementTree): `root.find(f"./user[@id='{var}']")` — flag whether `xml.etree.ElementTree` or `defusedxml.ElementTree` is in use; stdlib ET is also XXE-vulnerable
>    - Python (ElementTree): `root.findall(f"./item[name='{var}']")`
>    - C# (string interpolation): `nav.Select($"//user[@name='{username}']")`
>    - C# (string interpolation): `doc.SelectNodes($"//users/user[login='{login}']")`
>    - PHP: `$xpath->evaluate("string(//account[login='{$login}']/email)")`
>    - Ruby: `doc.xpath("//user[name='#{params[:name]}']")`
>
> 3. **String formatting functions used to build the XPath**:
>    - Python: `tree.xpath("//user[name='%s']" % var)`
>    - Python: `tree.xpath("//user[name='{}']".format(var))`
>    - Java: `String.format("//user[name='%s']", var)` passed to xpath.evaluate
>    - PHP: `sprintf("//user[name='%s']", $var)` passed to $xpath->query
>    - Ruby: `doc.xpath("//user[name='%s']" % username)`
>
> 4. **Multi-step construction** — the XPath string is built before the call and then passed to evaluation:
>    - Variable assigned a concatenated XPath string, then passed to the evaluation function in a separate statement
>    - `String expr = "//user[id=" + userId + "]"; xpath.evaluate(expr, doc, ...)`
>    - `query = "//product[@sku='" + sku + "']"; results = nav.Select(query)`
>    - `$expr = "//item[@id='" . $id . "']"; $xpath->query($expr)`
>
> **What to skip** (these are safe construction patterns — do not flag):
> - Fully static XPath strings with no dynamic parts: `xpath.evaluate("//users/user[@active='1']", doc, XPathConstants.NODESET)`
> - Java XPath with `XPathVariableResolver` where the expression uses `$varname` placeholders and user data is bound via the resolver, not concatenated into the string
> - lxml `.xpath()` calls where user data is passed as a **keyword argument** (variable binding), not embedded in the expression string: `tree.xpath("//user[name=$uname]", uname=username)`
> - Nokogiri `.xpath()` calls with variable bindings: `doc.xpath('//user[name=$name]', nil, name: username)`
> - .NET `XPathExpression.SetContext()` calls that properly resolve `$variable` placeholders from a typed context
>
> **Output format** — write to `sast/xpath-recon.md`:
>
> ```markdown
> # XPath Injection Recon: [Project Name]
>
> ## Summary
> Found [N] locations where XPath expressions are constructed in a vulnerable way.
>
> ## Vulnerable Construction Sites
>
> ### 1. [Descriptive name — e.g., "String concat in user login XPath query"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **XPath evaluation method**: [xpath.evaluate / xpath.compile / nav.Select / doc.SelectNodes / tree.xpath / $xpath->query / doc.xpath / etc.]
> - **Construction pattern**: [string concat / f-string / % format / .format() / String.format / sprintf / Ruby interpolation]
> - **Interpolated variable(s)**: `var_name` -- [brief note on what it appears to represent, e.g., "looks like a username" or "unknown origin"]
> - **Code snippet**:
>   ```
>   [the vulnerable XPath construction + evaluation call]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/xpath-recon.md`. If the recon found **zero vulnerable construction sites** (the summary reports "Found 0" or the "Vulnerable Construction Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following to both output files and stop:

`sast/xpath-results.md`:
```markdown
# XPath Injection Analysis Results

No vulnerabilities found.
```

`sast/xpath-results.json`:
```json
{ "findings": [] }
```

Only proceed to Phase 2 if Phase 1 found at least one vulnerable construction site.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/xpath-recon.md` and split the construction sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces user input only for its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/xpath-recon.md` and count the numbered site sections under "Vulnerable Construction Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/xpath-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Python with lxml, include the "Python — lxml" examples. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned vulnerable XPath construction site, determine whether a user-supplied value reaches the interpolated variable. Our goal is to find XPath injection vulnerabilities. Write results to `sast/xpath-batch-[N].md`.
>
> **Your assigned construction sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, XML document sources, and how data flows through the application.
>
> **XPath injection reference — trace the interpolated variable(s) backwards to their origin**:
>
> 1. **Direct user input** — the variable is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`, `request.args.get(...)`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `params[:x]`, `$_POST['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>    - Cookies: `request.COOKIES.get(...)`, `req.cookies.x`
>    - Environment / CLI args: `os.environ.get(...)`, `sys.argv[...]`, `ENV['KEY']`
>
> 2. **Indirect user input** — the variable is derived from user input through transformations, function calls, or intermediate assignments. Trace the full chain:
>    - Variable assigned from a function return value → check that function's parameter origin
>    - Variable passed as a function argument → check the call site(s)
>    - Variable read from a class attribute or shared state set elsewhere → find the setter
>    - Variable conditionally assigned — check all branches
>
> 3. **Data from an XML document** — in some applications, the XPath query input is read from the XML document itself (e.g., the result of a previous XPath query is used to build the next one). Treat this as potentially tainted if the XML document accepts user-provided content or is sourced from an untrusted channel.
>
> 4. **Server-side / hardcoded value** — the variable comes from config, an environment variable with no user influence, a hardcoded constant, or server-side logic with no user-supplied component — this site is NOT exploitable.
>
> **FP-killers — check these even when user input reaches the variable**:
>
> - **Parameterised XPath variable binding**: Is the user value passed to the XPath engine as a typed variable (via `XPathVariableResolver`, `XsltContext`, lxml keyword args `tree.xpath("...$x...", x=val)`, Nokogiri variable hash `doc.xpath('...$x...', nil, x: val)`) rather than being concatenated into the expression string? If so, classify as **Not Vulnerable**.
> - **Strict integer cast with no quoting context**: Is the value cast with `int()` / `Integer.parseInt()` / `(int)` and used in a purely numeric XPath predicate with no surrounding quotes (e.g., `//item[@id=42]`)? Integer casting prevents string injection but remains fragile — classify as **Likely Vulnerable** rather than safe because downstream context and XPath implementation quirks may still be exploitable.
> - **Allowlist validation**: Is the value validated against a hardcoded set of known-good strings (strict equality, not prefix or contains) before being used in the expression? If so, classify as **Not Vulnerable** (the allowlist eliminates the injection surface).
> - **Escaping / encoding** (custom sanitizers, `htmlspecialchars`, `str_replace("'", "&#39;", ...)`)**: This is **not** equivalent to parameterisation — classify as **Likely Vulnerable** because escaping can be bypassed through encoding attacks, double-encoding, or character set confusion.
>
> **Severity guidance**:
> - `high` by default — XPath injection enables authentication bypass and data exfiltration from XML stores
> - `critical` when the XML document contains credentials, session tokens, or private keys, OR when the XPath expression result directly determines whether authentication succeeds
> - `medium` when the XPath result is never returned to the caller and cannot influence branching on sensitive data (e.g., a write-only audit logging path)
>
> **Exploitability guidance**:
> - `reachable` when untrusted input reaches the XPath sink with no parameterisation or allowlist layer
> - `conditional` when there is a weak mitigation (integer cast, custom escaping) that may be bypassable
> - `unreachable` when a robust mitigation (parameterised binding, strict allowlist) is confirmed in the taint path
> - `unknown` when the taint path cannot be traced with confidence
>
> **Confidence guidance**:
> - `high` for direct parameter→XPath-sink flow with no intervening transformation
> - `medium` when the data flows through an intermediate variable, function, or conditional
> - `low` when the flow is speculative or the XPath sink is deeply nested in opaque helpers
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the interpolated variable with no effective mitigation.
> - **Likely Vulnerable**: User input probably reaches the variable (indirect flow), or only weak mitigation (integer cast, custom escaping) is present.
> - **Not Vulnerable**: The variable is server-side only, OR effective parameterised binding / strict allowlist is confirmed in the taint path.
> - **Needs Manual Review**: Cannot determine the variable's origin with confidence (opaque helpers, complex flows, external libraries).
>
> **Output format** — write to `sast/xpath-batch-[N].md`:
>
> ```markdown
> # XPath Injection Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP query param `username` flows directly into f-string XPath query"]
> - **Taint trace**: [Step-by-step from entry point to the construction site]
> - **Impact**: [What an attacker can do -- bypass auth, extract all nodes, enumerate document structure, etc.]
> - **Severity**: [critical|high|medium]
> - **Exploitability**: [reachable|conditional|unreachable|unknown]
> - **Confidence**: [high|medium|low]
> - **Remediation**: [Parameterised variable binding, allowlist, or rewrite to use constants]
> - **Test payload**:
>   ```
>   [Manual payload or curl command. Show parameter name, injection string, and expected signal.
>    Example: GET /search?user=' or '1'='1&pass=' or '1'='1
>    Expected: authentication bypass (returns a valid session) or unexpected user data in response]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Indirect flow or custom escaping only"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps]
> - **Concern**: [Why it remains a risk -- e.g., escaping bypassable via encoding]
> - **Severity**: [high|medium]
> - **Exploitability**: [conditional|unknown]
> - **Confidence**: [medium|low]
> - **Remediation**: [Replace with parameterised binding]
> - **Test payload**:
>   ```
>   [payload to attempt bypass]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "XPathVariableResolver in place" or "Allowlist gates field value"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why origin could not be determined]
> - **Suggestion**: [What to trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/xpath-batch-*.md` file and merge them into `sast/xpath-results.md` (human-readable) and `sast/xpath-results.json` (canonical machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/xpath-batch-1.md`, `sast/xpath-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/xpath-results.md`:

```markdown
# XPath Injection Analysis Results: [Project Name]

## Executive Summary
- Construction sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the canonical machine-readable file to `sast/xpath-results.json`. Assign sequential `id` values (`xpath-1`, `xpath-2`, ...) to all Vulnerable and Likely Vulnerable findings. Set `chain_id` to `"xml-attack-surface"` for any finding where the same XML parser instance or document that executes the XPath query also processes untrusted XML input (chains with `sast-xxe`); set `chain_id` to `null` otherwise. Emit `{ "findings": [] }` if no exploitable findings were found.

Example canonical output:

```json
{
  "findings": [
    {
      "id": "xpath-1",
      "skill": "sast-xpath",
      "severity": "high",
      "title": "XPath injection via HTTP query parameter in user search endpoint",
      "description": "The `username` request parameter is concatenated directly into an XPath expression evaluated against the users XML document. An attacker can inject XPath predicates such as `' or '1'='1` to bypass authentication or extract all user nodes from the document.",
      "location": { "file": "src/controllers/UserController.java", "line": 42, "column": 24 },
      "remediation": "Replace string concatenation with an XPathVariableResolver that binds `username` as a typed variable: compile the expression with a `$username` placeholder and resolve it in the variable resolver. Never concatenate user-supplied values into the XPath expression string.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": null
    },
    {
      "id": "xpath-2",
      "skill": "sast-xpath",
      "severity": "critical",
      "title": "XPath injection in authentication check allows login bypass",
      "description": "The `login` and `password` request parameters are concatenated into an XPath expression that selects a user node from a credentials XML store. The classic payload `' or '1'='1' or ''='` makes the predicate always true, bypassing authentication entirely.",
      "location": { "file": "src/auth/XmlAuthProvider.java", "line": 78, "column": 31 },
      "remediation": "Rewrite the authentication XPath to use `$login` and `$pass` variable placeholders resolved via XPathVariableResolver. Do not store credentials in plain-text XML; prefer a hashed-password database with parameterised queries.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "xml-attack-surface"
    }
  ]
}
```

6. After writing both result files, **delete all intermediate files**: `sast/xpath-recon.md` and all `sast/xpath-batch-*.md`.

---

## Chain IDs

| chain_id | Meaning |
|---|---|
| `xml-attack-surface` | The XPath injection sink shares an XML parser instance or document with untrusted XML input, creating a combined XXE + XPath injection attack surface. Link findings to `sast-xxe` results when the same parser can expand external entities. |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 construction sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any dynamic variable embedded in an XPath expression string, regardless of origin. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each assigned site, trace the interpolated variable back to its origin. If it comes from a user-controlled source without parameterised binding or an effective allowlist, the site is a real vulnerability.
- The key discriminator between safe and unsafe is **where user data enters**: if user data is in the XPath expression **string** (concatenated or interpolated), it is dangerous. If user data is passed as a **separate typed argument** to a variable-binding API (lxml keyword arg, Java resolver, Nokogiri hash), it is safe.
- Custom escaping (including `str_replace("'", ...)`, `htmlspecialchars`, or homegrown sanitizers) is **not** equivalent to parameterised binding — flag as Likely Vulnerable even if escaping is present.
- Integer casting is weak mitigation for numeric predicates. An attacker cannot inject XPath operators through a pure integer, but downstream context (quoting, type coercion, implementation quirks) may still be exploitable. Classify integer-cast cases as **Likely Vulnerable** unless you can confirm the cast is strict, exceptions surface to the caller as errors, and no quotes surround the variable in the expression.
- XPath authentication bypass is a critical finding when the expression is used to verify login credentials. The classic payload `' or '1'='1' or ''='` makes the predicate always true, returning the first user node regardless of password. Always check whether the XPath result drives an authentication decision.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Always emit `sast/xpath-results.json` even when there are no findings (`{ "findings": [] }`) so the `sast-skills export` aggregator can verify the scan ran.
- Clean up intermediate files: delete `sast/xpath-recon.md` and all `sast/xpath-batch-*.md` after both final result files are written.
