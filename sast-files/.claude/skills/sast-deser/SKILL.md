---
name: sast-deser
description: >-
  Detect insecure deserialization vulnerabilities (CWE-502, OWASP Web25 A05) where
  untrusted bytes from HTTP bodies, uploads, cookies, queues, or caches reach a
  deserializer capable of instantiating arbitrary types or invoking gadget-chain code
  (Java ObjectInputStream/XStream/SnakeYAML, Python pickle/yaml/jsonpickle/dill,
  PHP unserialize, .NET BinaryFormatter/Json.NET TypeNameHandling, Ruby Marshal/YAML,
  Node node-serialize/funcster/cryo). Uses a three-phase approach: recon (locate
  dangerous deserializer call sites), batched verify (trace untrusted bytes to those
  sites in parallel subagents, 3 sites per batch, applying FP-killers — SafeLoader,
  SafeConstructor, type allow-lists, schema validation before deserialize), and merge
  (consolidate batch results into sast/deser-results.md and sast/deser-results.json
  with schema-v2 fields exploitability, confidence, and chain_id). Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/deser-results.md and sast/deser-results.json.
version: 0.1.0
---

# Insecure Deserialization (Deser) Detection

You are performing a focused security assessment to find insecure deserialization vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find dangerous deserializer call sites), **batched verify** (taint analysis and FP-killer checks in parallel batches of 3), and **merge** (consolidate batch reports into `sast/deser-results.md` and `sast/deser-results.json`).

**Prerequisites**: `sast/architecture.md` must exist. Run the sast-analysis skill first if it does not.

---

## What is Insecure Deserialization

Deserialization converts a byte stream or string back into an in-memory object. When the bytes come from an untrusted source (HTTP body, cookie, upload, message queue, shared cache) and the deserializer can reconstruct arbitrary types without restriction, an attacker can craft a payload that instantiates classes already on the classpath and chains their methods together in ways the developer never intended. The result is typically Remote Code Execution (RCE), but also Denial of Service, authentication bypass, or privilege escalation depending on what gadget classes are available.

The core pattern: *untrusted bytes reach a deserializer that can instantiate types beyond a restricted set, with no input schema validation beforehand.*

### What Insecure Deserialization IS

- Calling `pickle.loads(request.data)` — Python pickle can reconstruct arbitrary objects including those with `__reduce__` methods that execute OS commands.
- `yaml.load(user_input)` with the default `Loader` in PyYAML — the default YAML loader uses the full constructor which can instantiate arbitrary Python objects.
- `jsonpickle.decode(request.body)` — jsonpickle encodes class names in the JSON and reconstructs them on decode.
- `dill.load(f)` where `f` is an uploaded file — dill extends pickle and can serialize/deserialize functions.
- `shelve` opened against a user-supplied path or user-controlled key values.
- Java `ObjectInputStream.readObject()` on bytes from an HTTP request body, cookie, or queue message.
- `XMLDecoder` parsing user-controlled XML — XMLDecoder executes arbitrary Java code embedded in XML.
- `XStream` without an allow-list parsing user-controlled XML or JSON.
- SnakeYAML `new Yaml().load(input)` without `SafeConstructor` — can instantiate arbitrary Java types.
- Kryo deserialization of untrusted bytes with no registered-class restriction.
- PHP `unserialize()` called on `$_COOKIE`, `$_POST`, `$_GET`, `$_REQUEST`, or any value derived from HTTP input.
- .NET `BinaryFormatter.Deserialize()` or `LosFormatter.Deserialize()` on untrusted streams.
- .NET `NetDataContractSerializer.ReadObject()` on user-controlled input.
- Json.NET (Newtonsoft.Json) with `TypeNameHandling.All` or `TypeNameHandling.Auto` deserializing user-controlled JSON — the `$type` field in the JSON controls which .NET type is instantiated.
- Ruby `Marshal.load` on user-controlled bytes.
- Ruby `YAML.load` using pre-Psych-4 or non-`safe_load` forms on user input.
- Node.js packages `node-serialize`, `serialize-to-js`, `funcster`, or `cryo` deserializing user-controlled strings — these packages serialize functions and execute them on deserialize.

### What Insecure Deserialization is NOT

Do not flag these patterns:

- **`yaml.safe_load` / `YAML.safe_load` / Psych `safe_load`**: These use `SafeLoader` / `SafeConstructor` which only reconstruct basic YAML types (strings, numbers, lists, dicts) — no arbitrary type instantiation is possible.
- **`json.loads` / `JSON.parse` / `json_decode` with no type resolution**: Plain JSON deserialization into basic types is safe — JSON has no mechanism for type-hinted class instantiation unless a framework layer adds it (e.g., Json.NET `TypeNameHandling`).
- **Schema-validated input before deserialization**: If user bytes pass through a JSON Schema, Pydantic model, or similar strict validator *before* being handed to a deserializer, the attack surface is dramatically reduced and may be out of scope.
- **Trusted / hardcoded sources**: `pickle.loads(open('bundled_model.pkl', 'rb').read())` where the file ships with the application and is never derived from user input is not a vulnerability.
- **`ObjectMapper.readValue(json, SomeDto.class)` (Jackson without polymorphic type handling)**: Jackson's default `readValue` into a concrete DTO class does not enable arbitrary type instantiation. Only flag Jackson when `@JsonTypeInfo` with `As.WRAPPER_OBJECT` or `enableDefaultTyping()` is present and the input is untrusted.
- **Pickle used purely for server-side caching of server-generated objects**: If the pickled bytes are written and read by the same server process without any user-controlled path or content — and there is no upload or injection vector — this is not a vulnerability.
- **IDOR on deserialized data**: Accessing another user's deserialized record because the ID parameter is predictable is an IDOR finding, not a deserialization finding.
- **XSS via deserialized content**: Rendering a deserialized string without HTML encoding is XSS, not deserialization.

### Patterns That Prevent Insecure Deserialization

When you see these patterns the code is likely **not vulnerable**:

**1. Safe loader / safe constructor**
```python
# Python — yaml.safe_load uses SafeLoader, no arbitrary object construction
data = yaml.safe_load(request.data)

# Ruby — Psych safe_load (Psych 4 default, or explicit in Psych 3)
data = YAML.safe_load(params[:data])
```

**2. SafeConstructor in SnakeYAML (Java)**
```java
// Safe: restricts construction to basic YAML types
Yaml yaml = new Yaml(new SafeConstructor());
Object data = yaml.load(inputStream);
```

**3. Explicit type allow-list for XStream**
```java
XStream xstream = new XStream();
xstream.allowTypes(new Class[]{ MyDataClass.class, MyOtherClass.class });
// Only the listed types can be instantiated
MyDataClass obj = (MyDataClass) xstream.fromXML(userXml);
```

**4. Json.NET with TypeNameHandling.None (the safe default)**
```csharp
// Safe: no $type field processing
var obj = JsonConvert.DeserializeObject<MyDto>(json);

// Safe: TypeNameHandling explicitly set to None
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
var obj = JsonConvert.DeserializeObject<MyDto>(json, settings);
```

**5. Schema validation before deserialize**
```python
# Validate the bytes as a known JSON schema before any deserialization
schema = MySchema()
data = schema.load(request.json)  # Marshmallow/Pydantic raises on unknown fields
# Only proceed with deserialization after schema has passed
```

**6. Java serialization filter (JEP 290)**
```java
// ObjectInputFilter allowlist restricts which classes can be deserialized
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(info -> {
    if (info.serialClass() == null) return ObjectInputFilter.Status.ALLOWED;
    if (info.serialClass() == MyAllowedClass.class) return ObjectInputFilter.Status.ALLOWED;
    return ObjectInputFilter.Status.REJECTED;
});
```

---

## Vulnerable vs. Secure Examples

### Python — pickle

```python
# VULNERABLE: untrusted HTTP body bytes passed directly to pickle.loads
from flask import Flask, request
import pickle

app = Flask(__name__)

@app.route('/load', methods=['POST'])
def load_object():
    obj = pickle.loads(request.data)       # CWE-502: arbitrary RCE
    return str(obj)

# SECURE: never deserialize untrusted bytes with pickle; use a data-only format
import json

@app.route('/load', methods=['POST'])
def load_object():
    data = request.get_json(force=True)    # JSON only, no type resolution
    return str(data)
```

### Python — yaml (PyYAML)

```python
# VULNERABLE: default yaml.load with no Loader uses FullLoader / UnsafeLoader
import yaml

def parse_config(user_input: str):
    return yaml.load(user_input)           # CWE-502 if user_input is untrusted

# ALSO VULNERABLE: explicit Loader=yaml.Loader or Loader=yaml.UnsafeLoader
def parse_config(user_input: str):
    return yaml.load(user_input, Loader=yaml.Loader)

# SECURE: SafeLoader restricts to basic YAML types only
def parse_config(user_input: str):
    return yaml.safe_load(user_input)
    # equivalent: yaml.load(user_input, Loader=yaml.SafeLoader)
```

### Python — jsonpickle

```python
# VULNERABLE: jsonpickle.decode reconstructs arbitrary Python objects
import jsonpickle
from flask import request

@app.route('/restore', methods=['POST'])
def restore():
    obj = jsonpickle.decode(request.json['data'])   # CWE-502
    return repr(obj)

# SECURE: use plain json.loads and map to an explicit DTO
import json
from dataclasses import dataclass

@dataclass
class UserPrefs:
    theme: str
    locale: str

@app.route('/restore', methods=['POST'])
def restore():
    raw = json.loads(request.data)
    prefs = UserPrefs(theme=raw['theme'], locale=raw['locale'])
    return repr(prefs)
```

### Python — dill / shelve

```python
# VULNERABLE: dill extends pickle — same RCE risk
import dill
from flask import request

@app.route('/upload-model', methods=['POST'])
def upload_model():
    model = dill.loads(request.data)               # CWE-502
    return model.predict([1, 2, 3])

# VULNERABLE: shelve on user-controlled path or tainted keys
import shelve

def load_user_data(username: str):
    with shelve.open(f'data/{username}') as db:    # path traversal + deserialization
        return db['profile']

# SECURE: use a safe serialization format (e.g., joblib with ONNX for ML models,
# or a schema-validated JSON blob for config)
```

### Java — ObjectInputStream

```java
// VULNERABLE: bytes from HTTP body deserialized without class filter
import java.io.*;
import javax.servlet.http.*;

public class LoadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream()); // CWE-502
        Object obj = ois.readObject();
        resp.getWriter().write(obj.toString());
    }
}

// SECURE: add JEP 290 serialization filter to allowlist known-safe classes only
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
    ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
    ois.setObjectInputFilter(info -> {
        Class<?> cls = info.serialClass();
        if (cls == null) return ObjectInputFilter.Status.ALLOWED;
        if (cls == MyDto.class) return ObjectInputFilter.Status.ALLOWED;
        return ObjectInputFilter.Status.REJECTED;
    });
    MyDto dto = (MyDto) ois.readObject();
}
```

### Java — XMLDecoder

```java
// VULNERABLE: XMLDecoder on user-supplied XML executes arbitrary Java code
import java.beans.XMLDecoder;
import java.io.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class ImportController {
    @PostMapping("/import")
    public String importData(@RequestBody byte[] xmlBytes) throws IOException {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBytes)); // CWE-502
        Object obj = decoder.readObject();
        return obj.toString();
    }
}

// SECURE: parse user XML with a schema-validating JAXB or DOM parser restricted
// to known element types; never use XMLDecoder on untrusted input
```

### Java — XStream

```java
// VULNERABLE: XStream with no allowlist parses any type from user XML
import com.thoughtworks.xstream.XStream;

public Object deserialize(String xml) {
    XStream xstream = new XStream();      // CWE-502: no type restrictions
    return xstream.fromXML(xml);
}

// SECURE: explicit allowlist of permitted types
public Object deserialize(String xml) {
    XStream xstream = new XStream();
    xstream.allowTypes(new Class[]{ OrderDto.class, ProductDto.class });
    return xstream.fromXML(xml);
}
```

### Java — SnakeYAML

```java
// VULNERABLE: default Yaml() without SafeConstructor
import org.yaml.snakeyaml.Yaml;

public Object parseYaml(String input) {
    Yaml yaml = new Yaml();               // CWE-502: arbitrary Java type construction
    return yaml.load(input);
}

// SECURE: SafeConstructor restricts types to basic YAML primitives
import org.yaml.snakeyaml.constructor.SafeConstructor;

public Object parseYaml(String input) {
    Yaml yaml = new Yaml(new SafeConstructor());
    return yaml.load(input);
}
```

### PHP — unserialize

```php
// VULNERABLE: unserialize() on cookie or POST data
function loadSession(): object {
    $data = $_COOKIE['session'];        // CWE-502
    return unserialize($data);
}

// ALSO VULNERABLE: base64 decode does not add safety
function loadSession(): object {
    $data = base64_decode($_POST['data']);
    return unserialize($data);          // CWE-502: still user-controlled bytes
}

// SECURE: use JSON for session data; never unserialize untrusted input
function loadSession(): array {
    $data = $_COOKIE['session'];
    return json_decode(base64_decode($data), true);
    // Validate the resulting array against an expected schema before use
}
```

### .NET — BinaryFormatter

```csharp
// VULNERABLE: BinaryFormatter deserializing untrusted stream (obsolete and dangerous)
using System.Runtime.Serialization.Formatters.Binary;

public object Deserialize(Stream inputStream) {
    var formatter = new BinaryFormatter();          // CWE-502; .NET 5+ throws by default
    return formatter.Deserialize(inputStream);
}

// ALSO VULNERABLE: LosFormatter on view-state from user
using System.Web.UI;

public object LoadViewState(string base64Input) {
    var formatter = new LosFormatter();
    return formatter.Deserialize(base64Input);      // CWE-502
}

// SECURE: use System.Text.Json or XmlSerializer with known concrete type
using System.Text.Json;

public MyDto Deserialize(Stream inputStream) {
    return JsonSerializer.Deserialize<MyDto>(inputStream)!;
}
```

### .NET — Json.NET TypeNameHandling

```csharp
// VULNERABLE: TypeNameHandling.All lets $type in JSON control the deserialized class
using Newtonsoft.Json;

public object Deserialize(string json) {
    var settings = new JsonSerializerSettings {
        TypeNameHandling = TypeNameHandling.All   // CWE-502
    };
    return JsonConvert.DeserializeObject(json, settings);
}

// ALSO VULNERABLE: TypeNameHandling.Auto with untrusted JSON
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Auto      // CWE-502
};

// SECURE: TypeNameHandling.None (the default) with a concrete target type
public MyDto Deserialize(string json) {
    return JsonConvert.DeserializeObject<MyDto>(json)!;
    // Or explicitly: TypeNameHandling = TypeNameHandling.None
}
```

### Ruby — Marshal.load

```ruby
# VULNERABLE: Marshal.load on user-controlled cookie or param
class SessionController < ApplicationController
  def restore
    obj = Marshal.load(Base64.decode64(params[:session]))  # CWE-502
    render json: obj
  end
end

# SECURE: use JSON.parse for data interchange; never Marshal.load on untrusted input
class SessionController < ApplicationController
  def restore
    data = JSON.parse(Base64.decode64(params[:session]))
    render json: data
  end
end
```

### Ruby — YAML.load (pre-Psych-4)

```ruby
# VULNERABLE: YAML.load with Psych < 4 can instantiate arbitrary Ruby objects
require 'yaml'

def parse_config(input)
  YAML.load(input)       # CWE-502 when input is untrusted and Psych < 4
end

# SECURE: YAML.safe_load restricts to basic types in all Psych versions
def parse_config(input)
  YAML.safe_load(input)
end
```

### Node.js — node-serialize / funcster / cryo

```javascript
// VULNERABLE: node-serialize reconstructs and executes serialized functions
const serialize = require('node-serialize');
const express = require('express');
const app = express();

app.post('/restore', (req, res) => {
  const obj = serialize.unserialize(req.body.data);  // CWE-502: RCE via IIFE in JSON
  res.json(obj);
});

// VULNERABLE: funcster executes stored function strings
const funcster = require('funcster');
app.post('/fn', (req, res) => {
  const fn = funcster.deepDeserialize(req.body);     // CWE-502
  res.json(fn());
});

// SECURE: use JSON.parse with an explicit DTO mapping; never deserialize function strings
app.post('/restore', (req, res) => {
  const raw = JSON.parse(req.body.data);
  const obj = { name: String(raw.name), value: Number(raw.value) };
  res.json(obj);
});
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Dangerous Deserializer Call Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where a potentially dangerous deserializer is called — regardless of where the input comes from. Write results to `sast/deser-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, frameworks, and serialization/deserialization patterns in use.
>
> **What to search for — deserializer call sites by language**:
>
> Search for the following sink patterns. Flag ANY call to these sinks — you are not yet checking whether the input is untrusted; that is Phase 2's job.
>
> **Python sinks:**
> - `pickle.load(` and `pickle.loads(` — in any module; note the variable or expression passed as the first argument
> - `yaml.load(` without `Loader=yaml.SafeLoader` — i.e., `yaml.load(x)` or `yaml.load(x, Loader=yaml.Loader)` or `yaml.load(x, Loader=yaml.UnsafeLoader)` or `yaml.load(x, Loader=yaml.FullLoader)` (FullLoader was still vulnerable to certain gadget attacks pre-5.4)
> - `jsonpickle.decode(`
> - `dill.load(` and `dill.loads(`
> - `shelve.open(` — note if the path argument is derived from user input
>
> **Java sinks:**
> - `ObjectInputStream` construction followed by `.readObject()` — flag the constructor call
> - `XMLDecoder` construction followed by `.readObject()` — flag the constructor call
> - `XStream` — flag any `.fromXML(` or `.fromJSON(` call; note whether an `allowTypes` call is present nearby
> - `new Yaml(` without `new SafeConstructor()` as the argument, followed by `.load(`
> - `Kryo` — `.readObject(` or `.readClassAndObject(`
>
> **.NET sinks:**
> - `BinaryFormatter` — `.Deserialize(` or `.UnsafeDeserialize(`
> - `LosFormatter` — `.Deserialize(`
> - `NetDataContractSerializer` — `.ReadObject(` or `.Deserialize(`
> - `JsonConvert.DeserializeObject(` or `JsonSerializer.Deserialize(` — ONLY flag when `TypeNameHandling` is set to `All`, `Auto`, `Objects`, or `Arrays` in a nearby `JsonSerializerSettings`; skip plain `DeserializeObject<T>(json)` calls
>
> **PHP sinks:**
> - `unserialize(` — note the argument expression; flag all occurrences
>
> **Ruby sinks:**
> - `Marshal.load(` and `Marshal.restore(`
> - `YAML.load(` — note if it is `YAML.safe_load` (skip) or `YAML.load` (flag)
>
> **Node.js sinks:**
> - `require('node-serialize')` usage followed by `.unserialize(`
> - `require('serialize-to-js')` usage followed by `unserialize(`
> - `require('funcster')` usage followed by `.deepDeserialize(` or `.serialize(`/`.deserialize(`
> - `require('cryo')` usage followed by `.thaw(`
>
> **What to skip** (safe patterns — do not flag):
> - `yaml.safe_load(` in Python
> - `yaml.load(x, Loader=yaml.SafeLoader)` in Python
> - `YAML.safe_load(` in Ruby
> - `new Yaml(new SafeConstructor())` in Java SnakeYAML
> - `XStream` calls that have an `allowTypes(` or `addPermission(` call with a non-empty list immediately before the `fromXML/fromJSON` call
> - `JsonConvert.DeserializeObject<ConcreteType>(json)` with no `JsonSerializerSettings` or with `TypeNameHandling.None`
> - `JSON.parse(` in JavaScript/TypeScript — plain JSON is safe
> - `json.loads(` in Python — plain JSON is safe
> - `json_decode(` in PHP — plain JSON is safe
> - `ObjectMapper.readValue(json, ConcreteType.class)` in Jackson — safe when no `@JsonTypeInfo` enables polymorphic handling
>
> **Output format** — write to `sast/deser-recon.md`:
>
> ```markdown
> # Deser Recon: [Project Name]
>
> ## Summary
> Found [N] deserializer call sites requiring taint verification.
>
> ## Call Sites
>
> ### 1. [Descriptive name — e.g., "pickle.loads in session restore endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Sink**: [e.g., `pickle.loads`, `ObjectInputStream.readObject`, `unserialize`]
> - **Input expression**: [the variable or expression passed to the deserializer]
> - **Notes**: [any immediately visible safe guard — e.g., "SafeConstructor present but verify scope" — or "no guard visible"]
> - **Code snippet**:
>   ```
>   [the deserializer call with 3-5 lines of surrounding context]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/deser-recon.md`. If the recon found **zero call sites** (the summary reports "Found 0" or the "Call Sites" section is empty or absent), **skip Phase 2 entirely**. Write the following to `sast/deser-results.md` and `sast/deser-results.json`, then stop:

`sast/deser-results.md`:
```markdown
# Deser Analysis Results

No vulnerabilities found.
```

`sast/deser-results.json`:
```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one call site.

### Phase 2: Verify — Taint Analysis and FP-Killer Checks (Batched)

After Phase 1 completes, read `sast/deser-recon.md` and split the call sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent traces the input expression only for its assigned sites, applies all FP-killers, and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/deser-recon.md` and count the numbered sections under "Call Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/deser-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned deserializer call site, determine whether the input bytes originate from an untrusted source and whether any effective FP-killers are in place. Write results to `sast/deser-batch-[N].md`.
>
> **Your assigned call sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware chains, message queues, and how data flows through the application.
>
> **Taint question — trace the input expression backwards to its origin**:
>
> The core question is: does the value passed to the deserializer cross a trust boundary?
>
> **Trust boundaries that make input untrusted:**
> - HTTP request body: `request.data`, `request.body`, `req.body`, `$_POST`, `$_REQUEST`, `c.Request.Body`, `@RequestBody`, `HttpRequest.Content`
> - HTTP query parameters: `request.args.get(...)`, `req.query.*`, `params[:x]`, `$_GET['x']`
> - HTTP headers: `request.headers.get(...)`, `req.headers['x']`, `$_SERVER['HTTP_*']`
> - HTTP cookies: `request.cookies.get(...)`, `req.cookies.*`, `$_COOKIE['x']`
> - File uploads: `request.files.get(...)`, `req.file`, `IFormFile`, `MultipartFile`
> - Message queues / event buses: SQS message body, Kafka record value, RabbitMQ message body, Redis Pub/Sub payload
> - External HTTP responses (if the URL is user-controlled, the response body is also untrusted)
> - Shared caches (Redis, Memcached) — if user-controlled data was written to the cache and is read back for deserialization
>
> **Tracing approach**:
> 1. Read the file containing the call site and trace the input variable/expression backwards through assignments, function call chains, and intermediate variables until you reach the origin.
> 2. If the origin is one of the trust boundaries above, the site is reachable.
> 3. If the origin is a hardcoded constant, a bundled file, a config file, or server-side computation with no user influence, the site is not a vulnerability.
> 4. If the input passes through multiple functions, check each function's body. Treat DB-read values as potentially tainted if the stored value could have come from user input.
>
> **FP-killers — apply these checks even when taint is confirmed:**
>
> If **any** of the following are present and apply to this call site, set exploitability to `conditional` (not `reachable`) or classify as Not Vulnerable:
>
> 1. **SafeLoader / SafeConstructor**: Python `yaml.safe_load` or `yaml.load(x, Loader=yaml.SafeLoader)`, Ruby `YAML.safe_load`, Java SnakeYAML `new Yaml(new SafeConstructor())`. These restrict deserialization to primitive types only — no arbitrary class instantiation is possible. Classify as **Not Vulnerable**.
>
> 2. **Explicit type allow-list / serialization filter**: Java `ObjectInputStream.setObjectInputFilter(...)` with a non-trivial allowlist; XStream `allowTypes(...)` with a concrete non-empty class array; Kryo `register(MyClass.class)` with class-registration mode enabled and default serializer disabled. If the allowlist is empty or trivially permissive (`allowTypesByWildcard("**")`) the FP-killer does NOT apply. Classify as `conditional` if the allowlist exists but may be incomplete.
>
> 3. **Schema validation before deserialization**: Input is parsed by a strict schema validator (Pydantic model, Marshmallow schema, JSON Schema validator, Zod) *before* the bytes reach the deserializer. The validation must constrain the structure to known-safe fields and reject unexpected keys. Classify as `conditional`.
>
> 4. **Trusted / hardcoded source**: The bytes come from a bundled file, a config file generated by the application itself, or any source that is not controllable by an external caller. Classify as **Not Vulnerable**.
>
> 5. **Json.NET with TypeNameHandling.None**: `JsonConvert.DeserializeObject<ConcreteType>(json)` with no settings, or with `TypeNameHandling.None` explicitly. No `$type` processing occurs. Classify as **Not Vulnerable**.
>
> **Severity determination** (from the spec):
>
> - Default severity: **critical** — a reachable gadget chain enables RCE.
> - Lower to **high** when a type allow-list is present but may be incomplete (gadget chain possible only through listed classes).
> - Lower to **medium** when the deserializer is constrained but no known gadget exists on the classpath for the specific allowed types, or the deserialized value is never used in a dangerous way.
>
> **exploitability and confidence** (schema-v2 fields):
>
> - `exploitability: "reachable"` — untrusted bytes reach the sink with no effective FP-killer; a gadget chain is plausible.
> - `exploitability: "conditional"` — untrusted bytes can reach the sink, but an FP-killer (incomplete allow-list, schema validation) reduces but does not eliminate risk.
> - `exploitability: "unreachable"` — bytes come from a trusted/hardcoded source OR a complete SafeLoader/SafeConstructor/allowlist eliminates the attack surface.
> - `exploitability: "unknown"` — cannot determine the input origin with confidence.
> - `confidence: "high"` — direct flow from a request parameter / body / cookie to the deserializer with no intermediaries and no FP-killers.
> - `confidence: "medium"` — indirect flow through intermediate variables, functions, or stored values; or FP-killer applicability is uncertain.
> - `confidence: "low"` — origin is opaque (external library, complex conditional logic); flag for manual review.
>
> **chain_id**: Set to `"rce-gadget"` for any finding that has `exploitability: "reachable"` and the deserializer is one that can instantiate arbitrary types (pickle, marshal, BinaryFormatter, XMLDecoder, XStream without allowlist, SnakeYAML without SafeConstructor, node-serialize, funcster, cryo). Leave `null` for conditional or low-severity findings unless a sibling `sast-deps` finding identifies a known-vulnerable gadget library.
>
> **Remediation** (from the spec):
>
> Tailor the remediation to the specific language and sink. Always include the safe alternative:
> - Python pickle/dill/jsonpickle: Replace with `json.loads` + an explicit DTO mapping. Never deserialize untrusted bytes with pickle.
> - Python yaml: Replace `yaml.load` with `yaml.safe_load`.
> - Java ObjectInputStream: Add a JEP 290 `ObjectInputFilter` allowlist; better, replace with a data-only format (JSON via Jackson DTO, Protobuf).
> - Java XMLDecoder: Never use on untrusted input; use a schema-validating XML parser with a strict XSD.
> - Java XStream: Add `allowTypes(new Class[]{ ... })` with the minimal required classes.
> - Java SnakeYAML: Replace `new Yaml()` with `new Yaml(new SafeConstructor())`.
> - PHP: Replace `unserialize` with `json_decode` + explicit field mapping. If serialization is required, use `igbinary` with a type whitelist or sign the serialized payload with HMAC and verify before deserializing.
> - .NET BinaryFormatter/LosFormatter: Obsolete and dangerous — remove entirely; use `System.Text.Json` with a concrete DTO type.
> - .NET Json.NET: Set `TypeNameHandling = TypeNameHandling.None` (the default); never use `TypeNameHandling.All` or `TypeNameHandling.Auto` with untrusted input.
> - Ruby Marshal: Replace with `JSON.parse`; never call `Marshal.load` on untrusted input.
> - Ruby YAML: Replace `YAML.load` with `YAML.safe_load`.
> - Node.js: Remove `node-serialize`, `funcster`, `serialize-to-js`, `cryo`; use `JSON.parse` with an explicit DTO mapping.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: Untrusted bytes demonstrably reach the deserializer with no effective FP-killer. `exploitability: reachable`, severity typically critical.
> - **Likely Vulnerable**: Indirect taint flow or an FP-killer that is present but incomplete / uncertain. `exploitability: conditional`.
> - **Not Vulnerable**: Bytes are from a trusted source OR a complete FP-killer (SafeLoader, full allowlist) is in place. `exploitability: unreachable`.
> - **Needs Manual Review**: Cannot determine input origin — opaque helpers, complex flow, external library. `exploitability: unknown`.
>
> **Output format** — write to `sast/deser-batch-[N].md`:
>
> ```markdown
> # Deser Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [e.g., `pickle.loads`, `unserialize`, `ObjectInputStream.readObject`]
> - **Issue**: [e.g., "HTTP request body bytes flow directly into pickle.loads with no schema guard"]
> - **Taint trace**: [Step-by-step: entry point → variable assignment(s) → deserializer call]
> - **FP-killers checked**: [List each FP-killer and why it does not apply]
> - **exploitability**: reachable
> - **confidence**: high|medium
> - **chain_id**: rce-gadget|null
> - **Severity**: critical|high|medium
> - **Impact**: [What an attacker can do — RCE, DoS, auth bypass, data exfiltration]
> - **Remediation**: [Language-specific safe alternative]
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink name]
> - **Issue**: [indirect flow, incomplete allow-list, or uncertain FP-killer]
> - **Taint trace**: [Best-effort trace; mark uncertain steps with "(inferred)"]
> - **FP-killers checked**: [List each FP-killer and disposition]
> - **exploitability**: conditional
> - **confidence**: medium|low
> - **chain_id**: null
> - **Severity**: high|medium
> - **Concern**: [Why the risk remains despite partial mitigation]
> - **Remediation**: [Safe alternative]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink name]
> - **exploitability**: unreachable
> - **Reason**: [e.g., "Input is a hardcoded file path bundled with the application" or "SafeLoader in use"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Sink**: [sink name]
> - **exploitability**: unknown
> - **confidence**: low
> - **chain_id**: null
> - **Uncertainty**: [Why the input origin could not be determined]
> - **Suggestion**: [What to trace manually — which helper function, which DB write path]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/deser-batch-*.md` file and merge them into `sast/deser-results.md` and `sast/deser-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/deser-batch-1.md`, `sast/deser-batch-2.md`, ... files.
2. Collect all findings from each batch, preserving every detail field and classification.
3. Count totals across all batches for the executive summary.
4. Write the merged human-readable report to `sast/deser-results.md`:

```markdown
# Deser Analysis Results: [Project Name]

## Executive Summary
- Call sites analyzed: [total from recon]
- Vulnerable (exploitability: reachable): [N]
- Likely Vulnerable (exploitability: conditional): [N]
- Not Vulnerable (exploitability: unreachable): [N]
- Needs Manual Review (exploitability: unknown): [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write the machine-readable JSON to `sast/deser-results.json` using the canonical schema. Assign a sequential `id` to each finding (`deser-1`, `deser-2`, ...) in the same order as the merged report (VULNERABLE first). Set all schema-v2 fields:

```json
{
  "findings": [
    {
      "id": "deser-1",
      "skill": "sast-deser",
      "severity": "critical",
      "title": "pickle.loads called on untrusted HTTP request body",
      "description": "The /load endpoint passes request.data directly to pickle.loads without schema validation. A crafted pickle payload can execute arbitrary OS commands via __reduce__.",
      "location": { "file": "app/routes/session.py", "line": 42, "column": 10 },
      "remediation": "Replace pickle.loads with json.loads and map the result to an explicit DTO. Never deserialize untrusted bytes with pickle.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "rce-gadget"
    }
  ]
}
```

Fields for each finding:
- `id`: `"deser-N"` where N is sequential starting at 1.
- `skill`: always `"sast-deser"`.
- `severity`: `"critical"`, `"high"`, `"medium"`, `"low"`, or `"info"`.
- `title`: short one-line description of the specific finding (not a generic label).
- `description`: full explanation including what the sink is, what the taint path is, and what an attacker can achieve.
- `location.file`: relative path from the repository root.
- `location.line`: the line number of the deserializer call itself.
- `location.column`: column number if determinable; omit or set to `0` if not.
- `remediation`: the language-specific safe alternative from the verify phase.
- `exploitability`: `"reachable"` | `"conditional"` | `"unreachable"` | `"unknown"`.
- `confidence`: `"high"` | `"medium"` | `"low"`.
- `chain_id`: `"rce-gadget"` for reachable gadget-capable sinks; `null` otherwise. If a sibling `sast-deps` finding identifies a known-vulnerable gadget library (e.g., Commons Collections, SnakeYAML CVE), set `chain_id` to `"rce-gadget"` even for `conditional` findings to allow the export CLI to link the chain.

Include only Vulnerable and Likely Vulnerable findings in the JSON. Not Vulnerable and Needs Manual Review findings are documented in the markdown only, unless the reviewer determines they warrant escalation.

6. After writing both output files, **delete all intermediate batch files** (`sast/deser-batch-*.md`) and the recon file (`sast/deser-recon.md`).

---

## Severity Reference

| Condition | Severity |
|---|---|
| Untrusted bytes → gadget-capable deserializer, no allow-list, no SafeLoader | **critical** |
| Untrusted bytes → deserializer with a type allow-list that may be incomplete | **high** |
| Untrusted bytes → constrained deserializer; no known gadget on classpath for allowed types | **medium** |
| Conditional flow (env-guarded, partially trusted source) | **high** → lower to **medium** based on reachability |

## Chain Reference

| chain_id | Sibling skill | Composition |
|---|---|---|
| `rce-gadget` | `sast-deps` | A known-vulnerable gadget library (Commons Collections, Spring Framework pre-patch, SnakeYAML CVE) combined with an insecure deserializer call is a confirmed RCE chain. When `sast-deps` reports a CVE for a gadget library and `sast-deser` reports a reachable call site, link both findings with `chain_id: "rce-gadget"`. |

## Test Fixture

A compliant implementation of this skill must produce exactly one finding for the following minimal fixture, classified `reachable`, `critical`, `chain_id: "rce-gadget"`, with `confidence: "high"`:

**True Positive** (must be flagged):
```python
# TP: untrusted HTTP body bytes → pickle.loads
from flask import Flask, request
import pickle

app = Flask(__name__)

@app.route('/restore', methods=['POST'])
def restore():
    obj = pickle.loads(request.data)   # TP: CWE-502 — reachable, critical
    return str(obj)
```

**True Negatives** (must NOT be flagged):
```python
# TN-1: safe_load — no arbitrary type construction
import yaml
from flask import request

@app.route('/config', methods=['POST'])
def load_config():
    data = yaml.safe_load(request.data)  # TN: SafeLoader in use
    return str(data)

# TN-2: hardcoded / trusted file — not user-controlled
import pickle

def load_bundled_model():
    with open('models/classifier.pkl', 'rb') as f:
        return pickle.loads(f.read())    # TN: file ships with the application
```

Assert: only the TP is flagged; both TNs are classified `Not Vulnerable` (`exploitability: unreachable`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 call sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any call to a listed dangerous deserializer sink regardless of input origin. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is taint analysis plus FP-killer verification**: for each assigned site, (a) trace the input expression back to its origin, (b) apply every FP-killer, and (c) set `exploitability`, `confidence`, and `chain_id` accordingly.
- When in doubt about input origin, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives in deserialization findings enable RCE.
- `yaml.safe_load` and `yaml.load(x, Loader=yaml.SafeLoader)` are equivalent and safe — do not flag either.
- `yaml.load(x, Loader=yaml.FullLoader)` is NOT safe for untrusted input in PyYAML < 5.4 — flag it.
- Base64 decoding (`base64.b64decode`, `Base64.decode64`) before deserialization does NOT add any safety — the bytes are still attacker-controlled after decoding. Do not treat base64 encoding as a mitigation.
- Custom HMAC signing of the serialized payload IS a partial mitigation for some attacks. If a verifiable HMAC is checked server-side before deserialization and the signing key is secret, classify as `conditional` (not `reachable`) — but flag it, because key compromise or HMAC bypass would restore the risk.
- Json.NET (`Newtonsoft.Json`) is safe when `TypeNameHandling.None` is in use. Only flag when `TypeNameHandling.All`, `TypeNameHandling.Auto`, `TypeNameHandling.Objects`, or `TypeNameHandling.Arrays` is explicitly set in a `JsonSerializerSettings` that is passed to a deserialize call receiving untrusted input.
- Kryo with class registration (`kryo.setRegistrationRequired(true)` and explicit `kryo.register(MyClass.class)`) is a type allow-list. Flag it as `conditional` (not `reachable`) but note that the allowlist must be reviewed for gadget classes.
- Clean up intermediate files: delete `sast/deser-recon.md` and all `sast/deser-batch-*.md` files after the final `sast/deser-results.md` and `sast/deser-results.json` are written.
- Always emit `sast/deser-results.json` even when there are zero findings — write `{"findings": []}` so the `sast-skills export` CLI can verify the scan ran.
