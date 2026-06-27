---
name: sast-xmlbomb
description: >-
  Detect XML entity-expansion denial-of-service vulnerabilities (CWE-776) in a
  codebase using a three-phase approach: recon (find XML parsing sites where DTD
  or entity expansion is not explicitly disabled), batched verify (trace
  user-controlled XML to each site in parallel subagents, 3 sites each), and
  merge (consolidate batch results). Distinct from sast-xxe (CWE-611): this
  skill targets CPU/memory exhaustion via recursive entity expansion (billion
  laughs, quadratic blowup) only — not file-read or SSRF exfiltration. Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/xmlbomb-results.md and sast/xmlbomb-results.json.
version: 0.1.0
---

# XML Entity-Expansion DoS (XML Bomb) Detection

You are performing a focused security assessment to find XML entity-expansion denial-of-service vulnerabilities (CWE-776 — Unrestricted Recursion in DTD) in a codebase. This skill uses a three-phase approach with subagents: **recon** (find XML parsing sites where DTD processing or entity expansion is not safely disabled), **batched verify** (trace whether user-supplied XML reaches those parsers, in parallel batches of 3), and **merge** (consolidate batch results into one report and the canonical JSON output).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## Scope Boundary: XML Bomb vs. XXE

**This skill (sast-xmlbomb) targets CWE-776 only** — denial-of-service through recursive entity expansion that exhausts CPU or memory. The canonical attack payload is the "billion laughs" DTD:

```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY bomb "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
]>
<root>&bomb;</root>
```

A depth-10 doubling chain like this causes an exponential (billion-element) expansion before the first byte is returned to the application. Quadratic blowup works similarly with a long repeated entity.

**Do NOT flag as XML Bomb these separate vulnerabilities (covered by sast-xxe, CWE-611)**:
- `SYSTEM` entity declarations referencing `file://` paths — that is arbitrary file read (XXE)
- `SYSTEM` entity declarations referencing `http://` or `https://` URLs — that is SSRF via XXE
- Parameter entity injection that fetches external DTD documents — that is blind XXE / OOB exfiltration
- XInclude (`xi:include`) processing that reads local or remote resources — that is XXE / SSRF

The two vulnerability classes often share the same root cause (DTD processing enabled, entity expansion not disabled), so a finding in sast-xmlbomb and a finding in sast-xxe may appear on the same line of code. That is expected and correct — they are different attack chains with different impacts (DoS vs. data exfiltration). Use `chain_id: "xml-attack-surface"` on any finding that shares a parse site with an XXE finding so the aggregated report can surface the full risk.

---

## What is an XML Bomb

An XML bomb exploits the fact that XML DTD entity declarations allow recursive substitution. When an XML parser processes a document containing such a DTD, it must expand each entity reference before returning the document tree to the application. A small input document (a few hundred bytes) can expand to gigabytes of in-memory data, exhausting the process heap and rendering the server unresponsive.

There are two common variants:

**Exponential / Billion-Laughs**: Each entity references 10 copies of the previous entity. At depth 10 this creates 10^10 (ten billion) expansions. A 4 KB payload triggers 3 GB of expansion.

**Quadratic Blowup**: A single large entity is referenced repeatedly in the document body. If the entity value is N bytes long and is referenced M times, the expansion is O(N*M). Simpler to craft, still effective for large N.

The core pattern: *user-controlled XML containing a recursive or deeply repeated DTD reaches an XML parser that has not disabled DTD processing or entity expansion.*

### What XML Bomb IS

- XML parsed with DTD processing **enabled** (the default in most parsers) and no explicit entity-expansion limit or DTD prohibition
- `<!ENTITY>` declarations that reference other entities, building an exponential tree
- A large `<!ENTITY>` value referenced many times in the document body (quadratic variant)
- Any parser that processes the `<!DOCTYPE>` declaration from untrusted input without restriction
- Python stdlib `xml.etree.ElementTree`, `xml.dom.minidom`, `xml.sax` on untrusted input (expat-backed; entity count limits vary by Python version — not guaranteed safe)
- `lxml.etree` without `resolve_entities=False` or `huge_tree=True` disabled
- Java `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` without `FEATURE_SECURE_PROCESSING` or `disallow-doctype-decl`
- PHP `simplexml_load_string`, `DOMDocument::loadXML` without `LIBXML_NOENT` stripping and entity loading disabled
- Ruby `Nokogiri::XML` with `NONET` but without `NOENT` disabled (NONET only blocks network entity resolution, not in-document recursive expansion)
- Node.js `fast-xml-parser` with `processEntities: true` (default in versions < 4.x)

### What XML Bomb is NOT

Do not flag these:

- **Parsers hardened against entity expansion**: `defusedxml` (Python), Java factories with `disallow-doctype-decl` set, .NET with `DtdProcessing.Prohibit`
- **Parsers with entity expansion limits**: Python's `expat` sets `EntityDeclHandler` limits in Python >= 3.8.6 / 3.9.1 (but verify — `defusedxml` is still the safe choice)
- **Fully server-controlled XML**: Config files loaded at startup, bundled schema documents, migration scripts — no user influence possible
- **SSRF/file-read via XML**: `SYSTEM` entity referencing external files or URLs — flag those in sast-xxe, not here
- **XML parsing behind a WAF or API gateway that enforces request body size limits**: The DoS risk is reduced to medium (still flag, but lower severity)

### Patterns That Prevent XML Bomb

When you see these patterns, the parser is **not vulnerable**:

**1. Python — defusedxml (always safe; blocks DTD, entities, entity expansion)**
```python
import defusedxml.ElementTree as ET
tree = ET.fromstring(user_input)   # DTD and entity expansion blocked unconditionally
```

**2. Python — lxml with resolve_entities=False and load_dtd=False**
```python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
tree = etree.fromstring(data, parser)
```
Note: `resolve_entities=False` alone still *loads* the DTD — setting `load_dtd=False` is the belt-and-suspenders defense against entity expansion.

**3. Java — DocumentBuilderFactory with FEATURE_SECURE_PROCESSING**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
// or, more explicitly:
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```
`FEATURE_SECURE_PROCESSING` imposes entity expansion limits per JAXP specification. `disallow-doctype-decl` is stronger — it throws an exception on any DOCTYPE declaration.

**4. Java — XMLInputFactory with SUPPORT_DTD=false**
```java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
```

**5. Java — SAXParserFactory with disallow-doctype-decl**
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
SAXParser parser = spf.newSAXParser();
```

**6. .NET — XmlReaderSettings with DtdProcessing.Prohibit**
```csharp
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
XmlReader reader = XmlReader.Create(stream, settings);
```
`DtdProcessing.Ignore` also prevents processing but is slightly weaker (it silently ignores rather than throwing). Either protects against entity expansion. `DtdProcessing.Parse` is the vulnerable default.

**7. PHP — LIBXML_NOENT + LIBXML_DTDLOAD explicitly disabled**
```php
// IMPORTANT: LIBXML_NOENT EXPANDS entities — it does NOT disable them.
// To block entity expansion, use LIBXML_NONET and avoid LIBXML_DTDLOAD:
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);   // blocks network, but not in-document expansion
// Safer: use a schema whitelist and parse with no entity flags at all
```
There is no single PHP flag that fully blocks recursive in-document entity expansion the way `defusedxml` does in Python. The safest PHP approach is to prohibit `<!DOCTYPE` entirely via a pre-parse string check or to use a PHP XML library that wraps libxml2 with secure defaults.

**8. Node.js — fast-xml-parser with processEntities disabled**
```javascript
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ processEntities: false });
parser.parse(xmlInput);
```

**9. Ruby — Nokogiri with NOENT disabled (default Nokogiri behavior)**
```ruby
# Safe: default Nokogiri does not expand entities in untrusted documents
doc = Nokogiri::XML(xml_input)

# Unsafe: noent option enables entity substitution
doc = Nokogiri::XML(xml_input) { |c| c.noent }
```

---

## Vulnerable vs. Secure Examples

### Python — stdlib xml.etree.ElementTree (potentially vulnerable)

```python
# VULNERABLE: stdlib ET does not defend against all entity-expansion DoS
# Python < 3.8.6 / 3.9.1 has no entity count limits; newer versions have partial
# mitigations but defusedxml is the only guaranteed-safe drop-in.
import xml.etree.ElementTree as ET
from flask import request

@app.route('/import', methods=['POST'])
def import_xml():
    data = request.data          # attacker supplies billion-laughs payload
    root = ET.fromstring(data)   # expat expands entities — may exhaust memory
    return process(root)

# SECURE: use defusedxml drop-in
import defusedxml.ElementTree as ET
from flask import request

@app.route('/import', methods=['POST'])
def import_xml():
    data = request.data
    root = ET.fromstring(data)   # entity expansion blocked unconditionally
    return process(root)
```

### Python — lxml

```python
# VULNERABLE: lxml resolves and expands entities by default
from lxml import etree
from flask import request

@app.route('/parse', methods=['POST'])
def parse():
    parser = etree.XMLParser()           # no resolve_entities=False -> entity expansion enabled
    tree = etree.fromstring(request.data, parser)
    return tree.tag

# ALSO VULNERABLE: resolve_entities=False without load_dtd=False still loads DTD
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)   # DTD is still loaded and parsed
tree = etree.fromstring(data, parser)              # quadratic blowup still possible

# SECURE: disable both entity resolution and DTD loading
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
tree = etree.fromstring(data, parser)
```

### Java — DocumentBuilder (DOM)

```java
// VULNERABLE: default DocumentBuilderFactory expands entities without limit
@PostMapping("/upload")
public ResponseEntity<?> uploadXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    // A billion-laughs payload will spin the JVM until OOM
    return ResponseEntity.ok(process(doc));
}

// SECURE: prohibit DOCTYPE declarations entirely
@PostMapping("/upload")
public ResponseEntity<?> uploadXml(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    return ResponseEntity.ok(process(doc));
}
```

### Java — SAXParser

```java
// VULNERABLE: default SAXParserFactory allows DTD and entity expansion
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);   // entity expansion: unbounded

// SECURE: prohibit DOCTYPE
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
SAXParser parser = factory.newSAXParser();
parser.parse(inputStream, handler);
```

### Java — XMLInputFactory (StAX)

```java
// VULNERABLE: default StAX factory supports DTD and entity expansion
XMLInputFactory xif = XMLInputFactory.newInstance();
XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

// SECURE: disable DTD support
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);
```

### .NET — XmlDocument / XmlReader

```csharp
// VULNERABLE: XmlDocument with default settings (DtdProcessing.Parse in older .NET)
XmlDocument doc = new XmlDocument();
doc.Load(stream);   // entity expansion unbounded in .NET Framework

// VULNERABLE: XmlReaderSettings with DtdProcessing.Parse
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Parse   // explicit opt-in to DTD processing
};
XmlReader reader = XmlReader.Create(stream, settings);

// SECURE: prohibit DTD
XmlReaderSettings settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
XmlReader reader = XmlReader.Create(stream, settings);
XmlDocument doc = new XmlDocument { XmlResolver = null };
doc.Load(reader);

// Note: XDocument.Load() and XElement.Load() in .NET Core 3.0+ prohibit DTD
// by default, but explicitly passing an XmlReader with DtdProcessing.Parse
// re-enables it. Check the call chain.
```

### PHP — simplexml / DOMDocument

```php
// VULNERABLE: simplexml_load_string with no entity loading disabled
function parseXml(string $xml): SimpleXMLElement {
    return simplexml_load_string($xml);   // in-document entities expanded
}

// VULNERABLE: DOMDocument without flag protection
function parseXml(string $xml): DOMDocument {
    $doc = new DOMDocument();
    $doc->loadXML($xml);   // entity expansion enabled by default
    return $doc;
}

// BETTER (but not foolproof): avoid LIBXML_DTDLOAD, use LIBXML_NONET
function parseXml(string $xml): DOMDocument {
    $doc = new DOMDocument();
    // LIBXML_NOENT EXPANDS entities — do NOT use it thinking it disables them
    $doc->loadXML($xml, LIBXML_NONET);   // only blocks network resolution
    return $doc;
}

// MOST SECURE for PHP: reject any input containing a DOCTYPE declaration
function parseXml(string $xml): DOMDocument {
    if (preg_match('/<!DOCTYPE/i', $xml)) {
        throw new InvalidArgumentException('DOCTYPE declarations are not permitted');
    }
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NONET | LIBXML_NOERROR);
    return $doc;
}
```

### Ruby — Nokogiri

```ruby
# VULNERABLE: noent option enables entity substitution (both external and internal)
def parse_upload(xml_input)
  Nokogiri::XML(xml_input) { |config| config.noent }
  # config.noent expands internal entities — billion-laughs will exhaust RAM
end

# ALSO RISKY: REXML is vulnerable to entity expansion DoS by default
require 'rexml/document'
def parse_upload(xml_input)
  REXML::Document.new(xml_input)   # entity expansion unbounded; known DoS vector
end

# SECURE: default Nokogiri (no config block, no noent)
def parse_upload(xml_input)
  Nokogiri::XML(xml_input)   # entity expansion not performed by default
end
```

### Node.js — fast-xml-parser and xml2js

```javascript
// VULNERABLE: fast-xml-parser < 4.x with processEntities defaulting to true
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser();            // processEntities: true by default in < 4.x
const result = parser.parse(xmlInput);     // entity expansion enabled

// ALSO VULNERABLE: explicitly enabling processEntities
const parser = new XMLParser({ processEntities: true });
const result = parser.parse(xmlInput);

// SECURE: disable entity processing
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser({ processEntities: false });
const result = parser.parse(xmlInput);

// xml2js: generally safe by default (v0.5+) — does not resolve entities
// Flag only if a custom parser is injected or an older version is pinned
const xml2js = require('xml2js');
xml2js.parseString(xmlInput, (err, result) => { /* safe by default */ });
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Find XML Parsing Sites Without Entity-Expansion Protection

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where XML is parsed without DTD processing or entity expansion being explicitly disabled. Write results to `sast/xmlbomb-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, XML libraries in use, and any XML-accepting endpoints.
>
> **What to flag — XML parsing sites lacking entity-expansion protection**:
>
> Flag any XML parsing call where there is **no adjacent, paired hardening** that disables DTD processing or limits entity expansion. You are not yet tracing whether the input is user-controlled — that is Phase 2's job.
>
> 1. **Python — stdlib parsers (flag unless defusedxml is used as the drop-in replacement)**:
>    - `xml.etree.ElementTree.parse(...)`, `ET.fromstring(...)`, `ET.iterparse(...)`
>    - `xml.dom.minidom.parseString(...)`, `xml.dom.minidom.parse(...)`
>    - `xml.sax.parseString(...)`, `xml.sax.parse(...)`
>    - `xmltodict.parse(...)` — entity expansion behavior depends on expat version; flag for review
>
> 2. **Python — lxml (flag unless `resolve_entities=False` AND `load_dtd=False` are both set)**:
>    - `etree.parse(...)`, `etree.fromstring(...)`, `etree.XML(...)`
>    - `etree.XMLParser(...)` without both `resolve_entities=False` and `load_dtd=False`
>    - `objectify.parse(...)`, `objectify.fromstring(...)`
>    - Flag `etree.XMLParser(resolve_entities=False)` alone — it still loads the DTD, enabling quadratic blowup
>
> 3. **Java — flag any instantiation of these without the matching hardening**:
>    - `DocumentBuilderFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` or `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
>    - `SAXParserFactory.newInstance()` without `disallow-doctype-decl` feature set
>    - `XMLInputFactory.newInstance()` without `SUPPORT_DTD=false`
>    - `TransformerFactory.newInstance()` used with untrusted XML source — XSLT transforms also parse XML
>    - Spring `MarshallingHttpMessageConverter` with `Jaxb2Marshaller` if entity expansion not disabled
>
> 4. **PHP — flag these without explicit DOCTYPE rejection or entity loading disabled**:
>    - `simplexml_load_string(...)`, `simplexml_load_file(...)`
>    - `DOMDocument::loadXML(...)`, `DOMDocument::load(...)`
>    - `SimpleXMLElement::__construct(...)` with raw string input
>    - `xml_parse(...)` with `xml_parser_create()` — expat-backed, check entity limits
>    - **Critical note**: `LIBXML_NOENT` **expands** entities — it is NOT protection. Flag code that uses `LIBXML_NOENT` as a misguided "fix"
>
> 5. **.NET — flag any of these without `DtdProcessing.Prohibit` (or `DtdProcessing.Ignore`)**:
>    - `new XmlDocument()` followed by `.Load(...)` or `.LoadXml(...)` without `XmlResolver = null` and a prohibiting reader
>    - `new XmlTextReader(...)` — legacy; DTD processing on by default in .NET Framework
>    - `XmlReader.Create(...)` with `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }`
>    - `XmlReader.Create(...)` without explicit `XmlReaderSettings` (default may vary by .NET version)
>    - `XPathDocument(...)` without a prohibiting reader
>    - `XDocument.Load(stream)` where `stream` is fed from user input and no reader settings control DTD — safe by default in .NET Core 3+ only when not using a custom XmlReader
>
> 6. **Node.js — flag these when entity processing is enabled or default-on**:
>    - `fast-xml-parser` `XMLParser({ processEntities: true })` — explicit opt-in
>    - `fast-xml-parser` `new XMLParser()` without `processEntities: false` in versions < 4.x (check `package.json` for version)
>    - `node-expat` parser — entity expansion behavior depends on configuration
>    - `libxmljs.parseXmlString(...)` — backed by libxml2; check entity limits
>
> 7. **Ruby — flag these when entity expansion is not blocked**:
>    - `Nokogiri::XML(input) { |config| config.noent }` — `noent` enables entity substitution
>    - `REXML::Document.new(input)` — REXML is historically vulnerable to entity expansion DoS; always flag when used with untrusted input
>    - `LibXML::XML::Document.string(input)` — check entity configuration
>
> **What to skip** (these are safe patterns — do not flag):
> - `import defusedxml` used as the XML parser (Python) — entity expansion blocked at the library level
> - `etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)` (lxml)
> - Java factories with `disallow-doctype-decl` set to `true`
> - Java factories with `FEATURE_SECURE_PROCESSING` set to `true`
> - Java `XMLInputFactory` with `SUPPORT_DTD` set to `false`
> - .NET `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }`
> - .NET `XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore }`
> - Nokogiri default usage (no config block or config block without `noent`)
> - `fast-xml-parser` with `processEntities: false`
> - Parsing of static, bundled, non-user-influenced XML (e.g., reading `config.xml` from the deployment package at startup with no user input involved)
> - A pre-parse check that rejects input containing `<!DOCTYPE` (effective but fragile — flag with low confidence if the check looks robust)
>
> **Output format** — write to `sast/xmlbomb-recon.md`:
>
> ```markdown
> # XML Bomb Recon: [Project Name]
>
> ## Summary
> Found [N] XML parsing sites without explicit entity-expansion protection.
>
> ## Parsing Sites Without Entity-Expansion Protection
>
> ### 1. [Descriptive name — e.g., "ET.fromstring without defusedxml in upload handler"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Parser / library**: [e.g., Python stdlib ET / lxml etree / Java DocumentBuilder / PHP DOMDocument]
> - **Missing hardening**: [what protection is absent — e.g., "no defusedxml", "load_dtd not set to False", "disallow-doctype-decl feature not set", "SUPPORT_DTD not false"]
> - **Input variable(s)**: `var_name` — [brief note on apparent origin, e.g., "HTTP request body" or "file upload content" or "unclear"]
> - **Entity-expansion risk**: [e.g., "exponential blowup via nested entities", "quadratic blowup via repeated large entity", "both"]
> - **Code snippet**:
>   ```
>   [the XML parsing call and surrounding context, 5-15 lines]
>   ```
>
> [Repeat for each site]
> ```

### Between Phases: Check Recon Results

After Phase 1 completes, read `sast/xmlbomb-recon.md`. If the summary states zero parsing sites were found (or the file contains no entries under "Parsing Sites Without Entity-Expansion Protection"), **do not launch Phase 2 or Phase 3**. Instead:

1. Write `No vulnerabilities found.` to `sast/xmlbomb-results.md`.
2. Write `{"findings":[]}` to `sast/xmlbomb-results.json`.
3. **Delete** `sast/xmlbomb-recon.md`.
4. Stop.

Only proceed to Phase 2 if at least one vulnerable parsing site was identified.

### Phase 2: Verify — Trace User Input (Batched)

After Phase 1 completes, read `sast/xmlbomb-recon.md` and split the entries under "Parsing Sites Without Entity-Expansion Protection" into **batches of up to 3 sites each** (use the numbered `###` sections). Launch **one subagent per batch in parallel**. Each subagent traces taint only for its assigned sites and writes to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/xmlbomb-recon.md` and count the numbered site sections (### 1., ### 2., etc.).
2. Divide into batches of up to 3. For example: 7 sites → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/xmlbomb-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include those selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned XML parsing site, determine whether a user-supplied value reaches the XML parser without entity-expansion protection. Our goal is to find XML entity-expansion DoS vulnerabilities (CWE-776 — "XML Bomb"). Write results to `sast/xmlbomb-batch-[N].md`.
>
> **Your assigned parsing sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, file upload handlers, message queue consumers, and how data flows through the application.
>
> **Scope reminder**: You are looking for DoS via entity expansion (billion laughs / quadratic blowup). Do NOT flag or describe file-read or SSRF attack chains — those belong to sast-xxe. If a parsing site is vulnerable to both, set `chain_id: "xml-attack-surface"` in the JSON output — the two skills report independently but share the chain.
>
> **For each parsing site, trace the XML input variable(s) backwards to their origin**:
>
> 1. **Direct user input** — the XML content comes directly from a request source:
>    - HTTP request body (especially `Content-Type: application/xml`, `text/xml`, `application/soap+xml` endpoints): `request.body`, `req.body`, `request.data`, `php://input`, `HttpContext.Request.Body`
>    - File uploads: `request.FILES`, `req.file`, `multipart/form-data` fields
>    - HTTP query parameters or form fields containing an XML snippet
>    - WebSocket messages parsed as XML
>
> 2. **Indirect user input** — the XML is derived from user input through intermediate steps:
>    - A filename supplied by the user is used to open and parse a file (but the file may also have been uploaded by the user)
>    - A URL supplied by the user is fetched and the response is parsed as XML (SSRF precondition — only flag the entity expansion aspect here)
>    - User input is embedded into an XML template before parsing
>    - Variable passed through helper functions — trace the full call chain
>
> 3. **Second-order / stored input** — the XML was stored (DB, filesystem, object storage) from a prior user-controlled upload or POST, and is now being parsed asynchronously:
>    - Find where the stored content was originally written — was it user-supplied at write time?
>    - Was it validated or sanitized before storage (e.g., DOCTYPE stripped)?
>    - Background jobs and worker queues are common second-order paths
>
> 4. **Server-side / hardcoded source** — the XML comes from a bundled resource, config file, or server-generated content with no user influence — this site is NOT exploitable
>
> **For each parsing site, assess exploitability**:
> - Is the endpoint authenticated? (Reduces risk but does not eliminate it — authenticated users can still DoS)
> - Is the endpoint publicly accessible without rate limiting? (Raises severity to critical)
> - Is the service behind a load balancer or cloud provider that enforces request body size limits? (e.g., AWS API Gateway default max 10 MB body)
> - Does the endpoint process many requests concurrently? (Increases blast radius — even a single request can block worker threads)
> - Is this a health check, webhook receiver, or SOAP service? (These are often unauthenticated and XML-accepting — highest risk tier)
>
> **Verify question**: Does user-controlled XML containing a DOCTYPE declaration with recursive or repeated entity definitions reach an XML parser that does not prohibit DTD processing or limit entity expansion depth/count?
>
> **FP-killers** (if any of these apply, mark NOT VULNERABLE or reduce confidence):
> - The XML input is validated against a schema *before* parsing with the vulnerable parser, and the schema rejects DOCTYPE — check that the validator actually sees the raw input and rejects it
> - A regex or string search for `<!DOCTYPE` or `<!ENTITY` is applied to the raw bytes before parsing — this is a partial mitigation, flag as LIKELY VULNERABLE with low confidence
> - The application is running with a JVM `-XX:MaxHeapSize` or OS `ulimit` that would prevent a complete DoS (the service crashes but other services on the host survive) — still flag, lower severity to medium
> - Request body size is limited at the web framework layer (e.g., `MAX_CONTENT_LENGTH` in Flask, `client_max_body_size` in nginx) — a billion-laughs payload typically fits in under 1 KB, so body size limits do NOT prevent the attack. Do not use body size limits as an FP-killer unless the limit is under 256 bytes
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the unguarded XML parser. No effective mitigation between the trust boundary and the parser call.
> - **Likely Vulnerable**: User input probably reaches the parser (indirect or stored flow), or the parser is unguarded but the input path is partially obscured.
> - **Not Vulnerable**: The XML source is fully server-controlled, OR effective hardening is present (DTD prohibited, entity expansion disabled or limited, defusedxml used).
> - **Needs Manual Review**: Cannot determine the input source with confidence, or the hardening configuration is complex and requires runtime verification.
>
> **Output format** — write to `sast/xmlbomb-batch-[N].md`:
>
> ```markdown
> # XML Bomb Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP request body flows into ET.fromstring without defusedxml — entity expansion unbounded"]
> - **Taint trace**: [Step-by-step from entry point to the parsing call — e.g., "request.data -> body -> ET.fromstring(body)"]
> - **Attack variant**: [Exponential / Quadratic / Both]
> - **Severity**: [critical / high / medium — with rationale]
> - **Exploitability**: [reachable / conditional — with rationale: authenticated?, rate-limited?, body size limit?]
> - **Impact**: [e.g., "Single HTTP request exhausts server heap, rendering the service unresponsive until OOM kill or process restart"]
> - **Remediation**: [Specific fix — e.g., "Replace `import xml.etree.ElementTree as ET` with `import defusedxml.ElementTree as ET`", "Set `dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`", "Add `processEntities: false` to XMLParser options"]
> - **chain_id**: ["xml-attack-surface" if the same parse call is also flagged by sast-xxe; null otherwise]
> - **Dynamic Test**:
>   ```
>   [Proof-of-concept showing how to trigger the vulnerability.
>    Show the endpoint, Content-Type header, and the bomb payload.
>    Example:
>    curl -X POST https://app.example.com/api/upload \
>      -H "Content-Type: application/xml" \
>      -d '<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY bomb "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">]><root>&bomb;</root>'
>    Expected: the server hangs, returns 503, or the worker process is killed by OOM.]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "XML content stored from user upload parsed asynchronously without hardening" or "Input path through helper function not fully traceable"]
> - **Taint trace**: [Best-effort trace with the uncertain step identified]
> - **Concern**: [Why it's still a risk despite uncertainty — e.g., "If the stored XML originated from a user upload, a bomb payload would survive to the async worker"]
> - **Remediation**: [Apply appropriate parser hardening at the parse site regardless of whether the input is user-controlled — defense in depth]
> - **chain_id**: ["xml-attack-surface" if applicable; null otherwise]
> - **Dynamic Test**:
>   ```
>   [payload to attempt, or manual tracing steps if dynamic test is not straightforward]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "defusedxml used as drop-in replacement", "DTD processing explicitly prohibited", "XML read from bundled config file with no user influence"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why the input source or parser configuration could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Follow `load_document()` in xml_utils.py to confirm whether its argument comes from a user request or a bundled resource"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/xmlbomb-batch-*.md` file and merge them. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/xmlbomb-batch-1.md`, `sast/xmlbomb-batch-2.md`, ... files.
2. Collect all findings, preserving every detail field. Count totals across batches.
3. Write the merged human-readable report to `sast/xmlbomb-results.md`:

```markdown
# XML Bomb Analysis Results: [Project Name]

## Executive Summary
- Parsing sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

4. Write the canonical machine-readable findings to `sast/xmlbomb-results.json`. Emit one JSON object with a `findings` array. Each entry must conform to the schema below. Use sequential IDs starting from `xmlbomb-001`. Preserve all detail from the batch results; synthesize `description` from `Issue` + `Impact` + `Taint trace` if not already a single prose block.

```json
{
  "findings": [
    {
      "id": "xmlbomb-001",
      "skill": "sast-xmlbomb",
      "severity": "high",
      "title": "ET.fromstring processes untrusted request body without entity-expansion protection",
      "description": "The Flask endpoint at /api/import passes request.data directly to xml.etree.ElementTree.fromstring() without using defusedxml. A billion-laughs DTD payload of under 1 KB can expand to gigabytes of in-memory data, crashing the worker process.",
      "location": { "file": "app/views/import.py", "line": 42, "column": 12 },
      "remediation": "Replace `import xml.etree.ElementTree as ET` with `import defusedxml.ElementTree as ET`. No other code changes required — the API is drop-in compatible.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "xml-attack-surface"
    }
  ]
}
```

If no VULNERABLE or LIKELY VULNERABLE findings exist across all batches, write `{"findings":[]}` to `sast/xmlbomb-results.json`.

5. After writing both output files, **delete all intermediate files**: `sast/xmlbomb-recon.md` and every `sast/xmlbomb-batch-*.md`.

---

## chain_id Values

| chain_id | Meaning |
|---|---|
| `"xml-attack-surface"` | The same XML parsing site is also reported by sast-xxe (CWE-611). Both entity expansion DoS (this skill) and external entity exfiltration (XXE) are possible from the same unguarded parser call. Include this chain_id on any finding where the parser also resolves external entities (i.e., neither `resolve_entities=False` nor `no_network=True` nor `disallow-doctype-decl` is set). |
| `null` | No related finding in another skill. The parser has some hardening that prevents XXE but not entity expansion, e.g., `LIBXML_NONET` (PHP) or `resolve_entities=False` without `load_dtd=False` (lxml). |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 parsing sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file.
- **This skill targets DoS only.** File-read and SSRF via external entities belong to sast-xxe. If a site is vulnerable to both, set `chain_id: "xml-attack-surface"` and let each skill report independently.
- **Body size limits do NOT prevent billion-laughs attacks.** A 500-byte payload triggers a billion-element expansion. Never dismiss a finding because the endpoint has a body size limit.
- **`LIBXML_NOENT` in PHP expands entities — it does NOT disable them.** Code that adds `LIBXML_NOENT` thinking it is a security fix is actually more vulnerable, not less. Flag such code with confidence: high.
- **`resolve_entities=False` alone in lxml is insufficient.** The DTD is still loaded and parsed. Setting `load_dtd=False` is required to block entity expansion at the DTD loading stage.
- **REXML (Ruby)** has a long history of entity expansion DoS vulnerabilities. Flag any use of REXML with untrusted input at confidence: high unless a modern version with explicit limits is confirmed.
- **`FEATURE_SECURE_PROCESSING` (Java)** imposes expansion limits but does not strictly prohibit DOCTYPE. `disallow-doctype-decl` is the stronger setting and is preferred. If only `FEATURE_SECURE_PROCESSING` is set, classify as LIKELY VULNERABLE with medium confidence.
- **Authenticated endpoints are still vulnerable.** An authenticated attacker (or a compromised account) can DoS the service. Lower severity to medium only if the service has very few trusted users and rate limiting is in place.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable." False negatives are worse than false positives in security assessment.
- Clean up intermediate files after both output files are written.
