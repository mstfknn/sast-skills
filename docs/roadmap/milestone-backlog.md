# Backlog — lower-priority skills (detailed plan)

6 Tier-A/C skills. See [../ROADMAP.md](../ROADMAP.md) and the per-skill task in it.

---

## sast-xpath — XPath injection

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-643

**Scope.** User-controlled input concatenated or interpolated into an XPath expression that is
then evaluated against an XML document. NOT: XPath queries built entirely from constants;
XPath evaluated against data the application itself authored; parameterised XPath APIs where
user input is bound as a typed variable (not string-concatenated).

**Recon sinks** (recon-phase grep/AST targets):

| Language | Sinks |
|---|---|
| Java | `XPathExpression.evaluate`, `XPath.compile`, `XPath.evaluate`, `DOMXPath` with string concat |
| .NET | `XPathNavigator.Select`, `XPathNavigator.Evaluate`, `XmlNode.SelectNodes`, `XmlNode.SelectSingleNode` |
| Python | `lxml.etree.XPath(f"…{user}…")`, `lxml` `.xpath()` with f-string or `%` format, `ElementTree` string concat |
| PHP | `DOMXPath::query`, `DOMXPath::evaluate`, `xpath()` on `SimpleXMLElement` with concat |
| Ruby | `Nokogiri::XML::Node#xpath` with interpolated string |

**Verify.** Does the XPath expression string include a value that crossed a trust boundary (request
parameter, header, cookie, file, environment)? FP-killers: expression is a compile-time constant;
user value is bound via a parameterised XPath variable binding (e.g. `XPathVariableResolver`);
input is strictly integer-validated before use. `exploitability: reachable` when untrusted input
reaches the sink with no binding layer; `confidence: high` for direct parameter→sink flow,
`medium` when data flows through an intermediate variable.

**Severity.** Default **high** (authentication bypass, data exfiltration from XML store). Raise
to **critical** when the XML document contains credentials or session tokens. Lower to **medium**
when the XPath result is never returned to the caller and cannot be used to branch on sensitive data.

**Remediation.** Never concatenate user input into XPath strings. Use a parameterised XPath
variable-resolver (Java `XPathVariableResolver`, .NET `XsltContext`) or rewrite the query to
use only constants and pass user data through a typed API. Validate input strictly before
any XPath construction.

**Chains with.** `sast-xxe` (the same XML parser may also expand entities) →
`chain_id` "xml-attack-surface".

**Test fixture.** TP: `xpath.evaluate("//user[name='" + req.getParameter("user") + "']", doc)`.
TN: expression is a string literal with no user data. TN: user value bound via
`XPathVariableResolver` with no string concat. Assert only the TP is flagged, `reachable`,
`high`.

---

## sast-csvinj — Formula / CSV injection

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-1236

**Scope.** User-controlled cell values starting with `=`, `+`, `-`, or `@` written to a CSV or
spreadsheet (XLSX, ODS) export without sanitisation, enabling formula execution when the file is
opened in a spreadsheet application. NOT: values that are always numeric or date; server-side
CSV consumed only by a parser (not a spreadsheet); exports where every field is wrapped in
a safe prefix or the leading character is escaped.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Library | Sinks |
|---|---|
| Python | `csv.writer.writerow` / `writerows`, `openpyxl.Worksheet.append`, `xlwt.Worksheet.write`, `pandas.DataFrame.to_csv`, `pandas.DataFrame.to_excel` |
| Java | `opencsv.CSVWriter.writeNext`, `Apache POI Cell.setCellValue` |
| Ruby | `CSV.generate` / `CSV::Row`, `caxlsx` cell writes |
| PHP | `fputcsv(`, `PhpSpreadsheet` `Cell::setValue` |
| Node | `csv-stringify` write, `exceljs` `addRow`, `papaparse` `unparse` |

**Verify.** Is any value in the written row or cell derived from user input and written without
a leading-character escape (prepend `'` or strip leading `=+-@`)? FP-killers: value is forced
to a numeric type before write; a sanitiser strips or prefixes the character; the export is
served with `Content-Disposition: attachment` AND the consumer is a machine parser only (no
human spreadsheet open). `exploitability: reachable` for direct user-field→CSV write;
`confidence: high` when the field name matches a user-controlled entity attribute, `medium`
when the flow crosses a service boundary.

**Severity.** Default **medium** (requires victim to open file and accept formula execution
prompt). Raise to **high** when the application exports financial, HR, or compliance data
likely to be opened in Excel/Sheets without security warnings disabled.

**Remediation.** Prefix any cell value starting with `=`, `+`, `-`, or `@` with a single
quote (`'`) before writing, or reject such leading characters for non-numeric fields. For
server-generated reports where spreadsheet formula execution is never needed, enforce strict
numeric/date typing for all computed columns.

**Chains with.** `sast-pii` (exported fields often contain personal data) →
`chain_id` "data-export-risk".

**Test fixture.** TP: `writer.writerow([user_name, user_input])` where `user_input` is
`=HYPERLINK(...)`. TN: `writer.writerow([name, str(int(amount))])` (forced numeric). TN:
value prefixed with `"'" + cell_value`. Assert only the TP is flagged, `reachable`, `medium`.

---

## sast-xmlbomb — XML entity-expansion DoS

**Framework:** Web25 A10 · **Tier:** A · **CWE:** CWE-776

**Scope.** XML parsers configured to allow DTD processing and recursive entity expansion,
enabling a billion-laughs / quadratic-blowup payload to exhaust CPU or memory. Distinct from
XXE (CWE-611): this skill targets DoS via entity expansion only, not file/SSRF exfiltration.
NOT: parsers with DTD or entity expansion explicitly disabled; parsers operating on
internally-generated XML with no user input path.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Library | Sinks |
|---|---|
| Python | `xml.etree.ElementTree.parse` / `fromstring` (stdlib, no DTD guard by default in older versions), `lxml.etree.parse` without `resolve_entities=False`, `defusedxml` NOT used |
| Java | `DocumentBuilderFactory` without `setFeature("…disallow-doctype-decl", true)`, `SAXParserFactory` without disabling external entities, `XMLInputFactory` without `SUPPORT_DTD=false` |
| .NET | `XmlReaderSettings` with `DtdProcessing.Parse` (not `Prohibit`), `XDocument.Load` / `XElement.Load` without `XmlReaderSettings` guard |
| PHP | `simplexml_load_string` / `DOMDocument::loadXML` without `LIBXML_NOENT` stripped and `LIBXML_DTDLOAD` disabled |
| Ruby | `Nokogiri::XML` with `NONET` but without `NOENT` |
| Node | `xml2js` / `fast-xml-parser` with `processEntities: true` (default in some versions) |

**Verify.** Does the parser receive bytes from a trust boundary (HTTP body, upload, message
queue) AND is DTD or entity processing enabled (or not explicitly disabled)? FP-killers:
`defusedxml` wraps the call; `FEATURE_SECURE_PROCESSING` set on Java factory; `DtdProcessing.Prohibit`
on .NET; `libxml2` flags disable entity loading. `exploitability: reachable` when untrusted XML
reaches an unguarded parser; `confidence: high` for a direct request→parse flow without any
wrapper.

**Severity.** Default **high** (unauthenticated DoS on any endpoint accepting XML). Raise
to **critical** when the endpoint is public and processes large documents or is called in a
tight loop. Lower to **medium** when the service runs behind a WAF that limits request body size.

**Remediation.** Disable DTD processing entirely: Python — use `defusedxml` or
`lxml.etree.XMLParser(resolve_entities=False, no_network=True)`; Java — set
`FEATURE_SECURE_PROCESSING` and `disallow-doctype-decl`; .NET — `DtdProcessing.Prohibit`;
PHP — pass `LIBXML_NONET | LIBXML_NOENT` and unset `LIBXML_DTDLOAD`. Never process DTDs from
untrusted sources.

**Chains with.** `sast-xxe` (same parser configuration often enables both XXE and entity DoS) →
`chain_id` "xml-attack-surface".

**Test fixture.** TP: `ET.fromstring(request.data)` (stdlib, no guard) with a billion-laughs
payload. TN: `defusedxml.ElementTree.fromstring(request.data)`. TN: `lxml.etree.parse(src,
lxml.etree.XMLParser(resolve_entities=False))`. Assert only the TP is flagged, `reachable`,
`high`.

---

## sast-elinj — Expression language / OGNL / SpEL injection

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-917

**Scope.** User-controlled input passed to an expression-language evaluator (Struts OGNL,
Spring SpEL, JSP EL, Pebble/Freemarker expression evaluation, Mvel, JEXL) that can execute
arbitrary Java or scripted code. Distinct from SSTI (CWE-94 / `sast-ssti`): this skill targets
programmatic EL/OGNL/SpEL API calls, not template-engine rendering pipelines. NOT: SpEL
expressions built entirely from constants; expressions evaluated in a sandboxed
`SimpleEvaluationContext` with no method invocations allowed; OGNL on non-user-controlled data.

**Recon sinks** (recon-phase grep/AST targets):

| Language / Framework | Sinks |
|---|---|
| Java — Spring SpEL | `SpelExpressionParser().parseExpression(userInput)`, `ExpressionParser.parseExpression` with concat |
| Java — Struts OGNL | OGNL `getValue` / `setValue` on request-derived expression string |
| Java — MVEL | `MVEL.eval(userInput, …)`, `MVEL.compile` |
| Java — JEXL | `JexlEngine.createExpression(userInput)`, `JexlScript` from user string |
| Java — JSP EL | `ExpressionFactory.createValueExpression(ctx, userInput, …)` |
| Python — simpleeval | `simple_eval(userInput)` when used to evaluate arbitrary expressions |
| Python — asteval | `Interpreter()(userInput)` on untrusted input |

**Verify.** Is the expression string or any sub-expression derived from a trust boundary
(request parameter, header, cookie, config read from an editable store)? FP-killers: SpEL
uses `SimpleEvaluationContext` (method calls disabled); expression string is a compile-time
constant; a strict allowlist validates the expression before evaluation; sandboxing policy
blocks Java reflection. `exploitability: reachable` for direct user-input→evaluator flow;
`confidence: high` when the source is a request parameter, `medium` when the source is a
configuration value editable by lower-privilege users.

**Severity.** Default **critical** (arbitrary code execution via expression evaluator). Lower
to **high** when `SimpleEvaluationContext` is used (limited, but property access may still
leak data). Lower to **medium** when a strict expression allowlist is in place but not
verified by the tool.

**Remediation.** Never pass user-controlled strings to an expression evaluator. For Spring SpEL,
use `SimpleEvaluationContext` with property access only (no method invocations) and build
expressions from constants. For Struts, upgrade to a version with OGNL sandbox controls and
never interpolate request parameters into action or redirect expressions. For dynamic
evaluation needs, use a purpose-built safe evaluator (e.g. `simpleeval` with operator
restrictions) and apply strict allowlisting.

**Chains with.** `sast-ssti` (template engines and EL injections often co-exist in the same
stack) → `chain_id` "code-injection-surface".

**Test fixture.** TP: `new SpelExpressionParser().parseExpression(req.getParameter("expr")).getValue()`.
TN: `parser.parseExpression("user.name").getValue(ctx)` (constant expression). TN:
`SimpleEvaluationContext` restricts method calls. Assert only the TP is flagged, `reachable`,
`critical`.

---

## sast-lockfile — Lockfile integrity / dependency pinning absent

**Framework:** Web25 A03 · **Tier:** A · **CWE:** CWE-494

**Scope.** Dependencies installed without integrity verification: missing lockfile, lockfile
not committed, packages without pinned hashes, install commands that bypass hash-checking, or
installation from an unverified URL or mutable git ref (branch name, `HEAD`). NOT: development-only
dependencies where the runtime artefact is independently signed and hash-verified; monorepo
workspaces where the root lockfile is present and covers all workspaces.

**Recon sinks** (recon-phase grep/AST targets):

| Ecosystem / Artefact | Sinks |
|---|---|
| Python / pip | `requirements.txt` without `--hash` entries; `pip install <url>` or `pip install git+https://…@branch`; absent `uv.lock` / `poetry.lock` / `Pipfile.lock` |
| Node / npm | `package.json` present but `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` absent or gitignored; `npm install --no-package-lock`; `integrity` field stripped from lockfile |
| Docker | `RUN pip install`, `RUN npm install`, `RUN curl … \| sh` without pinned digest |
| Ruby | `Gemfile` without `Gemfile.lock` committed; `gem install` from git without `:ref` SHA |
| Go | `go.mod` present but `go.sum` absent or gitignored |
| GitHub Actions | `uses: actions/checkout@main` or `uses: owner/action@v1` without full SHA pin |

**Verify.** Is there an install command, manifest, or CI step that fetches a dependency without
a pinned content hash or version digest? FP-killers: lockfile is present and committed with
`integrity`/hash fields; all `requirements.txt` entries use `==<version>` AND `--require-hashes`;
GitHub Actions steps use full 40-character SHA. `exploitability: conditional` — requires an
attacker to compromise the registry or CDN; `confidence: high` when the lockfile is provably
absent from the repository, `medium` when hash fields are present for some but not all
packages.

**Severity.** Default **high** (supply-chain compromise enables arbitrary code execution at
install time). Raise to **critical** when the missing pin is for a package that runs at
build time with broad filesystem or network access (e.g. a postinstall script). Lower to
**medium** for dev-only tooling not included in production artefacts.

**Remediation.** Commit lockfiles to version control and fail CI if they are out of date.
For pip, use `pip install --require-hashes -r requirements.txt` or switch to `uv lock`.
For npm, run `npm ci` (not `npm install`) in CI. Pin GitHub Actions to full commit SHAs.
Avoid installing packages from mutable git refs or raw URLs; if necessary, pin to a specific
commit SHA and verify a checksum.

**Chains with.** `sast-deps` (a lockfile without hashes means known-CVE detection is also
unreliable) → `chain_id` "supply-chain-risk".

**Test fixture.** TP: `requirements.txt` with `requests==2.31.0` (no `--hash`), no `uv.lock`
or `poetry.lock` present. TN: `requirements.txt` with every entry having a `--hash=sha256:…`
suffix. TN: `uv.lock` present and committed. Assert only the TP is flagged, `conditional`,
`high`.

---

## sast-paymentlogic — E-commerce business-logic abuse

**Framework:** API23 API6 · **Tier:** C · **CWE:** CWE-840

**Scope.** The single business-logic sub-category worth splitting from `sast-businesslogic`:
price/quantity manipulation, coupon and wallet stacking abuse, refund fraud, negative-amount
injection, and race conditions on balance or inventory. Any endpoint that computes a monetary
total, applies a discount, processes a refund, or debits/credits a balance. NOT: general
access-control logic (stays in `sast-missingauth`); non-monetary business rules; pure UI
validation that is also enforced server-side; general race conditions (stays in `sast-race`
unless the race directly targets a monetary balance).

**Recon sinks** (recon-phase grep/AST targets):

| Pattern | Sinks |
|---|---|
| Price / quantity | Server-side total computed from client-supplied `unit_price`, `amount`, or `quantity` without server-side re-lookup; `price * quantity` where `price` comes from request body |
| Coupon stacking | Coupon/promo redemption without a per-user or per-order uniqueness check; no `applied_coupons` set checked before insert |
| Refund / credit | Refund amount derived from a client-supplied value instead of the original charge record; credit applied without checking `max_credit_balance` |
| Negative amount | `amount` or `quantity` accepted as negative (integer underflow producing credit); no `> 0` guard before charge |
| Race on balance | `SELECT balance … UPDATE balance` without `SELECT … FOR UPDATE` or optimistic locking (`WHERE balance >= :amount`) |

**Verify.** Is a monetary value, quantity, discount amount, or balance delta read from client
input and applied without server-side re-derivation from authoritative records? FP-killers:
price is re-fetched from a products table (not trusted from the request); coupon is validated
against a single-use table with a unique index; refund amount is capped to the original charge
via a database lookup; amount has a `> 0` guard. `exploitability: reachable` when the path
is directly callable with crafted input; `confidence: high` for a direct request-field→charge
flow, `medium` when the field flows through an internal service.

**Severity.** Default **high** (direct financial loss or inventory manipulation). Raise to
**critical** when the manipulation can yield unbounded credit or a full account takeover via
negative-balance exploit. Lower to **medium** when the vulnerable path is rate-limited or
requires a privileged role.

**Remediation.** Never trust client-supplied prices or discount amounts — always re-derive
them from authoritative records at checkout. Enforce single-use coupon redemption with a
database unique constraint. Validate that all monetary amounts are positive before processing.
Use database-level locking (`SELECT … FOR UPDATE` or optimistic versioning) to prevent
race-condition balance manipulation. Log all discount and refund events for fraud-detection
alerting.

**Chains with.** `sast-race` (balance races are a subset) and `sast-missingauth` (unauthenticated
checkout is a prerequisite for some attacks) → `chain_id` "payment-fraud-surface".

**Test fixture.** TP: `total = request.json["unit_price"] * request.json["quantity"]` — price
trusted from body, no DB lookup. TN: `product = db.get(product_id); total = product.price * qty`
(server-side price lookup). TN: `if amount <= 0: raise ValidationError`. Assert only the TP is
flagged, `reachable`, `high`.
