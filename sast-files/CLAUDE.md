# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current directory.

---

## Step 1: Codebase Analysis & Threat Modeling

Before running, check if `sast/architecture.md` already exists. If it does, skip this step.

Run the sast-analysis skill directly (this one stays in-session since later steps depend on reading its output).

**Wait for this step to finish before proceeding.**

---

## Step 1b: Stack routing

Run the sast-stack skill (in-session, like sast-analysis) to detect the stack(s) and decide which detection skills are worth running. It writes `sast/stack.md`. Skip this step if `sast/stack.md` already exists.

**Wait for this step to finish before proceeding.**

---

## Step 2: Vulnerability Detection (Parallel)

Run the detection skills **selected by the router** in `sast/stack.md` — its `skills` list plus the `always_on` set — all at the same time, passing each its `profile` when one is set. The table below is the **full catalog** of detection skills (and their result / intermediate files); the router picks a subset of it. If `sast/stack.md` is missing, fall back to running every skill in the table. Skip any task where the output file already exists.

- Skip IDOR if `sast/idor-results.md` already exists.
- Skip SQLi if `sast/sqli-results.md` already exists.
- Skip SSRF if `sast/ssrf-results.md` already exists.
- Skip XSS if `sast/xss-results.md` already exists.
- Skip RCE if `sast/rce-results.md` already exists.
- Skip XXE if `sast/xxe-results.md` already exists.
- Skip File Upload if `sast/fileupload-results.md` already exists.
- Skip Path Traversal if `sast/pathtraversal-results.md` already exists.
- Skip SSTI if `sast/ssti-results.md` already exists.
- Skip JWT if `sast/jwt-results.md` already exists.
- Skip Missing Auth if `sast/missingauth-results.md` already exists.
- Skip Business Logic if `sast/businesslogic-results.md` already exists.
- Skip GraphQL injection if `sast/graphql-results.md` already exists.
- Skip Hardcoded Secrets if `sast/hardcodedsecrets-results.md` already exists.
- Skip CSRF if `sast/csrf-results.md` already exists.
- Skip Open Redirect if `sast/openredirect-results.md` already exists.
- Skip CORS if `sast/cors-results.md` already exists.
- Skip LDAP if `sast/ldap-results.md` already exists.
- Skip NoSQL if `sast/nosql-results.md` already exists.
- Skip Prototype Pollution if `sast/prototype-results.md` already exists.
- Skip ReDoS if `sast/redos-results.md` already exists.
- Skip Crypto if `sast/crypto-results.md` already exists.
- Skip Race Condition if `sast/race-results.md` already exists.
- Skip PII Logging if `sast/pii-results.md` already exists.
- Skip Vulnerable Dependencies if `sast/deps-results.md` already exists.
- Skip IaC if `sast/iac-results.md` already exists.
- Skip Prompt Injection if `sast/promptinjection-results.md` already exists.
- Skip LLM Output if `sast/llmoutput-results.md` already exists.
- Skip Insecure Deserialization if `sast/deser-results.md` already exists.
- Skip Error Handling if `sast/errorhandling-results.md` already exists.
- Skip TLS Verification if `sast/tls-results.md` already exists.
- Skip Cookie Flags if `sast/cookieflags-results.md` already exists.
- Skip Mass Assignment if `sast/massassign-results.md` already exists.
- Skip Excessive Data Exposure if `sast/excessivedata-results.md` already exists.
- Skip Security Headers if `sast/secheaders-results.md` already exists.
- Skip CRLF Injection if `sast/crlf-results.md` already exists.
- Skip Zip Slip if `sast/zipslip-results.md` already exists.
- Skip Pipeline Injection if `sast/pipelineinj-results.md` already exists.
- Skip Dependency Confusion if `sast/depconfusion-results.md` already exists.
- Skip Dangerous API if `sast/dangerousapi-results.md` already exists.
- Skip Cloud Metadata SSRF if `sast/ssrfimds-results.md` already exists.
- Skip Skill Audit if `sast/skillaudit-results.md` already exists.
- Skip MCP Security if `sast/mcpsec-results.md` already exists.
- Skip Config RCE if `sast/configrce-results.md` already exists.
- Skip Agent Identity if `sast/agentidentity-results.md` already exists.

Start **one subagent per check**, all **in parallel**, each with a dedicated task. Give each subagent the same instruction pattern, using the skill name and paths from the table:

> Read `sast/architecture.md` for context, then run the named SAST skill. Write all findings to that skill's results file. Clean up any intermediate recon or threat files for that skill when done.

| Skill | Results file | Typical intermediate files to clean |
|-------|----------------|--------------------------------------|
| sast-idor | `sast/idor-results.md` | `sast/idor-recon.md` |
| sast-sqli | `sast/sqli-results.md` | `sast/sqli-recon.md`, `sast/sqli-batch-*.md` |
| sast-ssrf | `sast/ssrf-results.md` | `sast/ssrf-recon.md` |
| sast-xss | `sast/xss-results.md` | `sast/xss-recon.md` |
| sast-rce | `sast/rce-results.md` | `sast/rce-recon.md`, `sast/rce-batch-*.md` |
| sast-xxe | `sast/xxe-results.md` | `sast/xxe-recon.md` |
| sast-fileupload | `sast/fileupload-results.md` | `sast/fileupload-recon.md`, `sast/fileupload-batch-*.md` |
| sast-pathtraversal | `sast/pathtraversal-results.md` | `sast/pathtraversal-recon.md`, `sast/pathtraversal-batch-*.md` |
| sast-ssti | `sast/ssti-results.md` | `sast/ssti-recon.md` |
| sast-jwt | `sast/jwt-results.md` | `sast/jwt-recon.md` |
| sast-missingauth | `sast/missingauth-results.md` | `sast/missingauth-recon.md`, `sast/missingauth-batch-*.md` |
| sast-businesslogic | `sast/businesslogic-results.md` | `sast/businesslogic-threats.md`, `sast/businesslogic-batch-*.md` |
| sast-graphql | `sast/graphql-results.md` | `sast/graphql-recon.md` |
| sast-hardcodedsecrets | `sast/hardcodedsecrets-results.md` | `sast/hardcodedsecrets-recon.md`, `sast/hardcodedsecrets-batch-*.md` |
| sast-csrf | `sast/csrf-results.md` | `sast/csrf-recon.md`, `sast/csrf-batch-*.md` |
| sast-openredirect | `sast/openredirect-results.md` | `sast/openredirect-recon.md`, `sast/openredirect-batch-*.md` |
| sast-cors | `sast/cors-results.md` | `sast/cors-recon.md`, `sast/cors-batch-*.md` |
| sast-ldap | `sast/ldap-results.md` | `sast/ldap-recon.md`, `sast/ldap-batch-*.md` |
| sast-nosql | `sast/nosql-results.md` | `sast/nosql-recon.md`, `sast/nosql-batch-*.md` |
| sast-prototype | `sast/prototype-results.md` | `sast/prototype-recon.md`, `sast/prototype-batch-*.md` |
| sast-redos | `sast/redos-results.md` | `sast/redos-recon.md`, `sast/redos-batch-*.md` |
| sast-crypto | `sast/crypto-results.md` | `sast/crypto-recon.md`, `sast/crypto-batch-*.md` |
| sast-race | `sast/race-results.md` | `sast/race-recon.md`, `sast/race-batch-*.md` |
| sast-pii | `sast/pii-results.md` | `sast/pii-recon.md`, `sast/pii-batch-*.md` |
| sast-deps | `sast/deps-results.md` | `sast/deps-recon.md`, `sast/deps-batch-*.md` |
| sast-iac | `sast/iac-results.md` | `sast/iac-recon.md`, `sast/iac-batch-*.md` |
| sast-promptinjection | `sast/promptinjection-results.md` | `sast/promptinjection-recon.md`, `sast/promptinjection-batch-*.md` |
| sast-llmoutput | `sast/llmoutput-results.md` | `sast/llmoutput-recon.md`, `sast/llmoutput-batch-*.md` |
| sast-deser | `sast/deser-results.md` | `sast/deser-recon.md`, `sast/deser-batch-*.md` |
| sast-errorhandling | `sast/errorhandling-results.md` | `sast/errorhandling-recon.md`, `sast/errorhandling-batch-*.md` |
| sast-tls | `sast/tls-results.md` | `sast/tls-recon.md`, `sast/tls-batch-*.md` |
| sast-cookieflags | `sast/cookieflags-results.md` | `sast/cookieflags-recon.md`, `sast/cookieflags-batch-*.md` |
| sast-massassign | `sast/massassign-results.md` | `sast/massassign-recon.md`, `sast/massassign-batch-*.md` |
| sast-excessivedata | `sast/excessivedata-results.md` | `sast/excessivedata-recon.md`, `sast/excessivedata-batch-*.md` |
| sast-secheaders | `sast/secheaders-results.md` | `sast/secheaders-recon.md`, `sast/secheaders-batch-*.md` |
| sast-crlf | `sast/crlf-results.md` | `sast/crlf-recon.md`, `sast/crlf-batch-*.md` |
| sast-zipslip | `sast/zipslip-results.md` | `sast/zipslip-recon.md`, `sast/zipslip-batch-*.md` |
| sast-pipelineinj | `sast/pipelineinj-results.md` | `sast/pipelineinj-recon.md`, `sast/pipelineinj-batch-*.md` |
| sast-depconfusion | `sast/depconfusion-results.md` | `sast/depconfusion-recon.md`, `sast/depconfusion-batch-*.md` |
| sast-dangerousapi | `sast/dangerousapi-results.md` | `sast/dangerousapi-recon.md`, `sast/dangerousapi-batch-*.md` |
| sast-ssrfimds | `sast/ssrfimds-results.md` | `sast/ssrfimds-recon.md`, `sast/ssrfimds-batch-*.md` |
| sast-skillaudit | `sast/skillaudit-results.md` | `sast/skillaudit-recon.md`, `sast/skillaudit-batch-*.md` |
| sast-mcpsec | `sast/mcpsec-results.md` | `sast/mcpsec-recon.md`, `sast/mcpsec-batch-*.md` |
| sast-configrce | `sast/configrce-results.md` | `sast/configrce-recon.md`, `sast/configrce-batch-*.md` |
| sast-agentidentity | `sast/agentidentity-results.md` | `sast/agentidentity-recon.md`, `sast/agentidentity-batch-*.md` |

Wait for all subagents to finish before proceeding.

### Canonical JSON output

In addition to the human-readable `sast/<skill>-results.md`, each subagent must also emit a machine-readable `sast/<skill>-results.json` file so the `sast-skills export` CLI can aggregate `sast/*-results.json` into SARIF, JSON, or HTML.

Each JSON file must contain a single object with a `findings` array. Each finding follows this canonical schema:

```json
{
  "findings": [
    {
      "id": "<skill>-<sequential-id>",
      "skill": "<skill-name>",
      "severity": "critical|high|medium|low|info",
      "title": "short one-line description",
      "description": "full explanation including exploitability",
      "location": { "file": "relative/path.ext", "line": 123, "column": 10 },
      "remediation": "how to fix",
      "exploitability": "reachable|conditional|unreachable|unknown",
      "confidence": "high|medium|low",
      "chain_id": null
    }
  ]
}
```

If a skill produces no findings, still write the file with `"findings": []` so the aggregator can verify the scan ran.

`exploitability` (is the sink reachable from untrusted input?), `confidence`, and `chain_id` (a stable id shared by findings that compose into one attack) are **schema v2** fields — set them when your verify phase can; they are optional. `sast-skills export` stamps the aggregated output with `"run": { ..., "schema": "2.0" }`.

---

## Step 3: Report Generation

After all subagents from Step 2 finish, generate the final consolidated report.

Skip this step if `sast/final-report.md` already exists.

Launch a single subagent:

> Read all available `sast/*-results.md` files and `sast/architecture.md` for context, then run the sast-report skill to generate `sast/final-report.md` with all findings ranked by severity and confidentiality impact.

---

## Step 4: Triage

After `sast/final-report.md` is generated, triage every finding to eliminate false positives and correct severities.

Skip this step if `sast/final-report-triaged.md` already exists.

Launch a single subagent that runs the sast-triage skill:

> Read `sast/final-report.md`, all `sast/*-results.json`, and `sast/architecture.md`. Run the sast-triage skill. For each finding, decide if it is a true positive, a false positive, or needs a severity adjustment (up or down), with evidence from the codebase for every change. Write the final triaged report to `sast/final-report-triaged.md` and the machine-readable canonical view to `sast/triaged.json`. Do not modify the original `*-results.json` or `final-report.md` — the triaged files are additive so the raw output stays auditable.

`sast-skills export --input sast/ --triaged` will prefer `sast/triaged.json` over `sast/*-results.json` when both are present.
