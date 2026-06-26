# Milestone 1 — Clean static, high prevalence (detailed plan)

13 Tier-A skills. See [../ROADMAP.md](../ROADMAP.md) and the per-skill task in it.

## Per-skill spec format

Every skill below is specified as:

- **Header** — framework mapping, tier, CWE.
- **Scope** — what it IS and explicitly what it is NOT (the boundary that keeps FP down).
- **Recon sinks** — the concrete grep/AST targets the recon phase looks for, per language/framework.
- **Verify** — the taint question + the FP-killers; sets `exploitability` / `confidence`.
- **Severity** — the default, and when to raise or lower it.
- **Remediation** — the fix written into the finding.
- **Chains with** — sibling skills it composes with via `chain_id`.
- **Test fixture** — a minimal repo with a true positive and the FP-killer true negatives; the skill must flag only the TP.

---

## sast-deser — Insecure deserialization

**Framework:** Web25 A05 · **Tier:** A · **CWE:** CWE-502

**Scope.** Untrusted bytes reaching a deserializer that can instantiate arbitrary types or
invoke code (gadget chains). NOT: deserializing trusted/internal data; `JSON.parse` of plain
data with no type resolution; schema-validated input.

**Recon sinks** (recon-phase grep/AST targets):

| Language | Sinks |
|---|---|
| Java | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream` (no allow-list), SnakeYAML `new Yaml()` without `SafeConstructor`, `Kryo` |
| Python | `pickle.load(s)`, `yaml.load` (no `SafeLoader`), `jsonpickle.decode`, `dill.load`, `shelve` |
| PHP | `unserialize(` on request data |
| .NET | `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `Json.NET` `TypeNameHandling.All/Auto` |
| Ruby | `Marshal.load`, `YAML.load` (pre-`safe_load` Psych) |
| Node | `node-serialize`, `serialize-to-js`, `funcster`, `cryo` |

**Verify.** Does the deserialized input cross a trust boundary (HTTP body, upload, queue,
cookie, cache)? FP-killers: trusted/hardcoded source; `SafeLoader`/`SafeConstructor`; an
explicit type allow-list; schema validation before deserialize. `exploitability: reachable`
only when untrusted bytes reach the sink with no allow-list; `confidence: high` for a direct
request→sink flow, `medium` when the source is inferred.

**Severity.** Default **critical** (reachable gadget chain → RCE). Lower to **high** when a
type allow-list is present but incomplete; **medium** when the input is untrusted but no
known gadget exists on the classpath.

**Remediation.** Use a safe deserializer (`yaml.safe_load`, Psych `safe_load`,
`SafeConstructor`), an explicit type allow-list, or a data-only format (JSON without type
resolution). Never deserialize untrusted bytes into typed objects.

**Chains with.** `sast-deps` (a known-vulnerable gadget library raises confidence) →
`chain_id` "rce-gadget".

**Test fixture.** TP: `pickle.loads(request.data)`. TN: `yaml.safe_load(request.data)`. TN:
`pickle.loads(open('trusted.pkl','rb').read())`. Assert only the TP is flagged, `reachable`,
`critical`.

---

## Remaining 12 skills (to be filled with the same format)

- [ ] `sast-errorhandling` — Web25 A10 — fail-open, stack-trace/secret leak, debug mode, swallowed catch
- [ ] `sast-massassign` — API23 API3 — mass assignment / overposting
- [ ] `sast-excessivedata` — API23 API3 — serializer returns the whole object
- [ ] `sast-tls` — Web25 A02/A04 — cert/hostname verification disabled
- [ ] `sast-cookieflags` — Web25 A02 — missing HttpOnly / Secure / SameSite
- [ ] `sast-secheaders` — Web25 A02 — CSP / HSTS / X-Frame-Options / SRI
- [ ] `sast-crlf` — Web25 A05 — CRLF / response splitting / header & host-header injection
- [ ] `sast-zipslip` — Web25 A01 — archive-extraction path traversal
- [ ] `sast-pipelineinj` — Web25 A03 — poisoned pipeline execution
- [ ] `sast-depconfusion` — Web25 A03 — dependency confusion / typosquat
- [ ] `sast-dangerousapi` — Web25 A05 — eval / reflection / native / process-spawn inventory
- [ ] `sast-ssrfimds` — Web25 A01 / API23 API7 — cloud-metadata SSRF + IMDSv1
