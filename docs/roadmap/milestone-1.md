# Milestone 1 — Clean static, high prevalence (detailed plan)

13 Tier-A skills. See [../ROADMAP.md](../ROADMAP.md) and the per-skill task in it.

## Per-skill spec format

Every skill below is specified as:

- **Scope** — what it IS and explicitly what it is NOT (the boundary that keeps FP down).
- **Recon sinks** — the concrete grep/AST targets the recon phase looks for, per language/framework.
- **Verify** — the taint question + the FP-killers; sets `exploitability` / `confidence`.
- **Test fixture** — a minimal repo with a true positive and the FP-killer true negatives; the skill must flag only the TP.

---

## sast-deser — Insecure deserialization

**Framework:** Web25 A05 · **Tier:** A

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
only when untrusted bytes reach the sink with no allow-list.

**Test fixture.** TP: `pickle.loads(request.data)`. TN: `yaml.safe_load(request.data)`. TN:
`pickle.loads(open('trusted.pkl','rb').read())`. Assert only the TP is flagged, `reachable`.

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
