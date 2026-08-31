# Contributing

Thanks for wanting to help. This project follows **test-driven development** end-to-end — red, green, refactor, one failing test at a time. TDD Guard is wired into the Claude Code session to enforce the cycle. If you're coding locally, run `npm test` frequently.

## Project layout

```text
bin/sast-skills.js          thin CLI shim — argv routing only
src/cli.js                  command router (install/update/uninstall/doctor/export)
src/commands/*.js           one file per command
src/agents.js               assistant registry (single source of truth)
src/oscal.js                OSCAL 1.2.3 renderers (assessment-results + POA&M)
src/oscal-controls.js       skill → NIST SP 800-53 Rev 5 control map
src/prompts/clack.js        @clack/prompts wrapper
scripts/sync-skills.js      keep .agents/skills byte-identical to .claude/skills
scripts/scaffold-skill.js   create a new skill SKILL.md in both trees
scripts/register-skill.js   patch the orchestrators, README, and the control map
sast-files/CLAUDE.md        Claude Code entry file shipped to users
sast-files/AGENTS.md        AGENTS.md entry file shipped to users
sast-files/.claude/skills/  canonical skill tree (edit these)
sast-files/.agents/skills/  generated mirror of .claude/skills (do NOT edit by hand)
test/*.test.js              vitest suites
```

## Setup

```bash
npm install
npm test
```

Node 20+ required.

## Adding a new vulnerability skill

1. Scaffold both trees:

   ```bash
   node scripts/scaffold-skill.js sast-yourcheck
   ```

   This creates `SKILL.md` stubs under `sast-files/.claude/skills/sast-yourcheck/` and the matching path in `.agents/skills/`.

2. Register it in the orchestrators, the README, and the OSCAL control map (skip-line, catalog row, README row, control entry):

   ```bash
   node scripts/register-skill.js sast-yourcheck yourcheck "Your Check" "One-line description"
   ```

   Use this rather than hand-patching `sast-files/CLAUDE.md`, `sast-files/AGENTS.md`, and `README.md` — `docs-completeness.test.js` fails if any of the three is missing the reference. The README row lands at the end of the last detection-class table; move it to the right "What it detects" category by hand (cross-table placement is editorial).

3. Narrow the OSCAL control mapping. `register-skill.js` seeds `'sast-yourcheck': ['ra-5']` in [`src/oscal-controls.js`](src/oscal-controls.js) so the skill is never unmapped, but `ra-5` (Vulnerability Monitoring and Scanning) only says "a scanner ran". Replace it with the **NIST SP 800-53 Rev 5** controls whose objective your findings actually defeat — `si-10` for input validation, `ac-3`/`ac-6` for access control, `sc-13` for crypto, `sc-5` for availability, `sr-3`/`sr-11` for supply chain. That id is what an auditor reads in the exported `assessment-results` document, so it is a judgement call worth making rather than leaving to the fallback. `oscal-controls.test.js` fails on an unmapped skill, a stale entry, or a malformed control id.

4. Write the skill body in `sast-files/.claude/skills/sast-yourcheck/SKILL.md` — follow the recon → batched-verify → merge structure of an existing skill (e.g. `sast-sqli` for taint, `sast-tls` for config detection). Emit the canonical finding JSON (with the schema-v2 `exploitability` / `confidence` / `chain_id` fields).

5. Sync the mirror:

   ```bash
   npm run sync
   ```

   This rewrites `.agents/skills` from `.claude/skills`. A regression test catches drift; `prepublishOnly` runs sync before every publish.

6. If the skill's vuln class deserves a dedicated `sast-report` row, update that too.

### Scope boundaries (keep skills from double-flagging)

When a new skill's domain overlaps a sibling's (common for agentic / LLM-runtime
skills), give it an explicit **"defer to a sibling skill"** boundary in its
`is NOT` / scope section, keyed to the shared `chain_id`. A skill should own one
concern and hand the rest to the owning sibling rather than re-flagging the same
line — e.g. `sast-mcpsec` owns MCP tool definitions and defers skill-config hooks
to `sast-skillaudit`; `sast-toolcalling` owns the explicit dispatch site and
defers the agent-authority question to `sast-excessiveagency`. The findings still
compose via `chain_id`; they just aren't double-raised. This keeps precision high
when several related skills run over the same file.

## Editing `.claude/skills` vs `.agents/skills`

Always edit `.claude/skills`. `.agents/skills` is a generated mirror. `npm run sync` (or any `npm publish`) regenerates it. A test enforces byte-identical equality.

## Writing tests

- One new failing test at a time. Run it, watch it fail for the *right* reason, then implement the minimum to turn it green.
- Tests that spawn the CLI use a tmp `workdir` via `mkdtemp` — see [test/install.test.js](test/install.test.js).
- Tests that unit-test commands import them directly — see [test/install-interactive.test.js](test/install-interactive.test.js).

## Running the CLI locally

```bash
node bin/sast-skills.js install --yes --target /tmp/playground --assistant claude --scope project
node bin/sast-skills.js doctor --target /tmp/playground --assistant claude
```

## Publishing

`npm publish` runs `prepublishOnly`, which runs `npm run sync && npm test`. A dirty working tree or a failing test will abort the publish.

## License

By contributing you agree your work is released under the project's MIT license (see [LICENSE](LICENSE)).
