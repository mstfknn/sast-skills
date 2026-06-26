# Multi-Agent Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `npx sast-skills install` install for any of 14 AI coding assistants (multi-select, with an "all" option), behind a proper banner, with `update` auto-detecting what's installed.

**Architecture:** A single `src/agents.js` registry maps each assistant id → `{ label, entryFile, skillTree }`. `install`/`update`/`doctor`/`uninstall` all consume it. Selecting assistants resolves to a **deduped** set of entry files (each written from the matching orchestrator: `.claude`→`CLAUDE.md`, `.agents`→`AGENTS.md`) plus skill trees. The clack layer gains a banner and a multiselect.

**Tech Stack:** Node ≥20, ESM, vitest, `@clack/prompts` ^1.6 (already a dep — provides `multiselect`).

## Global Constraints

- ESM only (`"type": "module"`); no new runtime dependencies (reuse `@clack/prompts`).
- `src/` stays side-effect-free and dependency-injected; route I/O through the passed-in bag (`{ argv, cwd, packageRoot, stdout, isTTY, prompt }`).
- TDD: failing test first; one logical change per commit; tests + their code in the same commit.
- `npm test` (vitest) and `npm run lint:md` (markdownlint) must stay green.
- Preserve the clobber guard (never overwrite an existing entry file without `--force`) and the clean one-line error output (bin catches and prints `err.message`).
- Orchestrator content is unchanged; only the path it is written to varies.
- Skill content lives only in `.claude` (canonical) and `.agents` (synced); never hand-edit `.agents`.

---

### Task 1: Agent registry (`src/agents.js`)

**Files:**

- Create: `src/agents.js`
- Test: `test/agents.test.js`

**Interfaces:**

- Produces:
  - `AGENTS: Array<{ id: string, label: string, entryFile: string, skillTree: '.claude'|'.agents' }>` (14 entries)
  - `ENTRY_SOURCE: { '.claude': 'CLAUDE.md', '.agents': 'AGENTS.md' }`
  - `ORCHESTRATOR_SIGNATURE: 'SAST Security Assessment'`
  - `validIds(): string[]`
  - `resolveAgents(selection: string[]): Array<agent>` — expands `all` and the legacy `agents` alias, dedupes by `id`, throws `Error` on unknown id.

- [ ] **Step 1: Write the failing test**

```js
// test/agents.test.js
import { test, expect } from 'vitest';
import { AGENTS, ENTRY_SOURCE, ORCHESTRATOR_SIGNATURE, validIds, resolveAgents } from '../src/agents.js';

test('registry has 14 agents with unique ids and complete fields', () => {
  expect(AGENTS).toHaveLength(14);
  const ids = AGENTS.map((a) => a.id);
  expect(new Set(ids).size).toBe(14);
  for (const a of AGENTS) {
    expect(a.id && a.label && a.entryFile).toBeTruthy();
    expect(['.claude', '.agents']).toContain(a.skillTree);
  }
  expect(ids).toEqual(expect.arrayContaining(['claude', 'codex', 'gemini', 'copilot', 'cursor', 'windsurf', 'opencode', 'cline', 'antigravity', 'aider', 'kilocode', 'augment', 'hermes', 'mistralvibe']));
});

test('entry-file conventions match the design', () => {
  const byId = Object.fromEntries(AGENTS.map((a) => [a.id, a]));
  expect(byId.claude).toMatchObject({ entryFile: 'CLAUDE.md', skillTree: '.claude' });
  expect(byId.gemini).toMatchObject({ entryFile: 'GEMINI.md', skillTree: '.agents' });
  expect(byId.copilot).toMatchObject({ entryFile: '.github/copilot-instructions.md', skillTree: '.agents' });
  expect(byId.windsurf.entryFile).toBe('.windsurf/rules/sast-skills.md');
  expect(byId.cline.entryFile).toBe('.clinerules/sast-skills.md');
  expect(byId.aider.entryFile).toBe('CONVENTIONS.md');
  expect(byId.cursor).toMatchObject({ entryFile: 'AGENTS.md', skillTree: '.agents' });
});

test('resolveAgents expands "all" to every agent, deduped', () => {
  expect(resolveAgents(['all'])).toHaveLength(14);
  expect(resolveAgents(['all', 'claude'])).toHaveLength(14);
});

test('resolveAgents maps legacy "agents" alias to an AGENTS.md/.agents target', () => {
  const [a] = resolveAgents(['agents']);
  expect(a).toMatchObject({ entryFile: 'AGENTS.md', skillTree: '.agents' });
});

test('resolveAgents dedupes by id and throws on unknown', () => {
  expect(resolveAgents(['claude', 'claude'])).toHaveLength(1);
  expect(() => resolveAgents(['nope'])).toThrow(/Unknown assistant: nope/);
});

test('ENTRY_SOURCE and signature are exported', () => {
  expect(ENTRY_SOURCE).toEqual({ '.claude': 'CLAUDE.md', '.agents': 'AGENTS.md' });
  expect(ORCHESTRATOR_SIGNATURE).toBe('SAST Security Assessment');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/agents.test.js`
Expected: FAIL — cannot resolve `../src/agents.js`.

- [ ] **Step 3: Write minimal implementation**

```js
// src/agents.js
export const AGENTS = [
  { id: 'claude', label: 'Claude Code', entryFile: 'CLAUDE.md', skillTree: '.claude' },
  { id: 'codex', label: 'OpenAI Codex (CLI)', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'gemini', label: 'Gemini CLI', entryFile: 'GEMINI.md', skillTree: '.agents' },
  { id: 'copilot', label: 'GitHub Copilot', entryFile: '.github/copilot-instructions.md', skillTree: '.agents' },
  { id: 'cursor', label: 'Cursor', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'windsurf', label: 'Windsurf', entryFile: '.windsurf/rules/sast-skills.md', skillTree: '.agents' },
  { id: 'opencode', label: 'OpenCode', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'cline', label: 'Cline', entryFile: '.clinerules/sast-skills.md', skillTree: '.agents' },
  { id: 'antigravity', label: 'Antigravity', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'aider', label: 'Aider', entryFile: 'CONVENTIONS.md', skillTree: '.agents' },
  { id: 'kilocode', label: 'Kilo Code', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'augment', label: 'Augment', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'hermes', label: 'Hermes Agent', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'mistralvibe', label: 'Mistral Vibe', entryFile: 'AGENTS.md', skillTree: '.agents' },
];

export const ENTRY_SOURCE = { '.claude': 'CLAUDE.md', '.agents': 'AGENTS.md' };
export const ORCHESTRATOR_SIGNATURE = 'SAST Security Assessment';

const BY_ID = new Map(AGENTS.map((a) => [a.id, a]));
const AGENTS_ALIAS = { id: 'agents', label: 'AGENTS.md assistants', entryFile: 'AGENTS.md', skillTree: '.agents' };

export function validIds() {
  return AGENTS.map((a) => a.id);
}

export function resolveAgents(selection) {
  const expanded = [];
  for (const raw of selection) {
    if (raw === 'all') { expanded.push(...AGENTS.map((a) => a.id)); continue; }
    if (raw === 'agents') { expanded.push('agents'); continue; }
    expanded.push(raw);
  }
  const seen = new Set();
  const out = [];
  for (const id of expanded) {
    const agent = id === 'agents' ? AGENTS_ALIAS : BY_ID.get(id);
    if (!agent) {
      throw new Error(`Unknown assistant: ${id}. Valid: ${validIds().join(', ')}, all.`);
    }
    if (seen.has(agent.id)) continue;
    seen.add(agent.id);
    out.push(agent);
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/agents.test.js`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add src/agents.js test/agents.test.js
git commit -m "feat(agents): add the assistant registry and selection resolver"
```

---

### Task 2: Registry-driven multi-agent install (`src/commands/install.js`)

**Files:**

- Modify: `src/commands/install.js` (replace `ASSISTANT_LAYOUT` usage)
- Test: `test/install.test.js` (add cases), `test/install-interactive.test.js` (update contract)

**Interfaces:**

- Consumes: `resolveAgents`, `ENTRY_SOURCE`, `validIds` from `src/agents.js`.
- Produces: `install({ packageRoot, argv, cwd, stdout, isTTY, prompt })` unchanged signature. The injected `prompt` is now called as `prompt({ name: 'assistant', choices: [...validIds(), 'all'], multi: true })` → returns `string[]`, and `prompt({ name: 'scope', choices: ['project','global'] })` → returns `string`.

- [ ] **Step 1: Write the failing tests** (append to `test/install.test.js`)

```js
test('install --assistant gemini writes GEMINI.md and the .agents skill tree', async () => {
  const { code } = await run(['install', '--yes', '--target', workdir, '--assistant', 'gemini', '--scope', 'project']);
  expect(code).toBe(0);
  expect((await stat(join(workdir, 'GEMINI.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.agents', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);
  const entries = await readdir(workdir);
  expect(entries).not.toContain('AGENTS.md');
});

test('install --assistant copilot writes the nested copilot-instructions path', async () => {
  const { code } = await run(['install', '--yes', '--target', workdir, '--assistant', 'copilot', '--scope', 'project']);
  expect(code).toBe(0);
  const file = join(workdir, '.github', 'copilot-instructions.md');
  expect((await stat(file)).isFile()).toBe(true);
  const content = await readFile(file, 'utf8');
  expect(content).toMatch(/SAST Security Assessment/);
});

test('install --assistant codex,cursor dedupes to a single AGENTS.md and one .agents tree', async () => {
  const { code } = await run(['install', '--yes', '--target', workdir, '--assistant', 'codex,cursor', '--scope', 'project']);
  expect(code).toBe(0);
  expect((await stat(join(workdir, 'AGENTS.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.agents', 'skills', 'sast-sqli', 'SKILL.md'))).isFile()).toBe(true);
});

test('install --assistant all writes both entry families and both skill trees', async () => {
  const { code } = await run(['install', '--yes', '--target', workdir, '--assistant', 'all', '--scope', 'project']);
  expect(code).toBe(0);
  expect((await stat(join(workdir, 'CLAUDE.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, 'GEMINI.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.github', 'copilot-instructions.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.claude', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);
  expect((await stat(join(workdir, '.agents', 'skills', 'sast-analysis', 'SKILL.md'))).isFile()).toBe(true);
});

test('install rejects an unknown assistant id with a clean message', async () => {
  const { code, stderr } = await run(['install', '--yes', '--target', workdir, '--assistant', 'bogus', '--scope', 'project']);
  expect(code).toBe(1);
  expect(stderr).toMatch(/Unknown assistant: bogus/);
  expect(stderr).not.toMatch(/install\.js/);
});
```

Update `test/install-interactive.test.js` to the multiselect contract:

```js
test('install in interactive mode multi-selects assistants and a scope', async () => {
  const asked = [];
  const prompt = async ({ name, choices, multi }) => {
    asked.push({ name, choices, multi });
    if (name === 'assistant') return ['claude'];
    if (name === 'scope') return 'project';
    throw new Error(`unexpected prompt for ${name}`);
  };
  const stdout = { write: () => {} };
  await install({ packageRoot, argv: ['--target', workdir], cwd: workdir, stdout, isTTY: true, prompt });

  expect(asked.map((a) => a.name)).toEqual(['assistant', 'scope']);
  expect(asked[0].multi).toBe(true);
  expect(asked[0].choices).toEqual(expect.arrayContaining(['claude', 'cursor', 'copilot', 'all']));
  expect((await stat(join(workdir, 'CLAUDE.md'))).isFile()).toBe(true);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/install.test.js test/install-interactive.test.js`
Expected: FAIL — GEMINI.md not written, multiselect contract unmet.

- [ ] **Step 3: Rewrite `src/commands/install.js`**

```js
import { readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { resolveAgents, ENTRY_SOURCE, validIds } from '../agents.js';

async function exists(path) {
  try { await access(path); return true; } catch { return false; }
}

async function copyTree(srcRoot, skillTree, target) {
  const skillsSrc = resolve(srcRoot, skillTree, 'skills');
  const skills = await readdir(skillsSrc);
  for (const name of skills) {
    const dst = resolve(target, skillTree, 'skills', name, 'SKILL.md');
    await mkdir(dirname(dst), { recursive: true });
    await copyFile(resolve(skillsSrc, name, 'SKILL.md'), dst);
  }
  return skills.length;
}

export async function install({ packageRoot, argv, cwd, stdout, isTTY, prompt }) {
  let target;
  let dryRun = false;
  let force = false;
  let yes = false;
  let assistantArg;
  let scope;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--dry-run') dryRun = true;
    else if (argv[i] === '--force') force = true;
    else if (argv[i] === '--yes') yes = true;
    else if (argv[i] === '--assistant') assistantArg = argv[++i];
    else if (argv[i] === '--scope') scope = argv[++i];
  }

  if (!yes && !isTTY) {
    throw new Error('Non-interactive stdin detected; pass --yes to run without prompts, or run in an interactive TTY.');
  }

  let selection = assistantArg ? assistantArg.split(',').map((s) => s.trim()).filter(Boolean) : null;

  if (!yes && isTTY) {
    if (selection === null) {
      selection = await prompt({ name: 'assistant', choices: [...validIds(), 'all'], multi: true });
    }
    if (scope === undefined) {
      scope = await prompt({ name: 'scope', choices: ['project', 'global'] });
    }
  }

  if (selection === null || selection.length === 0) selection = ['claude'];
  scope ??= 'project';

  if (!['project', 'global'].includes(scope)) {
    throw new Error(`Invalid --scope value: ${scope}. Expected one of: project, global.`);
  }

  const agents = resolveAgents(selection); // throws on unknown id
  const srcRoot = resolve(packageRoot, 'sast-files');
  if (target === undefined) target = scope === 'global' ? homedir() : cwd;

  const entryFiles = [...new Map(agents.map((a) => [a.entryFile, a])).values()];
  const skillTrees = [...new Set(agents.map((a) => a.skillTree))];

  if (dryRun) {
    if (scope !== 'global') for (const a of entryFiles) stdout.write(`${a.entryFile}\n`);
    for (const tree of skillTrees) {
      for (const name of await readdir(resolve(srcRoot, tree, 'skills'))) {
        stdout.write(`${tree}/skills/${name}/SKILL.md\n`);
      }
    }
    return;
  }

  if (scope !== 'global') {
    for (const a of entryFiles) {
      const entryDst = resolve(target, a.entryFile);
      if (!force && await exists(entryDst)) {
        const err = new Error(`${a.entryFile} already exists in target. Run "sast-skills update" to refresh an existing install, or pass --force to overwrite.`);
        err.code = 'EEXIST';
        throw err;
      }
      await mkdir(dirname(entryDst), { recursive: true });
      await copyFile(resolve(srcRoot, ENTRY_SOURCE[a.skillTree]), entryDst);
    }
  }

  let skillCount = 0;
  for (const tree of skillTrees) skillCount = await copyTree(srcRoot, tree, target);

  return {
    scope,
    labels: agents.map((a) => a.label),
    entryFiles: entryFiles.map((a) => a.entryFile),
    skillCount,
  };
}
```

Add a return-value test to `test/install-interactive.test.js` (it imports `install` directly):

```js
test('install returns a summary of what it wrote', async () => {
  const stdout = { write: () => {} };
  const summary = await install({
    packageRoot, argv: ['--target', workdir, '--yes', '--assistant', 'claude,cursor', '--scope', 'project'],
    cwd: workdir, stdout, isTTY: false, prompt: async () => {},
  });
  expect(summary.scope).toBe('project');
  expect(summary.entryFiles).toEqual(expect.arrayContaining(['CLAUDE.md', 'AGENTS.md']));
  expect(summary.labels).toEqual(expect.arrayContaining(['Claude Code', 'Cursor']));
  expect(summary.skillCount).toBeGreaterThan(0);
});
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/install.test.js test/install-interactive.test.js`
Expected: PASS (all existing + new cases; `--assistant claude`, `agents`, `all`, `--force`, global, EEXIST cases still pass).

- [ ] **Step 5: Commit**

```bash
git add src/commands/install.js test/install.test.js test/install-interactive.test.js
git commit -m "feat(install): registry-driven multi-assistant install with deduped writes"
```

---

### Task 3: Banner + multiselect prompt (`src/banner.js`, `src/prompts/clack.js`)

**Files:**

- Create: `src/banner.js`
- Modify: `src/prompts/clack.js`
- Modify: `bin/sast-skills.js` (print banner before interactive install)
- Test: `test/banner.test.js`, `test/clack-prompt.test.js` (add multiselect case)

**Interfaces:**

- Produces:
  - `BANNER(version: string): string` — the ASCII wordmark + tagline + repo URL.
  - `clackPrompt({ name, choices, multi })` — `multi: true` → `multiselect` returning `string[]`; else `select` returning `string`. Cancel throws `Error(/cancel/)`.

- [ ] **Step 1: Write the failing tests**

```js
// test/banner.test.js
import { test, expect } from 'vitest';
import { BANNER } from '../src/banner.js';

test('banner includes the name, repo URL, and version', () => {
  const out = BANNER('9.9.9');
  expect(out).toMatch(/github\.com\/mstfknn\/sast-skills/);
  expect(out).toMatch(/SAST scanner/i);
  expect(out).toMatch(/9\.9\.9/);
});
```

Add to `test/clack-prompt.test.js`:

```js
test('clackPrompt uses multiselect and returns an array when multi is set', async () => {
  clack.multiselect = vi.fn().mockResolvedValueOnce(['claude', 'cursor']);
  const result = await clackPrompt({ name: 'assistant', choices: ['claude', 'cursor', 'all'], multi: true });
  expect(result).toEqual(['claude', 'cursor']);
  expect(clack.multiselect).toHaveBeenCalledTimes(1);
});
```

Update the `vi.mock('@clack/prompts', ...)` factory at the top of `test/clack-prompt.test.js` to also expose `multiselect: vi.fn()`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/banner.test.js test/clack-prompt.test.js`
Expected: FAIL — `src/banner.js` missing; `multiselect` path absent.

- [ ] **Step 3: Implement**

```js
// src/banner.js
export function BANNER(version) {
  return [
    ' ___  _   ___ _____   ___ _  _____ _    _    ___',
    '/ __|/_\\ / __|_   _| / __| |/ /_ _| |  | |  / __|',
    '\\__ \\ _ \\\\__ \\ | |   \\__ \\ \' < | || |__| |__\\__ \\',
    `|___/_/ \\_\\___/ |_|   |___/_|\\_\\___|____|____|___/  v${version}`,
    ' Turn your AI coding assistant into a SAST scanner',
    ' github.com/mstfknn/sast-skills · 31 skills, 28 classes',
    '',
  ].join('\n');
}
```

```js
// src/prompts/clack.js
import { select, multiselect, isCancel } from '@clack/prompts';

export async function clackPrompt({ name, choices, multi }) {
  const options = choices.map((value) => ({ value }));
  const value = multi
    ? await multiselect({ message: name, options, required: false })
    : await select({ message: name, options });
  if (isCancel(value)) {
    throw new Error('Prompt cancelled by user');
  }
  return value;
}
```

In `bin/sast-skills.js`, print the banner before an interactive install. Inside the `install`/`update` branch, before calling `run(...)`, when `process.stdin.isTTY` and the command is `install`:

```js
import { BANNER } from '../src/banner.js';
// ...
if ((command === 'install' || command === 'update') && process.stdin.isTTY) {
  const pkg = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'));
  process.stdout.write(BANNER(pkg.version));
}
```

(`readFile`, `resolve` are already imported in bin.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/banner.test.js test/clack-prompt.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/banner.js src/prompts/clack.js bin/sast-skills.js test/banner.test.js test/clack-prompt.test.js
git commit -m "feat(cli): add ASCII banner and multiselect assistant prompt"
```

---

### Task 4: `update` auto-detect (`src/commands/update.js`, `src/cli.js`)

**Files:**

- Create: `src/commands/update.js`
- Modify: `src/cli.js` (route `update` to the new command)
- Test: `test/update.test.js` (add auto-detect cases)

**Interfaces:**

- Consumes: `AGENTS`, `ENTRY_SOURCE`, `ORCHESTRATOR_SIGNATURE` from `src/agents.js`; `install` from `./install.js`.
- Produces: `update({ argv, cwd, packageRoot, stdout, isTTY, prompt })`. If `--assistant` is present → delegate to `install` with `--force`. Else auto-detect installed entry files (exist + contain `ORCHESTRATOR_SIGNATURE`) and skill trees (`<tree>/skills/` has `sast-*` dirs), refresh them from the bundle; if none → throw.

- [ ] **Step 1: Write the failing tests** (append to `test/update.test.js`)

```js
test('update with no --assistant auto-detects an existing install and refreshes it', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'gemini', '--scope', 'project']);
  const skill = join(workdir, '.agents', 'skills', 'sast-sqli', 'SKILL.md');
  await writeFile(skill, 'outdated');

  const { code } = await run(['update', '--yes', '--target', workdir]);
  expect(code).toBe(0);
  const refreshed = await (await import('node:fs/promises')).readFile(skill, 'utf8');
  expect(refreshed).not.toBe('outdated');
  expect((await stat(join(workdir, 'GEMINI.md'))).isFile()).toBe(true);
});

test('update leaves a non-ours entry file untouched and reports nothing to update', async () => {
  await writeFile(join(workdir, 'AGENTS.md'), 'my own agents file');
  const { code, stdout, stderr } = await run(['update', '--yes', '--target', workdir]);
  expect(code).not.toBe(0);
  expect(`${stdout}${stderr}`).toMatch(/No sast-skills install found/i);
  const after = await (await import('node:fs/promises')).readFile(join(workdir, 'AGENTS.md'), 'utf8');
  expect(after).toBe('my own agents file');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/update.test.js`
Expected: FAIL — current `update` requires `--assistant`; auto-detect not implemented.

- [ ] **Step 3: Implement `src/commands/update.js`**

```js
import { readFile, readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { install } from './install.js';
import { AGENTS, ENTRY_SOURCE, ORCHESTRATOR_SIGNATURE } from '../agents.js';

async function read(path) { try { return await readFile(path, 'utf8'); } catch { return null; } }
async function exists(path) { try { await access(path); return true; } catch { return false; } }

export async function update({ argv, cwd, packageRoot, stdout, isTTY, prompt }) {
  if (argv.includes('--assistant')) {
    await install({ argv: [...argv, '--force'], cwd, packageRoot, stdout, isTTY, prompt });
    return;
  }

  let target = cwd;
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--target') target = argv[++i];

  const srcRoot = resolve(packageRoot, 'sast-files');
  const entryFiles = [...new Map(AGENTS.map((a) => [a.entryFile, a])).values()];
  const trees = [...new Set(AGENTS.map((a) => a.skillTree))];

  let refreshed = 0;

  for (const a of entryFiles) {
    const dst = resolve(target, a.entryFile);
    const content = await read(dst);
    if (content !== null && content.includes(ORCHESTRATOR_SIGNATURE)) {
      await copyFile(resolve(srcRoot, ENTRY_SOURCE[a.skillTree]), dst);
      refreshed++;
    }
  }

  for (const tree of trees) {
    const skillsDir = resolve(target, tree, 'skills');
    if (!(await exists(skillsDir))) continue;
    const installed = (await readdir(skillsDir)).filter((n) => n.startsWith('sast-'));
    if (installed.length === 0) continue;
    for (const name of await readdir(resolve(srcRoot, tree, 'skills'))) {
      const out = resolve(target, tree, 'skills', name, 'SKILL.md');
      await mkdir(dirname(out), { recursive: true });
      await copyFile(resolve(srcRoot, tree, 'skills', name, 'SKILL.md'), out);
    }
    refreshed++;
  }

  if (refreshed === 0) {
    throw new Error('No sast-skills install found in target — run "npx sast-skills install".');
  }
}
```

Wire `src/cli.js` to route `update` to the new command (add an import and a branch before the install fallthrough):

```js
import { update } from './commands/update.js';
// ... inside run(), alongside the other command branches:
if (command === 'update') {
  await update({ argv: rest, cwd, packageRoot, stdout, isTTY: Boolean(stdin.isTTY), prompt: clackPrompt });
  return;
}
```

Remove the old `command === 'update' ? [...rest, '--force'] : rest` line; the final fallthrough now only handles `install`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/update.test.js`
Expected: PASS (existing `--assistant claude` update test still passes via the delegate branch).

- [ ] **Step 5: Commit**

```bash
git add src/commands/update.js src/cli.js test/update.test.js
git commit -m "feat(update): auto-detect and refresh an existing install"
```

---

### Task 5: Registry-aware `doctor` (`src/commands/doctor.js`)

**Files:**

- Modify: `src/commands/doctor.js`
- Test: `test/doctor.test.js` (add a non-claude case)

**Interfaces:**

- Consumes: `AGENTS` from `src/agents.js`.
- Produces: `doctor({ argv, cwd, packageRoot, stdout })` unchanged signature; `--assistant <id>` now accepts any registry id (default `claude`).

- [ ] **Step 1: Write the failing test** (append to `test/doctor.test.js`)

```js
test('doctor verifies a non-claude assistant (cursor) install', async () => {
  await run(['install', '--yes', '--target', workdir, '--assistant', 'cursor', '--scope', 'project']);
  const { code, stdout } = await run(['doctor', '--target', workdir, '--assistant', 'cursor']);
  expect(code).toBe(0);
  expect(stdout).toMatch(/AGENTS\.md: OK/);
  expect(stdout).toMatch(/\.agents\/skills.*OK/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/doctor.test.js`
Expected: FAIL — `ASSISTANT_LAYOUT[cursor]` is undefined.

- [ ] **Step 3: Implement** — replace the `ASSISTANT_LAYOUT` lookup in `src/commands/doctor.js` with the registry:

```js
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AGENTS, ENTRY_SOURCE } from '../agents.js';

async function readIfExists(path) {
  try { return await readFile(path, 'utf8'); } catch { return null; }
}
function classify(installed, bundled) {
  if (installed === null) return 'MISSING';
  if (installed !== bundled) return 'MODIFIED';
  return 'OK';
}

export async function doctor({ argv, cwd, packageRoot, stdout }) {
  let target = cwd;
  let assistant = 'claude';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
  }

  const agent = AGENTS.find((a) => a.id === assistant);
  if (!agent) throw new Error(`Unknown assistant: ${assistant}.`);
  const { entryFile, skillTree } = agent;
  const srcRoot = resolve(packageRoot, 'sast-files');
  let ok = true;

  const bundledEntry = await readIfExists(resolve(srcRoot, ENTRY_SOURCE[skillTree]));
  const installedEntry = await readIfExists(resolve(target, entryFile));
  const entryStatus = classify(installedEntry, bundledEntry);
  if (entryStatus !== 'OK') ok = false;
  stdout.write(`${entryFile}: ${entryStatus}\n`);

  const skillsSrc = resolve(srcRoot, skillTree, 'skills');
  for (const name of await readdir(skillsSrc)) {
    const bundled = await readIfExists(resolve(skillsSrc, name, 'SKILL.md'));
    const installed = await readIfExists(resolve(target, skillTree, 'skills', name, 'SKILL.md'));
    const status = classify(installed, bundled);
    if (status !== 'OK') ok = false;
    stdout.write(`${skillTree}/skills/${name}/SKILL.md: ${status}\n`);
  }

  if (!ok) throw new Error('doctor detected issues');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/doctor.test.js`
Expected: PASS (existing claude OK / MISSING-MODIFIED tests still pass).

- [ ] **Step 5: Commit**

```bash
git add src/commands/doctor.js test/doctor.test.js
git commit -m "feat(doctor): verify any registry assistant"
```

---

### Task 6: Registry-aware `uninstall` (`src/commands/uninstall.js`)

**Files:**

- Modify: `src/commands/uninstall.js`
- Test: `test/uninstall.test.js` (add a non-claude case)

**Interfaces:**

- Consumes: `AGENTS`, `ENTRY_SOURCE` from `src/agents.js`.
- Produces: `uninstall({ argv, cwd, packageRoot })` unchanged; `--assistant <id>` accepts any registry id.

- [ ] **Step 1: Write the failing test** (append to `test/uninstall.test.js`)

```js
test('uninstall removes a cursor (AGENTS.md/.agents) install', async () => {
  const { spawn } = await import('node:child_process');
  // install then uninstall via the bin (mirror existing uninstall.test.js helper `run`)
  await run(['install', '--yes', '--target', workdir, '--assistant', 'cursor', '--scope', 'project']);
  const { code } = await run(['uninstall', '--target', workdir, '--assistant', 'cursor', '--force']);
  expect(code).toBe(0);
  const { access } = await import('node:fs/promises');
  await expect(access(join(workdir, 'AGENTS.md'))).rejects.toBeTruthy();
  await expect(access(join(workdir, '.agents', 'skills'))).rejects.toBeTruthy();
});
```

(If `test/uninstall.test.js` lacks a `run`/`join`/`workdir` harness, copy the spawn-based `run` helper and `beforeEach`/`afterEach` tmpdir setup from `test/doctor.test.js`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/uninstall.test.js`
Expected: FAIL — `ASSISTANT_LAYOUT[cursor]` undefined.

- [ ] **Step 3: Implement** — replace the lookup in `src/commands/uninstall.js`:

```js
import { rm, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AGENTS, ENTRY_SOURCE } from '../agents.js';

async function readIfExists(path) {
  try { return await readFile(path, 'utf8'); } catch { return null; }
}

export async function uninstall({ argv, cwd, packageRoot }) {
  let target = cwd;
  let assistant = 'claude';
  let force = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
    else if (argv[i] === '--force') force = true;
  }

  const agent = AGENTS.find((a) => a.id === assistant);
  if (!agent) throw new Error(`Unknown assistant: ${assistant}.`);
  const { entryFile, skillTree } = agent;
  const entryDst = resolve(target, entryFile);

  if (!force) {
    const installed = await readIfExists(entryDst);
    const bundled = await readIfExists(resolve(packageRoot, 'sast-files', ENTRY_SOURCE[skillTree]));
    if (installed !== null && bundled !== null && installed !== bundled) {
      throw new Error(`${entryFile} has been modified; pass --force to remove it anyway.`);
    }
  }

  await rm(entryDst, { force: true });
  await rm(resolve(target, skillTree, 'skills'), { recursive: true, force: true });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/uninstall.test.js`
Expected: PASS (existing claude modified-guard test still passes).

- [ ] **Step 5: Commit**

```bash
git add src/commands/uninstall.js test/uninstall.test.js
git commit -m "feat(uninstall): remove any registry assistant"
```

---

### Task 7: Docs — README assistant list + flags (`README.md`)

**Files:**

- Modify: `README.md` (intro assistants line; CLI flags table; drop the Gemini rename note)
- Test: `test/docs-completeness.test.js` (add an assertion that README names all 14 assistants)

**Interfaces:**

- Consumes: `validIds` indirectly (assertion lists the human labels).

- [ ] **Step 1: Write the failing test** (append to `test/docs-completeness.test.js`)

```js
test('README lists every supported assistant', async () => {
  const readme = await readFile(resolve(repoRoot, 'README.md'), 'utf8');
  for (const label of ['Claude Code', 'Codex', 'Gemini', 'Copilot', 'Cursor', 'Windsurf', 'OpenCode', 'Cline', 'Antigravity', 'Aider', 'Kilo Code', 'Augment', 'Hermes', 'Mistral Vibe']) {
    expect(readme).toContain(label);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/docs-completeness.test.js`
Expected: FAIL — labels like "Windsurf", "Kilo Code" not yet in README.

- [ ] **Step 3: Update README**

Replace the intro assistants sentence (line ~5) with a sentence naming all 14:

```markdown
Turn your LLM coding assistant into a fully featured SAST scanner. Drop-in agent skills for **Claude Code, OpenAI Codex (CLI), Gemini CLI, GitHub Copilot, Cursor, Windsurf, OpenCode, Cline, Antigravity, Aider, Kilo Code, Augment, Hermes Agent, and Mistral Vibe**.
```

In the CLI flags table, change the `--assistant` row to:

```markdown
| `--assistant <ids>` | Comma-separated assistant ids (e.g. `claude,cursor,copilot`) or `all` |
```

In the Manual-install section, delete the block telling Gemini users to `mv AGENTS.md GEMINI.md` (the installer now writes `GEMINI.md` directly); replace with a one-liner: "Gemini CLI reads `GEMINI.md`; the installer writes it for you when you pick Gemini."

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/docs-completeness.test.js && npm run lint:md`
Expected: PASS + markdownlint clean.

- [ ] **Step 5: Commit**

```bash
git add README.md test/docs-completeness.test.js
git commit -m "docs(readme): document all 14 supported assistants and the new --assistant flag"
```

---

### Task 8: Interactive presentation (intro / summary / outro + Aider note)

**Files:**

- Modify: `src/banner.js` (add `summaryText`)
- Modify: `src/cli.js` (wrap the interactive install with clack `intro`/`note`/`outro`)
- Test: `test/banner.test.js` (add `summaryText` cases)

**Interfaces:**

- Consumes: the summary object returned by `install` (`{ scope, labels, entryFiles, skillCount }`).
- Produces: `summaryText(summary): string` — a multi-line message for the outro, including an
  Aider note when `labels` contains `'Aider'`.

- [ ] **Step 1: Write the failing tests** (append to `test/banner.test.js`)

```js
import { summaryText } from '../src/banner.js';

test('summaryText reports the assistants, files, and skill count', () => {
  const out = summaryText({ scope: 'project', labels: ['Claude Code', 'Cursor'], entryFiles: ['CLAUDE.md', 'AGENTS.md'], skillCount: 31 });
  expect(out).toMatch(/2 assistant/);
  expect(out).toMatch(/CLAUDE\.md/);
  expect(out).toMatch(/AGENTS\.md/);
  expect(out).toMatch(/31 skills/);
  expect(out).toMatch(/Run vulnerability scan/i);
});

test('summaryText adds an Aider hint only when Aider is selected', () => {
  expect(summaryText({ scope: 'project', labels: ['Aider'], entryFiles: ['CONVENTIONS.md'], skillCount: 31 })).toMatch(/CONVENTIONS\.md/);
  expect(summaryText({ scope: 'project', labels: ['Aider'], entryFiles: ['CONVENTIONS.md'], skillCount: 31 })).toMatch(/--read CONVENTIONS\.md/);
  expect(summaryText({ scope: 'project', labels: ['Claude Code'], entryFiles: ['CLAUDE.md'], skillCount: 31 })).not.toMatch(/--read/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/banner.test.js`
Expected: FAIL — `summaryText` is not exported.

- [ ] **Step 3: Implement** — append to `src/banner.js`:

```js
export function summaryText({ scope, labels, entryFiles, skillCount }) {
  const lines = [
    `Installed for ${labels.length} assistant${labels.length === 1 ? '' : 's'} (${scope}): ${labels.join(', ')}.`,
    `Wrote: ${entryFiles.join(', ')}  +  ${skillCount} skills.`,
    'Prompt your assistant: "Run vulnerability scan".',
  ];
  if (labels.includes('Aider')) {
    lines.push('Aider: add `--read CONVENTIONS.md` or set it in `.aider.conf.yml` so Aider loads it.');
  }
  return lines.join('\n');
}
```

Wrap the interactive install in `src/cli.js`. Import clack's `intro`, `note`, `outro` and `summaryText`; when the install runs interactively (TTY, no `--yes`), call `intro('sast-skills installer')` before and `note(summaryText(summary), 'Done')` + `outro('Happy scanning')` after. The non-interactive path returns the summary without decoration. (Visual output is verified by the manual smoke in Task 9, not unit-tested.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/banner.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/banner.js src/cli.js test/banner.test.js
git commit -m "feat(cli): summary outro with an Aider hint after interactive install"
```

---

### Task 9: Full-suite green + sync check

**Files:** none (verification only)

- [ ] **Step 1: Run the whole suite and lint**

Run: `npm test && npm run lint:md`
Expected: all tests PASS, markdownlint clean. Fix any contract-test regressions (e.g. `release-readiness` README assertions, `package-contents`) inline before proceeding.

- [ ] **Step 2: Manual smoke (non-interactive)**

```bash
node bin/sast-skills.js install --yes --assistant all --scope project --dry-run
```

Expected: prints `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.windsurf/rules/sast-skills.md`, `.clinerules/sast-skills.md`, `CONVENTIONS.md` and both skill trees.

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "test: keep contract tests green after multi-assistant install"
```
