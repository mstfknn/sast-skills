import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { install } from '../src/commands/install.js';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-interactive-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

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
