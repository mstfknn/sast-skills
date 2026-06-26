import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, stat, writeFile, chmod } from 'node:fs/promises';
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
  expect(asked[0].choices.map((c) => c.value)).toEqual(expect.arrayContaining(['claude', 'cursor', 'copilot', 'all']));
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

test('install errors on an empty assistant selection instead of silently defaulting', async () => {
  const prompt = async ({ name }) => (name === 'assistant' ? [] : 'project');
  const stdout = { write: () => {} };
  await expect(
    install({ packageRoot, argv: ['--target', workdir], cwd: workdir, stdout, isTTY: true, prompt }),
  ).rejects.toThrow(/No assistants selected/i);
});

test('install disables undetected CLI assistants and keeps undetectable ones selectable', async () => {
  const bindir = await mkdtemp(join(tmpdir(), 'sast-bin-'));
  const gemini = join(bindir, 'gemini');
  await writeFile(gemini, '#!/bin/sh\n');
  await chmod(gemini, 0o755);
  const savedPath = process.env.PATH;
  process.env.PATH = bindir;
  try {
    let captured;
    const prompt = async ({ name, choices }) => {
      if (name === 'assistant') { captured = choices; return ['gemini']; }
      return 'project';
    };
    await install({ packageRoot, argv: ['--target', workdir], cwd: workdir, stdout: { write() {} }, isTTY: true, prompt });
    const byId = Object.fromEntries(captured.filter((c) => c.value !== 'all').map((c) => [c.value, c]));
    expect(byId.gemini.disabled).toBeFalsy();  // found on PATH → selectable
    expect(byId.codex.disabled).toBe(true);    // cli, absent from PATH → disabled
    expect(byId.cline.disabled).toBeFalsy();   // no cli probe → always selectable
  } finally {
    process.env.PATH = savedPath;
    await rm(bindir, { recursive: true, force: true });
  }
});
