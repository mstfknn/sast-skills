import { test, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installedIds } from '../src/detect.js';

let bindir;

beforeEach(async () => {
  bindir = await mkdtemp(join(tmpdir(), 'sast-bin-'));
});

afterEach(async () => {
  await rm(bindir, { recursive: true, force: true });
});

test('installedIds reports only agents whose cli is found on PATH', async () => {
  const fake = join(bindir, 'gemini');
  await writeFile(fake, '#!/bin/sh\n');
  await chmod(fake, 0o755);

  const agents = [
    { id: 'gemini', cli: 'gemini' }, // present on PATH
    { id: 'codex', cli: 'codex' },   // not present
    { id: 'cline' },                 // no cli probe → never detected
  ];

  const ids = await installedIds(agents, { PATH: bindir });
  expect(ids.has('gemini')).toBe(true);
  expect(ids.has('codex')).toBe(false);
  expect(ids.has('cline')).toBe(false);
});
