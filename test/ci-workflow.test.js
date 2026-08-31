import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const workflow = resolve(here, '..', '.github', 'workflows', 'test.yml');

test('.github/workflows/test.yml runs the test suite on push and pull_request with Node 20', async () => {
  const content = await readFile(workflow, 'utf8');
  expect(content).toMatch(/\bpush:/);
  expect(content).toMatch(/\bpull_request:/);
  expect(content).toMatch(/actions\/checkout@/);
  expect(content).toMatch(/actions\/setup-node@/);
  expect(content).toMatch(/node-version:\s*['"]?20/);
  expect(content).toMatch(/npm (ci|install)/);
  expect(content).toMatch(/npm test/);
});

test('.github/workflows/test.yml also runs markdown lint', async () => {
  const content = await readFile(workflow, 'utf8');
  expect(content).toMatch(/npm run lint:md/);
});

test('publish.yml installs an npm major that still supports the Node it pins', async () => {
  const publish = resolve(here, '..', '.github', 'workflows', 'publish.yml');
  const content = await readFile(publish, 'utf8');

  expect(content).toMatch(/tags:\s*\n\s*-\s*'v\*'/);
  expect(content).toMatch(/npm publish --provenance/);
  expect(content).toMatch(/id-token:\s*write/);

  // OIDC trusted publishing needs npm >= 11.5.1, but `npm@latest` is now npm 12,
  // which dropped Node 20 — an unbounded `@latest` silently breaks every release
  // the day a new npm major lands. Pin the major that matches the pinned Node.
  expect(content).not.toMatch(/npm install -g npm@latest/);
  expect(content).toMatch(/npm install -g npm@\^?11/);
});
