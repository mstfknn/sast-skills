import { test, expect, vi } from 'vitest';

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  note: vi.fn(),
  outro: vi.fn(),
}));

vi.mock('../src/commands/install.js', () => ({
  install: vi.fn().mockResolvedValue({
    scope: 'project',
    labels: ['Claude Code'],
    entryFiles: ['CLAUDE.md'],
    skillCount: 31,
  }),
}));
vi.mock('../src/prompts/clack.js', () => ({
  clackPrompt: vi.fn(),
}));

const { intro, note, outro } = await import('@clack/prompts');
const { run } = await import('../src/cli.js');

test('run install calls intro/note/outro when interactive (TTY, no --yes)', async () => {
  await run({
    argv: ['install'],
    cwd: '/tmp',
    packageRoot: '/pkg',
    stdin: { isTTY: true },
    stdout: { write: () => {} },
    stderr: { write: () => {} },
  });

  expect(intro).toHaveBeenCalledWith('sast-skills installer');
  expect(note).toHaveBeenCalledTimes(1);
  expect(outro).toHaveBeenCalledWith('Happy scanning');
});
