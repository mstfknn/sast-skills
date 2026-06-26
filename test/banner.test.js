import { test, expect } from 'vitest';
import { BANNER, summaryText } from '../src/banner.js';

test('banner includes the name, repo URL, and version', () => {
  const out = BANNER('9.9.9');
  expect(out).toMatch(/github\.com\/mstfknn\/sast-skills/);
  expect(out).toMatch(/SAST scanner/i);
  expect(out).toMatch(/9\.9\.9/);
});

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
