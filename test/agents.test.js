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
