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
