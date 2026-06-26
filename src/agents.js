// `cli` is set only for CLI-primary assistants whose absence from PATH reliably
// means "not installed" — used to disable them in the interactive picker. App-
// and editor-extension assistants (Cursor, Windsurf, Copilot, Cline, Kilo Code,
// Antigravity) have no dependable PATH probe, so they carry no `cli` and stay
// selectable. `label` uses each tool's official name.
export const AGENTS = [
  { id: 'claude', label: 'Claude Code', entryFile: 'CLAUDE.md', skillTree: '.claude', cli: 'claude' },
  { id: 'codex', label: 'OpenAI Codex CLI', entryFile: 'AGENTS.md', skillTree: '.agents', cli: 'codex' },
  { id: 'gemini', label: 'Gemini CLI', entryFile: 'GEMINI.md', skillTree: '.agents', cli: 'gemini' },
  { id: 'copilot', label: 'GitHub Copilot', entryFile: '.github/copilot-instructions.md', skillTree: '.agents' },
  { id: 'cursor', label: 'Cursor', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'windsurf', label: 'Windsurf', entryFile: '.windsurf/rules/sast-skills.md', skillTree: '.agents' },
  { id: 'opencode', label: 'OpenCode', entryFile: 'AGENTS.md', skillTree: '.agents', cli: 'opencode' },
  { id: 'cline', label: 'Cline', entryFile: '.clinerules/sast-skills.md', skillTree: '.agents' },
  { id: 'antigravity', label: 'Antigravity', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'aider', label: 'Aider', entryFile: 'CONVENTIONS.md', skillTree: '.agents', cli: 'aider' },
  { id: 'kilocode', label: 'Kilo Code', entryFile: 'AGENTS.md', skillTree: '.agents' },
  { id: 'augment', label: 'Augment Code', entryFile: 'AGENTS.md', skillTree: '.agents', cli: 'auggie' },
  { id: 'hermes', label: 'Hermes Agent', entryFile: 'AGENTS.md', skillTree: '.agents', cli: 'hermes' },
  { id: 'mistralvibe', label: 'Mistral Vibe', entryFile: 'AGENTS.md', skillTree: '.agents' },
];

// Orchestrator source per skill tree: the entry file written for a `.claude` agent
// comes from sast-files/CLAUDE.md, every `.agents`-family agent from sast-files/AGENTS.md.
export const ENTRY_SOURCE = { '.claude': 'CLAUDE.md', '.agents': 'AGENTS.md' };

// Shared H1 in both orchestrator files — used to recognize an existing sast-skills
// install (so `update` never clobbers a user-authored entry file).
export const ORCHESTRATOR_SIGNATURE = 'SAST Security Assessment';

const BY_ID = new Map(AGENTS.map((a) => [a.id, a]));

// Synthetic target for the legacy `agents` alias — the generic AGENTS.md / .agents
// install shared by every AGENTS.md-based assistant (Codex, Cursor, OpenCode, …).
const AGENTS_ALIAS = { id: 'agents', label: 'AGENTS.md assistants', entryFile: 'AGENTS.md', skillTree: '.agents' };

// Fail loud at module load if a registry entry uses a skill tree with no
// orchestrator source — keeps the registry and ENTRY_SOURCE in lockstep.
for (const a of AGENTS) {
  if (!ENTRY_SOURCE[a.skillTree]) {
    throw new Error(`Registry agent "${a.id}" uses skillTree "${a.skillTree}" with no ENTRY_SOURCE entry.`);
  }
}

const VALID_IDS = Object.freeze(AGENTS.map((a) => a.id));

/**
 * Every concrete assistant id (excludes the `all` / `agents` aliases).
 * @returns {readonly string[]}
 */
export function validIds() {
  return VALID_IDS;
}

/**
 * Resolve a single assistant id — including the legacy `agents` alias — to its
 * registry entry, or null if the id is unknown.
 * @param {string} id
 * @returns {{id: string, label: string, entryFile: string, skillTree: string} | null}
 */
export function agentById(id) {
  if (id === 'agents') return AGENTS_ALIAS;
  return BY_ID.get(id) ?? null;
}

/**
 * Expand a selection (concrete ids plus the `all` / `agents` aliases) to a deduped
 * list of registry entries. Throws on an unknown id.
 * @param {string[]} selection
 */
export function resolveAgents(selection) {
  const expanded = [];
  for (const raw of selection) {
    if (raw === 'all') { expanded.push(...VALID_IDS); continue; }
    expanded.push(raw);
  }
  const seen = new Set();
  const out = [];
  for (const id of expanded) {
    const agent = agentById(id);
    if (!agent) {
      throw new Error(`Unknown assistant: ${id}. Valid: ${VALID_IDS.join(', ')}, all.`);
    }
    if (seen.has(agent.id)) continue;
    seen.add(agent.id);
    out.push(agent);
  }
  return out;
}
