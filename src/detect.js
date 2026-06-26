import { access, constants } from 'node:fs/promises';
import { join, delimiter } from 'node:path';

// Best-effort: is `cmd` an executable on the given PATH? Dependency-free, no
// subprocess. Used only to disable assistants we can confidently probe.
async function onPath(cmd, env) {
  const dirs = (env.PATH || '').split(delimiter).filter(Boolean);
  const exts = process.platform === 'win32'
    ? (env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';')
    : [''];
  for (const dir of dirs) {
    for (const ext of exts) {
      try {
        await access(join(dir, cmd + ext), constants.F_OK);
        return true;
      } catch {
        // not here — keep looking
      }
    }
  }
  return false;
}

/**
 * Ids of agents whose `cli` command is found on PATH. Agents without a `cli`
 * probe (editor extensions, GUI apps) are never reported — callers must keep
 * them selectable rather than treat absence as "not installed".
 * @param {Array<{id: string, cli?: string}>} agents
 * @param {NodeJS.ProcessEnv} [env]
 */
export async function installedIds(agents, env = process.env) {
  const found = new Set();
  await Promise.all(
    agents.map(async (a) => {
      if (a.cli && (await onPath(a.cli, env))) found.add(a.id);
    }),
  );
  return found;
}
