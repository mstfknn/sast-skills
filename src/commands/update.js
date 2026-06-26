import { readFile, readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { install } from './install.js';
import { AGENTS, ENTRY_SOURCE, ORCHESTRATOR_SIGNATURE } from '../agents.js';

async function read(path) { try { return await readFile(path, 'utf8'); } catch { return null; } }
async function exists(path) { try { await access(path); return true; } catch { return false; } }

export async function update({ argv, cwd, packageRoot, stdout, isTTY, prompt }) {
  if (argv.includes('--assistant')) {
    const summary = await install({ argv: [...argv, '--force'], cwd, packageRoot, stdout, isTTY, prompt });
    if (summary) {
      stdout.write(`Refreshed ${summary.entryFiles.join(', ')} + ${summary.skillCount} skills.\n`);
    }
    return;
  }

  let target = cwd;
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--target') target = argv[++i];

  const srcRoot = resolve(packageRoot, 'sast-files');
  const entryFiles = [...new Map(AGENTS.map((a) => [a.entryFile, a])).values()];
  const trees = [...new Set(AGENTS.map((a) => a.skillTree))];

  const refreshedEntries = [];
  let skillCount = 0;

  for (const a of entryFiles) {
    const dst = resolve(target, a.entryFile);
    const content = await read(dst);
    if (content !== null && content.includes(ORCHESTRATOR_SIGNATURE)) {
      await copyFile(resolve(srcRoot, ENTRY_SOURCE[a.skillTree]), dst);
      refreshedEntries.push(a.entryFile);
    }
  }

  for (const tree of trees) {
    const skillsDir = resolve(target, tree, 'skills');
    if (!(await exists(skillsDir))) continue;
    const installed = (await readdir(skillsDir)).filter((n) => n.startsWith('sast-'));
    if (installed.length === 0) continue;
    const names = await readdir(resolve(srcRoot, tree, 'skills'));
    for (const name of names) {
      const out = resolve(target, tree, 'skills', name, 'SKILL.md');
      await mkdir(dirname(out), { recursive: true });
      await copyFile(resolve(srcRoot, tree, 'skills', name, 'SKILL.md'), out);
    }
    skillCount = names.length;
  }

  if (refreshedEntries.length === 0 && skillCount === 0) {
    throw new Error('No sast-skills install found in target — run "npx sast-skills install".');
  }

  const entryPart = refreshedEntries.length ? refreshedEntries.join(', ') : 'skill tree';
  stdout.write(`Refreshed ${entryPart} + ${skillCount} skills.\n`);
}
