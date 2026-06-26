import { readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { resolveAgents, ENTRY_SOURCE, AGENTS } from '../agents.js';

async function exists(path) {
  try { await access(path); return true; } catch { return false; }
}

async function copyTree(srcRoot, skillTree, target) {
  const skillsSrc = resolve(srcRoot, skillTree, 'skills');
  const skills = await readdir(skillsSrc);
  for (const name of skills) {
    const dst = resolve(target, skillTree, 'skills', name, 'SKILL.md');
    await mkdir(dirname(dst), { recursive: true });
    await copyFile(resolve(skillsSrc, name, 'SKILL.md'), dst);
  }
  return skills.length;
}

export async function install({ packageRoot, argv, cwd, stdout, isTTY, prompt }) {
  let target;
  let dryRun = false;
  let force = false;
  let yes = false;
  let assistantArg;
  let scope;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--dry-run') dryRun = true;
    else if (argv[i] === '--force') force = true;
    else if (argv[i] === '--yes') yes = true;
    else if (argv[i] === '--assistant') assistantArg = argv[++i];
    else if (argv[i] === '--scope') scope = argv[++i];
  }

  if (!yes && !isTTY) {
    throw new Error('Non-interactive stdin detected; pass --yes to run without prompts, or run in an interactive TTY.');
  }

  let selection = assistantArg ? assistantArg.split(',').map((s) => s.trim()).filter(Boolean) : null;

  if (!yes && isTTY) {
    if (selection === null) {
      selection = await prompt({
        name: 'assistant',
        message: 'Which assistants should sast-skills install for?  (↑↓ move · space to select · enter to confirm)',
        choices: [
          ...AGENTS.map((a) => ({ value: a.id, label: a.label })),
          { value: 'all', label: '✨ All of the above' },
        ],
        multi: true,
      });
    }
    if (scope === undefined) {
      scope = await prompt({
        name: 'scope',
        message: 'Install scope',
        choices: [
          { value: 'project', label: 'This project (./)' },
          { value: 'global', label: 'Global (home directory)' },
        ],
      });
    }
  }

  if (selection === null) selection = ['claude'];
  else if (selection.length === 0) throw new Error('No assistants selected — nothing to install.');
  scope ??= 'project';

  if (!['project', 'global'].includes(scope)) {
    throw new Error(`Invalid --scope value: ${scope}. Expected one of: project, global.`);
  }

  let agents;
  try {
    agents = resolveAgents(selection);
  } catch (err) {
    throw new Error(`Invalid --assistant value: ${err.message}`);
  }
  const srcRoot = resolve(packageRoot, 'sast-files');
  if (target === undefined) target = scope === 'global' ? homedir() : cwd;

  const entryFiles = [...new Map(agents.map((a) => [a.entryFile, a])).values()];
  const skillTrees = [...new Set(agents.map((a) => a.skillTree))];

  if (dryRun) {
    if (scope !== 'global') for (const a of entryFiles) stdout.write(`${a.entryFile}\n`);
    for (const tree of skillTrees) {
      for (const name of await readdir(resolve(srcRoot, tree, 'skills'))) {
        stdout.write(`${tree}/skills/${name}/SKILL.md\n`);
      }
    }
    return;
  }

  if (scope !== 'global') {
    for (const a of entryFiles) {
      const entryDst = resolve(target, a.entryFile);
      if (!force && await exists(entryDst)) {
        const err = new Error(`${a.entryFile} already exists in target. Run "sast-skills update" to refresh an existing install, or pass --force to overwrite.`);
        err.code = 'EEXIST';
        throw err;
      }
      await mkdir(dirname(entryDst), { recursive: true });
      await copyFile(resolve(srcRoot, ENTRY_SOURCE[a.skillTree]), entryDst);
    }
  }

  let skillCount = 0;
  for (const tree of skillTrees) skillCount = await copyTree(srcRoot, tree, target);

  return {
    scope,
    labels: agents.map((a) => a.label),
    entryFiles: entryFiles.map((a) => a.entryFile),
    skillCount,
  };
}
