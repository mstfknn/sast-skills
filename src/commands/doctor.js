import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { agentById, ENTRY_SOURCE } from '../agents.js';

async function readIfExists(path) {
  try { return await readFile(path, 'utf8'); } catch { return null; }
}
function classify(installed, bundled) {
  if (installed === null) return 'MISSING';
  if (installed !== bundled) return 'MODIFIED';
  return 'OK';
}

export async function doctor({ argv, cwd, packageRoot, stdout }) {
  let target = cwd;
  let assistant = 'claude';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
  }

  const agent = agentById(assistant);
  if (!agent) throw new Error(`Unknown assistant: ${assistant}.`);
  const { entryFile, skillTree } = agent;
  const srcRoot = resolve(packageRoot, 'sast-files');
  let ok = true;

  const bundledEntry = await readIfExists(resolve(srcRoot, ENTRY_SOURCE[skillTree]));
  const installedEntry = await readIfExists(resolve(target, entryFile));
  const entryStatus = classify(installedEntry, bundledEntry);
  if (entryStatus !== 'OK') ok = false;
  stdout.write(`${entryFile}: ${entryStatus}\n`);

  const skillsSrc = resolve(srcRoot, skillTree, 'skills');
  for (const name of await readdir(skillsSrc)) {
    const bundled = await readIfExists(resolve(skillsSrc, name, 'SKILL.md'));
    const installed = await readIfExists(resolve(target, skillTree, 'skills', name, 'SKILL.md'));
    const status = classify(installed, bundled);
    if (status !== 'OK') ok = false;
    stdout.write(`${skillTree}/skills/${name}/SKILL.md: ${status}\n`);
  }

  if (!ok) throw new Error('doctor detected issues');
}
