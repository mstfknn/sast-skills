import { rm, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AGENTS, ENTRY_SOURCE } from '../agents.js';

async function readIfExists(path) {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return null;
  }
}

export async function uninstall({ argv, cwd, packageRoot }) {
  let target = cwd;
  let assistant = 'claude';
  let force = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--assistant') assistant = argv[++i];
    else if (argv[i] === '--force') force = true;
  }

  const agent = AGENTS.find((a) => a.id === assistant);
  if (!agent) throw new Error(`Unknown assistant: ${assistant}.`);
  const { entryFile, skillTree } = agent;
  const entryDst = resolve(target, entryFile);

  if (!force) {
    const installed = await readIfExists(entryDst);
    const bundled = await readIfExists(resolve(packageRoot, 'sast-files', ENTRY_SOURCE[skillTree]));
    if (installed !== null && bundled !== null && installed !== bundled) {
      throw new Error(`${entryFile} has been modified; pass --force to remove it anyway.`);
    }
  }

  await rm(entryDst, { force: true });
  await rm(resolve(target, skillTree, 'skills'), { recursive: true, force: true });
}
