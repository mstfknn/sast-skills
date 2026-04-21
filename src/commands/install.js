import { readdir, copyFile, mkdir, access } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const ASSISTANT_LAYOUT = {
  claude: { entryFile: 'CLAUDE.md', skillsDir: '.claude' },
  agents: { entryFile: 'AGENTS.md', skillsDir: '.agents' },
};

function assistantsFor(choice) {
  if (choice === 'all') return ['claude', 'agents'];
  return [choice];
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function install({ packageRoot, argv, cwd, stdout }) {
  let target = cwd;
  let dryRun = false;
  let force = false;
  let assistant = 'claude';
  let scope = 'project';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target') target = argv[++i];
    else if (argv[i] === '--dry-run') dryRun = true;
    else if (argv[i] === '--force') force = true;
    else if (argv[i] === '--assistant') assistant = argv[++i];
    else if (argv[i] === '--scope') scope = argv[++i];
  }

  const srcRoot = resolve(packageRoot, 'sast-files');

  for (const a of assistantsFor(assistant)) {
    const { entryFile, skillsDir } = ASSISTANT_LAYOUT[a];
    const skillsSrc = resolve(srcRoot, skillsDir, 'skills');
    const skills = await readdir(skillsSrc);

    if (dryRun) {
      stdout.write(`${entryFile}\n`);
      for (const name of skills) {
        stdout.write(`${skillsDir}/skills/${name}/SKILL.md\n`);
      }
      continue;
    }

    if (scope !== 'global') {
      const entryDst = resolve(target, entryFile);
      if (!force && await exists(entryDst)) {
        const err = new Error(`${entryFile} already exists in target; use --force to overwrite`);
        err.code = 'EEXIST';
        throw err;
      }
      await copyFile(resolve(srcRoot, entryFile), entryDst);
    }

    for (const name of skills) {
      const dst = resolve(target, skillsDir, 'skills', name, 'SKILL.md');
      await mkdir(dirname(dst), { recursive: true });
      await copyFile(resolve(skillsSrc, name, 'SKILL.md'), dst);
    }
  }
}
