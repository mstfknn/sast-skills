import { intro, note, outro } from '@clack/prompts';
import { install } from './commands/install.js';
import { update } from './commands/update.js';
import { uninstall } from './commands/uninstall.js';
import { doctor } from './commands/doctor.js';
import { exportCmd } from './commands/export.js';
import { clackPrompt } from './prompts/clack.js';
import { summaryText } from './banner.js';

export async function run({ argv, cwd, packageRoot, stdin, stdout }) {
  const [command, ...rest] = argv;
  if (command === 'uninstall') {
    await uninstall({ argv: rest, cwd, packageRoot });
    return;
  }
  if (command === 'doctor') {
    await doctor({ argv: rest, cwd, packageRoot, stdout });
    return;
  }
  if (command === 'export') {
    await exportCmd({ argv: rest, cwd, stdout });
    return;
  }
  if (command === 'update') {
    await update({ argv: rest, cwd, packageRoot, stdout, isTTY: Boolean(stdin.isTTY), prompt: clackPrompt });
    return;
  }
  const interactive = Boolean(stdin.isTTY) && !rest.includes('--yes');
  if (interactive) {
    intro('sast-skills installer');
  }
  const summary = await install({
    argv: rest,
    cwd,
    packageRoot,
    stdout,
    isTTY: Boolean(stdin.isTTY),
    prompt: clackPrompt,
  });
  if (interactive && summary) {
    note(summaryText(summary), 'Done');
    outro('Happy scanning');
  }
}
