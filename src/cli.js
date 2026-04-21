import { install } from './commands/install.js';
import { clackPrompt } from './prompts/clack.js';

export async function run({ argv, cwd, packageRoot, stdin, stdout }) {
  await install({
    argv: argv.slice(1),
    cwd,
    packageRoot,
    stdout,
    isTTY: Boolean(stdin.isTTY),
    prompt: clackPrompt,
  });
}
