#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { run } from '../src/cli.js';

const [, , command, ...rest] = process.argv;
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');

if (command === '--version') {
  const pkg = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'));
  console.log(pkg.version);
} else if (command === undefined || command === '--help' || command === '-h') {
  console.log([
    'Usage: sast-skills <command>',
    '',
    'Commands:',
    '  install      Install SAST skills',
    '  update       Refresh an existing install with the bundled skill files',
    '  uninstall    Remove installed SAST skills',
    '  doctor       Verify an install against the bundled files',
    '  export       Convert sast/ findings to JSON, SARIF, or HTML',
    '',
    'Flags:',
    '  --version    Print the installed version',
  ].join('\n'));
} else if (command === 'install' || command === 'uninstall' || command === 'update' || command === 'doctor' || command === 'export') {
  try {
    await run({
      argv: [command, ...rest],
      cwd: process.cwd(),
      packageRoot,
      stdin: process.stdin,
      stdout: process.stdout,
      stderr: process.stderr,
    });
  } catch (err) {
    // Operational errors (validation, refusing to clobber, doctor findings)
    // should read as a clean, actionable line — not a Node stack trace.
    console.error(err?.message ?? err);
    process.exit(1);
  }
} else {
  console.error('Unknown command');
  process.exit(1);
}
