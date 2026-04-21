#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { install } from '../src/commands/install.js';

const [, , command, ...rest] = process.argv;
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');

if (command === '--version') {
  const pkg = JSON.parse(await readFile(resolve(packageRoot, 'package.json'), 'utf8'));
  console.log(pkg.version);
} else if (command === undefined) {
  console.log('Usage: sast-skills <command>\n\nCommands:\n  install    Install SAST skills');
} else if (command === 'install') {
  await install({ packageRoot, argv: rest, cwd: process.cwd(), stdout: process.stdout });
} else {
  console.error('Unknown command');
  process.exit(1);
}
