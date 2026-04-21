#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const [, , command] = process.argv;

if (command === '--version') {
  const here = dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(await readFile(resolve(here, '..', 'package.json'), 'utf8'));
  console.log(pkg.version);
} else if (command === undefined) {
  console.log('Usage: sast-skills <command>\n\nCommands:\n  install    Install SAST skills');
} else {
  console.error('Unknown command');
  process.exit(1);
}
