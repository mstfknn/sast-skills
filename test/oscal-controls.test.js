import { test, expect } from 'vitest';
import { readdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SKILL_CONTROLS, controlsForSkill, FALLBACK_CONTROLS } from '../src/oscal-controls.js';

const here = dirname(fileURLToPath(import.meta.url));
const skillsDir = resolve(here, '..', 'sast-files', '.claude', 'skills');

// The recon/synthesis skills drive the scan but never emit findings, so they
// have no control objective to put in doubt.
const NON_DETECTION = new Set(['sast-analysis', 'sast-stack', 'sast-report', 'sast-triage']);

async function detectionSkills() {
  const entries = await readdir(skillsDir, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory() && !NON_DETECTION.has(e.name))
    .map((e) => e.name)
    .sort();
}

test('every bundled detection skill has an explicit NIST SP 800-53 control mapping', async () => {
  const skills = await detectionSkills();
  const unmapped = skills.filter((s) => !Object.hasOwn(SKILL_CONTROLS, s));

  expect(unmapped).toEqual([]);
  expect(skills.length).toBeGreaterThan(0);
});

test('the map has no stale entries pointing at skills that no longer ship', async () => {
  const skills = new Set(await detectionSkills());
  const stale = Object.keys(SKILL_CONTROLS).filter((s) => !skills.has(s));

  expect(stale).toEqual([]);
});

test('every mapped control id is spelled the way the OSCAL 800-53 catalog spells it', () => {
  // e.g. si-10, ac-6, sc-13, si-10.3 — lowercase family, number, optional enhancement.
  const CATALOG_ID = /^[a-z]{2}-\d+(\.\d+)?$/;

  for (const [skill, controls] of Object.entries(SKILL_CONTROLS)) {
    expect(controls.length, `${skill} has no controls`).toBeGreaterThan(0);
    for (const id of controls) expect(id, `${skill} -> ${id}`).toMatch(CATALOG_ID);
  }
  for (const id of FALLBACK_CONTROLS) expect(id).toMatch(CATALOG_ID);
});

test('an unknown skill falls back rather than returning nothing', () => {
  expect(controlsForSkill('sast-not-a-real-skill')).toEqual(FALLBACK_CONTROLS);
  expect(controlsForSkill('sast-sqli')).toContain('si-10');
});
