import { test, expect } from 'vitest';
import { BANNER } from '../src/banner.js';

test('banner includes the name, repo URL, and version', () => {
  const out = BANNER('9.9.9');
  expect(out).toMatch(/github\.com\/mstfknn\/sast-skills/);
  expect(out).toMatch(/SAST scanner/i);
  expect(out).toMatch(/9\.9\.9/);
});
