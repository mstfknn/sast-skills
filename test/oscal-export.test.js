import { test, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import AjvModule from 'ajv';
import addFormatsModule from 'ajv-formats';

const Ajv = AjvModule.default ?? AjvModule;
const addFormats = addFormatsModule.default ?? addFormatsModule;

const here = dirname(fileURLToPath(import.meta.url));
const bin = resolve(here, '..', 'bin', 'sast-skills.js');
const schemaDir = resolve(here, 'fixtures', 'oscal');

function run(args, opts = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [bin, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: opts.cwd,
      env: { ...process.env, ...opts.env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.on('close', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

/** Compile a validator for one of the vendored NIST OSCAL v1.2.3 schemas. */
async function validatorFor(schemaFile) {
  const schema = JSON.parse(await readFile(join(schemaDir, schemaFile), 'utf8'));
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

function assertValid(validate, doc) {
  const ok = validate(doc);
  if (!ok) {
    const detail = validate.errors
      .slice(0, 10)
      .map((e) => `${e.instancePath || '/'} ${e.message}`)
      .join('\n');
    throw new Error(`document is not schema-valid OSCAL:\n${detail}`);
  }
  expect(ok).toBe(true);
}

let workdir;

beforeEach(async () => {
  workdir = await mkdtemp(join(tmpdir(), 'sast-skills-oscal-'));
});

afterEach(async () => {
  await rm(workdir, { recursive: true, force: true });
});

const findingsFixture = {
  run: { tool: 'sast-skills', version: '0.8.2', schema: '2.0' },
  findings: [
    {
      id: 'sast-sqli-0001',
      skill: 'sast-sqli',
      severity: 'critical',
      title: 'SQL injection in /api/user',
      description: 'User id concatenated into raw query.',
      location: { file: 'src/api/user.js', line: 42, column: 10 },
      remediation: 'Use parameterized queries.',
      exploitability: 'reachable',
      confidence: 'high',
      chain_id: 'chain-1',
    },
    {
      id: 'sast-crypto-0001',
      skill: 'sast-crypto',
      severity: 'medium',
      title: 'MD5 used for password hashing',
      description: 'Password digest computed with MD5.',
      location: { file: 'src/auth/hash.js', line: 7, column: 3 },
      remediation: 'Use argon2id.',
    },
  ],
};

async function writeFixture(name = 'findings.json', data = findingsFixture) {
  const input = join(workdir, name);
  await writeFile(input, JSON.stringify(data));
  return input;
}

test('export --format oscal produces a document valid against the NIST OSCAL 1.2.3 assessment-results schema', async () => {
  const input = await writeFixture();

  const { code, stdout, stderr } = await run(['export', '--format', 'oscal', '--input', input]);
  expect(stderr).toBe('');
  expect(code).toBe(0);

  const doc = JSON.parse(stdout);
  const validate = await validatorFor('oscal_assessment-results_schema.json');
  assertValid(validate, doc);
});

test('skills map to NIST SP 800-53 controls in reviewed-controls and in each finding target', async () => {
  const input = await writeFixture();

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const result = JSON.parse(stdout)['assessment-results'].results[0];

  const selection = result['reviewed-controls']['control-selections'][0];
  expect(selection['include-controls']).toBeDefined();

  const reviewed = selection['include-controls'].map((c) => c['control-id']);
  expect(reviewed).toContain('si-10');  // sast-sqli
  expect(reviewed).toContain('sc-13');  // sast-crypto
  expect(reviewed).toEqual([...reviewed].sort()); // deterministic ordering
  expect(new Set(reviewed).size).toBe(reviewed.length); // deduped

  const targets = result.findings.map((f) => f.target['target-id']);
  expect(targets).toContain('si-10_smt');
  expect(targets).toContain('sc-13_smt');
  for (const f of result.findings) {
    expect(f.target.type).toBe('statement-id');
    expect(f.target.status.state).toBe('not-satisfied');
  }
});

test('risk characterizations carry severity, and likelihood/confidence only when the finding has them', async () => {
  const input = await writeFixture();

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const risks = JSON.parse(stdout)['assessment-results'].results[0].risks;

  const facetsOf = (risk) => Object.fromEntries(
    (risk.characterizations?.[0].facets ?? []).map((f) => [f.name, f.value]),
  );

  const sqli = facetsOf(risks.find((r) => r.title.includes('SQL injection')));
  expect(sqli.severity).toBe('critical');
  expect(sqli.likelihood).toBe('reachable');
  expect(sqli.confidence).toBe('high');

  // The v1-shaped finding carries neither exploitability nor confidence — omit, don't invent.
  const crypto = facetsOf(risks.find((r) => r.title.includes('MD5')));
  expect(crypto.severity).toBe('medium');
  expect(crypto.likelihood).toBeUndefined();
  expect(crypto.confidence).toBeUndefined();
});

test('remediation becomes an OSCAL recommendation, and skill/chain_id survive as risk props', async () => {
  const input = await writeFixture();

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const risks = JSON.parse(stdout)['assessment-results'].results[0].risks;
  const sqli = risks.find((r) => r.title.includes('SQL injection'));

  expect(sqli.status).toBe('open');
  expect(sqli.remediations?.[0].lifecycle).toBe('recommendation');
  expect(sqli.remediations[0].description).toMatch(/parameterized queries/);
  expect(sqli.props?.find((p) => p.name === 'skill')?.value).toBe('sast-sqli');
  expect(sqli.props.find((p) => p.name === 'chain-id')?.value).toBe('chain-1');

  // No remediation text on a finding means no invented response.
  const noFix = risks.find((r) => r.title.includes('MD5'));
  expect(noFix.props.find((p) => p.name === 'chain-id')).toBeUndefined();
});

test('a triaged false positive is emitted as a closed risk, not an open one', async () => {
  const input = await writeFixture('triaged.json', {
    run: { tool: 'sast-skills', version: '0.8.2' },
    findings: [{
      id: 'fp1',
      skill: 'sast-xss',
      severity: 'info',
      title: 'Reflected value in template',
      description: 'Auto-escaped by the framework.',
      location: { file: 'a.html', line: 3, column: 1 },
      remediation: '',
      triage_status: 'false_positive',
    }],
  });

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const risk = JSON.parse(stdout)['assessment-results'].results[0].risks[0];
  expect(risk.status).toBe('closed');
});

test('a clean scan still produces a schema-valid assessment-results document', async () => {
  const sastDir = join(workdir, 'sast');
  await mkdir(sastDir, { recursive: true });
  await writeFile(join(sastDir, 'sqli-results.json'), JSON.stringify({ findings: [] }));

  const { code, stdout } = await run(['export', '--format', 'oscal', '--input', sastDir]);
  expect(code).toBe(0);

  const doc = JSON.parse(stdout);
  const validate = await validatorFor('oscal_assessment-results_schema.json');
  assertValid(validate, doc);
  expect(doc['assessment-results'].results[0].observations).toBeUndefined();
});

test('a skill with no control mapping falls back to ra-5 rather than dropping the finding', async () => {
  const input = await writeFixture('unmapped.json', {
    run: { tool: 'sast-skills', version: '0.8.2' },
    findings: [{
      id: 'x1',
      skill: 'sast-brand-new-thing',
      severity: 'low',
      title: 'Something new',
      description: 'd',
      location: { file: 'a.js', line: 1, column: 1 },
      remediation: 'fix it',
    }],
  });

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const result = JSON.parse(stdout)['assessment-results'].results[0];

  expect(result.findings).toHaveLength(1);
  expect(result.findings[0].target['target-id']).toBe('ra-5_smt');
});

test('export --format oscal-poam produces a document valid against the NIST OSCAL 1.2.3 POA&M schema', async () => {
  const input = await writeFixture();

  const { code, stdout, stderr } = await run(['export', '--format', 'oscal-poam', '--input', input]);
  expect(stderr).toBe('');
  expect(code).toBe(0);

  const doc = JSON.parse(stdout);
  expect(doc['plan-of-action-and-milestones']).toBeDefined();
  const validate = await validatorFor('oscal_poam_schema.json');
  assertValid(validate, doc);
});

test('POA&M emits one poam-item per open finding, cross-linked to its finding, observation and risk', async () => {
  const input = await writeFixture();

  const { stdout } = await run(['export', '--format', 'oscal-poam', '--input', input]);
  const poam = JSON.parse(stdout)['plan-of-action-and-milestones'];

  expect(poam['poam-items']).toHaveLength(2);
  const findingUuids = new Set(poam.findings.map((f) => f.uuid));
  const obsUuids = new Set(poam.observations.map((o) => o.uuid));
  const riskUuids = new Set(poam.risks.map((r) => r.uuid));

  for (const item of poam['poam-items']) {
    expect(item.title).toBeTruthy();
    expect(findingUuids.has(item['related-findings'][0]['finding-uuid'])).toBe(true);
    expect(obsUuids.has(item['related-observations'][0]['observation-uuid'])).toBe(true);
    expect(riskUuids.has(item['related-risks'][0]['risk-uuid'])).toBe(true);
  }
});

test('POA&M excludes triaged false positives — it lists only work that is still owed', async () => {
  const input = await writeFixture('mixed.json', {
    run: { tool: 'sast-skills', version: '0.8.2' },
    findings: [
      { id: 'a', skill: 'sast-sqli', severity: 'high', title: 'real one', description: 'd', location: { file: 'a.js', line: 1, column: 1 }, remediation: 'fix', triage_status: 'confirmed' },
      { id: 'b', skill: 'sast-xss', severity: 'low', title: 'not real', description: 'd', location: { file: 'b.js', line: 2, column: 1 }, remediation: '', triage_status: 'false_positive' },
    ],
  });

  const { stdout } = await run(['export', '--format', 'oscal-poam', '--input', input]);
  const poam = JSON.parse(stdout)['plan-of-action-and-milestones'];

  expect(poam['poam-items']).toHaveLength(1);
  expect(poam['poam-items'][0].title).toMatch(/real one/);
});

test('a clean scan produces a schema-valid POA&M with an explicit no-open-items entry', async () => {
  const sastDir = join(workdir, 'sast');
  await mkdir(sastDir, { recursive: true });
  await writeFile(join(sastDir, 'sqli-results.json'), JSON.stringify({ findings: [] }));

  const { code, stdout } = await run(['export', '--format', 'oscal-poam', '--input', sastDir]);
  expect(code).toBe(0);

  const doc = JSON.parse(stdout);
  const validate = await validatorFor('oscal_poam_schema.json');
  assertValid(validate, doc);

  const items = doc['plan-of-action-and-milestones']['poam-items'];
  expect(items).toHaveLength(1); // the schema requires at least one
  expect(items[0].title).toMatch(/no open/i);
});

test('assessment-results carries the sast-skills identity, the run version, and OSCAL 1.2.3', async () => {
  const input = await writeFixture();

  const { stdout } = await run(['export', '--format', 'oscal', '--input', input]);
  const ar = JSON.parse(stdout)['assessment-results'];

  expect(ar.metadata['oscal-version']).toBe('1.2.3');
  expect(ar.metadata.version).toBe('0.8.2');
  expect(ar.metadata.title).toMatch(/sast-skills/);
  // import-ap is required by the schema; with no real plan it resolves to a
  // back-matter placeholder rather than a dangling external href.
  const apRef = ar['import-ap'].href.replace('#', '');
  expect(ar['back-matter'].resources.map((r) => r.uuid)).toContain(apRef);
});

test('every generated identifier is an OSCAL-acceptable type 4 or 5 UUID', async () => {
  // OSCAL rejects any other UUID version outright.
  const OSCAL_UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$/;
  const input = await writeFixture();

  for (const format of ['oscal', 'oscal-poam']) {
    const { stdout } = await run(['export', '--format', format, '--input', input]);
    const uuids = [...stdout.matchAll(/"[a-z-]*uuid"\s*:\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(uuids.length).toBeGreaterThan(5);
    for (const u of uuids) expect(u).toMatch(OSCAL_UUID);
  }
});

test('re-exporting the same findings is byte-identical apart from the run timestamps', async () => {
  const input = await writeFixture();
  const stripTimestamps = (s) => s.replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, '<TS>');

  for (const format of ['oscal', 'oscal-poam']) {
    const first = await run(['export', '--format', format, '--input', input]);
    const second = await run(['export', '--format', format, '--input', input]);
    expect(stripTimestamps(second.stdout)).toBe(stripTimestamps(first.stdout));
    expect(stripTimestamps(first.stdout)).toContain('<TS>'); // the strip actually matched
  }
});

test('--output writes the OSCAL document to a file instead of stdout', async () => {
  const input = await writeFixture();
  const out = join(workdir, 'report.oscal.json');

  const { code, stdout } = await run(['export', '--format', 'oscal', '--input', input, '--output', out]);
  expect(code).toBe(0);
  expect(stdout).toBe('');

  const doc = JSON.parse(await readFile(out, 'utf8'));
  expect(doc['assessment-results']).toBeDefined();
});

test('an unrecognised --format fails loudly instead of silently emitting raw JSON', async () => {
  const input = await writeFixture();

  const { code, stdout, stderr } = await run(['export', '--format', 'oscal-poem', '--input', input]);
  expect(code).toBe(1);
  expect(stdout).toBe('');
  expect(stderr).toMatch(/oscal-poem/);
  expect(stderr).toMatch(/json.*sarif.*html.*oscal/is);
});

test('the document uuid tracks the findings, so a changed scan is a distinguishable document', async () => {
  const other = {
    run: findingsFixture.run,
    findings: [findingsFixture.findings[0]], // same run identity, one finding fewer
  };
  const a = await writeFixture('a.json');
  const b = await writeFixture('b.json', other);

  const uuidOf = async (file, format, key) => {
    const { stdout } = await run(['export', '--format', format, '--input', file]);
    return JSON.parse(stdout)[key].uuid;
  };

  for (const [format, key] of [['oscal', 'assessment-results'], ['oscal-poam', 'plan-of-action-and-milestones']]) {
    expect(await uuidOf(a, format, key)).toBe(await uuidOf(a, format, key)); // stable
    expect(await uuidOf(a, format, key)).not.toBe(await uuidOf(b, format, key)); // revised
  }
});
