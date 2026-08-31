import { createHash } from 'node:crypto';
import { controlsForSkill } from './oscal-controls.js';

/** The OSCAL release these documents declare conformance to. */
export const OSCAL_VERSION = '1.2.3';

// A fixed namespace so v5 UUIDs are stable across runs, machines, and CI:
// re-exporting an unchanged sast/ directory must not churn the document.
const NAMESPACE = 'f8a2c1d4-3b7e-4a56-9c8d-1e2f3a4b5c6d';

/** RFC 4122 v5 (SHA-1) UUID — OSCAL only accepts type 4 or type 5. */
export function uuid5(name) {
  const ns = Buffer.from(NAMESPACE.replace(/-/g, ''), 'hex');
  const digest = createHash('sha1').update(Buffer.concat([ns, Buffer.from(name, 'utf8')])).digest();
  const b = Buffer.from(digest.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const TOOL_COMPONENT_UUID = uuid5('component:sast-skills');
const PLATFORM_UUID = uuid5('platform:sast-skills');
const AP_RESOURCE_UUID = uuid5('resource:assessment-plan');

const toolOrigin = () => ({ actors: [{ type: 'tool', 'actor-uuid': TOOL_COMPONENT_UUID }] });

/** Content-derived key so the same finding yields the same UUIDs on every run. */
function findingKey(f) {
  const loc = f.location ?? {};
  return [f.skill, loc.file, loc.line, loc.column, f.title].join('|');
}

/**
 * A digest of everything the document reports. OSCAL expects a document's uuid
 * to change when the document is revised, so deriving it from the findings —
 * not just the tool version — keeps re-exports stable while still making a
 * changed scan a distinguishable document.
 */
function runDigest(items) {
  return createHash('sha256')
    .update(items.map((f) => `${findingKey(f)}|${f.severity}|${f.triage_status ?? ''}`).join('\n'))
    .digest('hex');
}

function metadata(tool, version, now) {
  return {
    title: `SAST Assessment Results — ${tool}`,
    'last-modified': now,
    version,
    'oscal-version': OSCAL_VERSION,
    props: [{ name: 'tool', value: tool }],
  };
}

function assessmentAssets(tool, version) {
  return {
    components: [{
      uuid: TOOL_COMPONENT_UUID,
      type: 'software',
      title: tool,
      description: 'LLM-driven static analysis skill bundle.',
      status: { state: 'operational' },
      props: [{ name: 'version', value: version }],
    }],
    'assessment-platforms': [{
      uuid: PLATFORM_UUID,
      title: `${tool} scanner`,
      'uses-components': [{ 'component-uuid': TOOL_COMPONENT_UUID }],
    }],
  };
}

function observationFor(f, now) {
  const key = findingKey(f);
  const loc = f.location ?? {};
  const obs = {
    uuid: uuid5(`observation:${key}`),
    title: f.title,
    description: f.description,
    methods: ['TEST'],
    types: ['finding'],
    origins: [toolOrigin()],
    collected: now,
  };
  if (loc.file) {
    obs['relevant-evidence'] = [{
      href: `${encodeURI(loc.file)}#L${loc.line}`,
      description: `Detected by ${f.skill} at ${loc.file}:${loc.line}.`,
    }];
  }
  return obs;
}

// A facet is only meaningful alongside the vocabulary it is scored in. These are
// sast-skills' own ladders, not CVSS, so they are namespaced to the generic
// OSCAL system rather than to a scoring system we do not actually use.
const FACET_SYSTEM = 'http://csrc.nist.gov/ns/oscal';

/** Severity always; likelihood/confidence only when the finding carries them. */
function facetsFor(f) {
  const facets = [{ name: 'severity', system: FACET_SYSTEM, value: f.severity }];
  if (f.exploitability) facets.push({ name: 'likelihood', system: FACET_SYSTEM, value: f.exploitability });
  if (f.confidence) facets.push({ name: 'confidence', system: FACET_SYSTEM, value: f.confidence });
  return facets;
}

/** Carries the sast-skills fields OSCAL has no first-class slot for. */
function riskProps(f) {
  const props = [{ name: 'skill', value: f.skill }];
  if (f.chain_id) props.push({ name: 'chain-id', value: f.chain_id });
  if (f.triage_status) props.push({ name: 'triage-status', value: f.triage_status });
  return props;
}

function riskFor(f) {
  const key = findingKey(f);
  const loc = f.location ?? {};
  const risk = {
    uuid: uuid5(`risk:${key}`),
    title: f.title,
    description: f.description,
    statement: loc.file ? `${f.description} Observed at ${loc.file}:${loc.line}.` : f.description,
    props: riskProps(f),
    // A finding triage ruled out is a risk that has been dispositioned, not an
    // open one — but it stays in the SAR as evidence the scanner considered it.
    status: f.triage_status === 'false_positive' ? 'closed' : 'open',
    origins: [toolOrigin()],
    characterizations: [{ origin: toolOrigin(), facets: facetsFor(f) }],
    'related-observations': [{ 'observation-uuid': uuid5(`observation:${key}`) }],
  };
  if (f.remediation) {
    risk.remediations = [{
      uuid: uuid5(`response:${key}`),
      lifecycle: 'recommendation',
      title: `Remediate: ${f.title}`,
      description: f.remediation,
      origins: [toolOrigin()],
    }];
  }
  return risk;
}

/**
 * One OSCAL finding per (sast finding × mapped control): each control objective
 * gets its own verdict, all pointing back at the same observation and risk.
 */
function findingsFor(f) {
  const key = findingKey(f);
  return controlsForSkill(f.skill).map((control) => ({
    uuid: uuid5(`finding:${key}:${control}`),
    title: `${f.title} (${control.toUpperCase()})`,
    description: f.description,
    origins: [toolOrigin()],
    target: {
      type: 'statement-id',
      'target-id': `${control}_smt`,
      status: { state: 'not-satisfied', reason: 'fail' },
    },
    'related-observations': [{ 'observation-uuid': uuid5(`observation:${key}`) }],
    'related-risks': [{ 'risk-uuid': uuid5(`risk:${key}`) }],
  }));
}

/** A single unit of remediation work, cross-linked to its finding/observation/risk. */
function poamItemFor(f) {
  const key = findingKey(f);
  const loc = f.location ?? {};
  return {
    uuid: uuid5(`poam-item:${key}`),
    title: f.title,
    description: loc.file ? `${f.description} (${loc.file}:${loc.line})` : f.description,
    props: riskProps(f),
    'related-findings': findingsFor(f).map((finding) => ({ 'finding-uuid': finding.uuid })),
    'related-observations': [{ 'observation-uuid': uuid5(`observation:${key}`) }],
    'related-risks': [{ 'risk-uuid': uuid5(`risk:${key}`) }],
  };
}

/** Sorted, deduped control ids across every finding in the run. */
function reviewedControls(items) {
  const ids = [...new Set(items.flatMap((f) => controlsForSkill(f.skill)))].sort();
  // `include-controls` has minItems: 1, so a clean scan cannot express its
  // selection that way. OSCAL spells "nothing in particular" as include-all.
  return ids.length > 0
    ? { 'control-selections': [{ 'include-controls': ids.map((id) => ({ 'control-id': id })) }] }
    : { 'control-selections': [{ 'include-all': {} }] };
}

/**
 * Render canonical sast-skills findings as an OSCAL plan-of-action-and-milestones.
 *
 * A POA&M is a list of work still owed, so anything triage ruled out is left
 * behind — unlike the SAR, which keeps false positives as dispositioned risks.
 */
export function toOscalPoam(data, { now = new Date().toISOString() } = {}) {
  const tool = data.run?.tool ?? 'sast-skills';
  const version = data.run?.version ?? '0.0.0';
  const open = (data.findings ?? []).filter((f) => f.triage_status !== 'false_positive');
  const digest = runDigest(open);

  const poam = {
    uuid: uuid5(`poam:${tool}:${version}:${digest}`),
    metadata: { ...metadata(tool, version, now), title: `SAST Plan of Action and Milestones — ${tool}` },
    'system-id': { 'identifier-type': 'https://ietf.org/rfc/rfc4122', id: uuid5(`system:${tool}`) },
    'local-definitions': { 'assessment-assets': assessmentAssets(tool, version) },
    'poam-items': open.map((f) => poamItemFor(f)),
  };

  if (open.length > 0) {
    poam.observations = open.map((f) => observationFor(f, now));
    poam.risks = open.map((f) => riskFor(f));
    poam.findings = open.flatMap((f) => findingsFor(f));
  } else {
    // `poam-items` has minItems: 1, so a clean scan has to say so explicitly
    // rather than hand back an empty list.
    poam['poam-items'] = [{
      uuid: uuid5('poam-item:none'),
      title: 'No open findings',
      description: `${tool} ${version} completed with no open findings to remediate.`,
    }];
  }

  return { 'plan-of-action-and-milestones': poam };
}

/** Render canonical sast-skills findings as an OSCAL assessment-results (SAR) document. */
export function toOscalAssessmentResults(data, { now = new Date().toISOString() } = {}) {
  const items = data.findings ?? [];
  const tool = data.run?.tool ?? 'sast-skills';
  const version = data.run?.version ?? '0.0.0';
  const digest = runDigest(items);

  const result = {
    uuid: uuid5(`result:${tool}:${version}:${digest}`),
    title: 'Automated static analysis scan',
    description: `Findings produced by ${tool} ${version}.`,
    start: now,
    end: now,
    'local-definitions': { 'assessment-assets': assessmentAssets(tool, version) },
    'reviewed-controls': reviewedControls(items),
  };

  // Every optional OSCAL array has minItems: 1 — omit rather than emit [].
  if (items.length > 0) {
    result.observations = items.map((f) => observationFor(f, now));
    result.risks = items.map((f) => riskFor(f));
    result.findings = items.flatMap((f) => findingsFor(f));
  }

  return {
    'assessment-results': {
      uuid: uuid5(`assessment-results:${tool}:${version}:${digest}`),
      metadata: metadata(tool, version, now),
      'import-ap': {
        href: `#${AP_RESOURCE_UUID}`,
        remarks: 'No formal assessment plan — this is an ad-hoc automated scan.',
      },
      results: [result],
      'back-matter': {
        resources: [{
          uuid: AP_RESOURCE_UUID,
          title: 'Ad-hoc automated SAST assessment',
          description: `Placeholder for the assessment plan implied by running ${tool}.`,
        }],
      },
    },
  };
}
