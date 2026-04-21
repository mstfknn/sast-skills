import { readFile, writeFile, stat, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const SEVERITY_TO_SARIF_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function toHtml(data) {
  const rows = data.findings.map((f) => `<tr>
  <td>${escapeHtml(f.skill)}</td>
  <td>${escapeHtml(f.severity)}</td>
  <td>${escapeHtml(f.title)}</td>
  <td>${escapeHtml(f.location.file)}:${f.location.line}</td>
  <td>${escapeHtml(f.description)}</td>
</tr>`).join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>SAST Report</title></head>
<body>
<h1>SAST Report — ${escapeHtml(data.run.tool)} ${escapeHtml(data.run.version)}</h1>
<table border="1">
<thead><tr><th>Skill</th><th>Severity</th><th>Title</th><th>Location</th><th>Description</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</body>
</html>
`;
}

function toSarif(data) {
  const rules = [...new Set(data.findings.map((f) => f.skill))].map((id) => ({ id }));
  const results = data.findings.map((f) => ({
    ruleId: f.skill,
    level: SEVERITY_TO_SARIF_LEVEL[f.severity] ?? 'warning',
    message: { text: `${f.title}\n\n${f.description}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.location.file },
        region: { startLine: f.location.line, startColumn: f.location.column },
      },
    }],
  }));
  return {
    version: '2.1.0',
    runs: [{ tool: { driver: { name: data.run.tool, rules } }, results }],
  };
}

export async function exportCmd({ argv, stdout }) {
  let input;
  let output;
  let format = 'json';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--input') input = argv[++i];
    else if (argv[i] === '--output') output = argv[++i];
    else if (argv[i] === '--format') format = argv[++i];
  }
  const info = await stat(input);
  let data;
  if (info.isDirectory()) {
    const files = (await readdir(input)).filter((n) => n.endsWith('-results.json'));
    const findings = [];
    for (const f of files) {
      const parsed = JSON.parse(await readFile(join(input, f), 'utf8'));
      if (Array.isArray(parsed.findings)) findings.push(...parsed.findings);
    }
    data = { run: { tool: 'sast-skills', version: '0.1.0' }, findings };
  } else {
    data = JSON.parse(await readFile(input, 'utf8'));
  }
  const payload = format === 'html'
    ? toHtml(data)
    : `${JSON.stringify(format === 'sarif' ? toSarif(data) : data)}\n`;
  if (output) {
    await writeFile(output, payload);
  } else {
    stdout.write(payload);
  }
}
