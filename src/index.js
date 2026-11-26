'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

function getInput(name, fallback = '') {
  const key = 'INPUT_' + name.replace(/ /g, '_').toUpperCase();
  return (process.env[key] ?? fallback).trim();
}

function setOutput(name, value) {
  const outFile = process.env.GITHUB_OUTPUT;
  const line = `${name}=${String(value)}\n`;
  if (outFile) fs.appendFileSync(outFile, line, 'utf8');
}

function writeSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) fs.appendFileSync(summaryFile, markdown + '\n', 'utf8');
}

function annotate(level, file, line, message) {
  console.log(`::${level} file=${file},line=${line}::${message}`);
}

const SECRET_RULES = [
  { id: 'AWS_ACCESS_KEY', label: 'AWS Access Key ID', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'GITHUB_PAT', label: 'GitHub Personal Access Token', regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g },
  { id: 'GITHUB_FINE_PAT', label: 'GitHub Fine-Grained PAT', regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { id: 'STRIPE_LIVE_KEY', label: 'Stripe Live Secret Key', regex: /\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b/g },
  { id: 'SLACK_TOKEN', label: 'Slack Bot/User Token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'GOOGLE_API_KEY', label: 'Google Cloud API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { id: 'PRIVATE_KEY_PEM', label: 'PEM Private Key Header', regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { id: 'JWT_TOKEN', label: 'Hardcoded JWT', regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'GENERIC_SECRET', label: 'Hardcoded Secret Assignment', regex: /(?:api_key|apikey|secret_key|password|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/gi },
];

function shannonEntropy(str) {
  const len = str.length;
  if (!len) return 0;
  const counts = {};
  for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
  let entropy = 0;
  for (const c of Object.values(counts)) {
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function redact(val) {
  if (val.length <= 8) return '****';
  return val.slice(0, 4) + '****' + val.slice(-4);
}

function walkDir(dir, ignoreList, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (ignoreList.some((ig) => full.includes(ig))) continue;
    if (entry.isDirectory()) {
      walkDir(full, ignoreList, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (['.png', '.jpg', '.jpeg', '.gif', '.zip', '.woff', '.woff2', '.pdf', '.exe'].includes(ext)) continue;
      out.push(full);
    }
  }
  return out;
}

function scanSecrets(scanPath, entropyThreshold, ignoreList) {
  const files = walkDir(scanPath, ignoreList);
  const findings = [];
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      for (const rule of SECRET_RULES) {
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(lineText)) !== null) {
          findings.push({
            file: path.relative(scanPath, file) || file,
            line: lineNum,
            rule: rule.id,
            label: rule.label,
            preview: redact(match[0]),
            entropy: Number(shannonEntropy(match[0]).toFixed(2)),
          });
        }
      }
      const tokenMatches = lineText.match(/['"]([A-Za-z0-9+/=_-]{28,})['"]/g) || [];
      for (const quoted of tokenMatches) {
        const raw = quoted.slice(1, -1);
        const ent = shannonEntropy(raw);
        if (ent >= entropyThreshold && !raw.includes('/') && !findings.some((f) => f.line === lineNum && f.file.endsWith(path.basename(file)))) {
          findings.push({
            file: path.relative(scanPath, file) || file,
            line: lineNum,
            rule: 'HIGH_ENTROPY_STRING',
            label: `High-Entropy Token (${ent.toFixed(2)} bits)`,
            preview: redact(raw),
            entropy: Number(ent.toFixed(2)),
          });
        }
      }
    });
  }
  return { filesScanned: files.length, findings };
}

function formatSummary(result, passed) {
  const lines = [
    '## PR Secret & API Key Leak Gate',
    '',
    `- **Files Scanned:** ${result.filesScanned}`,
    `- **Secrets Detected:** ${result.findings.length}`,
    `- **Gate Status:** ${passed ? 'PASSED' : 'FAILED'}`,
    '',
  ];
  if (result.findings.length > 0) {
    lines.push('| File | Line | Rule | Preview | Entropy |');
    lines.push('|------|------|------|---------|---------|');
    for (const f of result.findings.slice(0, 50)) {
      lines.push(`| \`${f.file}\` | ${f.line} | ${f.label} | \`${f.preview}\` | ${f.entropy} |`);
    }
  }
  return lines.join('\n');
}

function runSelfTest() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-gate-'));
  try {
    const sample = path.join(tmp, 'config.js');
    fs.writeFileSync(sample, 'const aws = "AKIA1234567890ABCDEF";\nconst safe = "hello-world";\n', 'utf8');
    const res = scanSecrets(tmp, 4.3, ['node_modules']);
    if (res.findings.length < 1 || res.findings[0].rule !== 'AWS_ACCESS_KEY') {
      throw new Error('Expected AWS_ACCESS_KEY detection in self-test');
    }
    console.log(`[SELF-TEST OK] pr-secret-leak-gate detected ${res.findings.length} secret(s) in ${res.filesScanned} file(s).`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function main() {
  if (process.argv.includes('--self-test')) {
    return runSelfTest();
  }
  const scanPath = getInput('scan-path', '.');
  const entropyThreshold = parseFloat(getInput('entropy-threshold', '4.3')) || 4.3;
  const failOnFind = getInput('fail-on-find', 'true').toLowerCase() !== 'false';
  const ignoreList = getInput('ignore-paths', 'node_modules,.git,dist,coverage')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const result = scanSecrets(scanPath, entropyThreshold, ignoreList);
  for (const f of result.findings) {
    annotate(failOnFind ? 'error' : 'warning', f.file, f.line, `${f.label} detected (${f.preview})`);
  }

  const passed = result.findings.length === 0 || !failOnFind;
  setOutput('findings-count', result.findings.length);
  setOutput('passed', passed ? 'true' : 'false');
  writeSummary(formatSummary(result, passed));

  if (!passed) {
    process.exitCode = 1;
  }
}

main();
