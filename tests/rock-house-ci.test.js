#!/usr/bin/env node

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const scanner = path.join(repoRoot, 'scripts', 'rock-house-ci.js');

run();

function run() {
  testVulnerableDemoBlocks();
  testCleanFixturePasses();
  testConfigControlsScan();
  testSuppressionsAreAudited();
  testCriticalSuppressionsBlockedByDefault();
  testBaselineFailOnNewOnly();
  testScannerArtifactsAreIgnored();
  testGeneratedArtifactsDirectoryIsIgnored();
  testEscapedInnerHtmlDoesNotCreateFinding();
  testMalformedPnpmWorkspaceIsReported();
  testHighRiskWithoutAssuranceBlocks();
  testHighRiskAssuranceAllowsProgress();
  testMissingPathErrors();
  testMissingConfigErrors();
  testInvalidConfigErrors();
  console.log('rock-house-ci tests passed');
}

function testBaselineFailOnNewOnly() {
  const fixture = makeTempProject('rock-house-baseline-');
  writeFile(fixture, 'app/page.tsx', [
    'export default function Page() {',
    '  return <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;',
    '}'
  ].join('\n'));

  const baselineOutput = path.join(fixture, 'baseline.json');
  const firstRun = runScanner(fixture, baselineOutput, 'bronze');
  assert.notStrictEqual(firstRun.status, 0, 'initial vulnerable scan should fail');

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    baseline: baselineOutput,
    failOnNewOnly: true
  }, null, 2));

  const secondRun = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(secondRun.status, 0, secondRun.stdout + secondRun.stderr);
  const report = readJson(output);
  assert.strictEqual(report.result, 'passed');
  assert.strictEqual(report.baseline.matched, 1);
  assert.strictEqual(report.baseline.new, 0);
  assert(report.findings.every((finding) => finding.baseline === true), 'known findings must be marked as baseline');
}

function testScannerArtifactsAreIgnored() {
  const fixture = makeTempProject('rock-house-artifacts-');
  writeFile(fixture, 'app/page.tsx', [
    'export default function Page() {',
    '  return <div>ok</div>;',
    '}'
  ].join('\n'));
  writeFile(fixture, 'rock-house-report.json', JSON.stringify({
    tool: 'rock-house',
    findings: [
      {
        checkId: 'I3',
        file: 'app/page.tsx',
        description: 'dangerouslySetInnerHTML from a previous report'
      }
    ]
  }, null, 2));

  const output = path.join(os.tmpdir(), `rock-house-artifacts-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.findings.some((finding) => finding.file === 'rock-house-report.json'), false, 'scanner output artifacts must not be scanned');
}

function testGeneratedArtifactsDirectoryIsIgnored() {
  const fixture = makeTempProject('rock-house-generated-artifacts-');
  writeFile(fixture, 'artifacts/mockup-sandbox/app/page.tsx', [
    'export default function Page() {',
    '  return <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;',
    '}'
  ].join('\n'));
  writeFile(fixture, 'app/page.tsx', [
    'export default function Page() {',
    '  return <div>ok</div>;',
    '}'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-generated-artifacts-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.findings.some((finding) => finding.file.startsWith('artifacts/')), false, 'generated artifacts directory must not be scanned by default');
}

function testEscapedInnerHtmlDoesNotCreateFinding() {
  const fixture = makeTempProject('rock-house-innerhtml-');
  writeFile(fixture, 'static/app.js', [
    'function escapeHtml(s) { return String(s).replace(/[&<>]/g, ""); }',
    'function renderSafe(user) {',
    '  document.getElementById("safe").innerHTML = `<div>${escapeHtml(user.name)}</div>`;',
    '}',
    'function renderUnsafe(user) {',
    '  document.getElementById("unsafe").innerHTML = `<div>${user.name}</div>`;',
    '}'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-innerhtml-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  const i2Findings = report.findings.filter((finding) => finding.checkId === 'I2');
  assert.strictEqual(i2Findings.length, 1, 'only unescaped innerHTML should be reported');
  assert.strictEqual(i2Findings[0].line, 6);
}

function testMalformedPnpmWorkspaceIsReported() {
  const fixture = makeTempProject('rock-house-pnpm-workspace-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'pnpm-workspace-fixture',
    packageManager: 'pnpm@9.15.0',
    dependencies: {
      next: '^16.0.0'
    }
  }, null, 2));
  writeFile(fixture, 'pnpm-lock.yaml', [
    "lockfileVersion: '9.0'",
    '',
    'importers:',
    '  .:',
    '    dependencies: {}'
  ].join('\n'));
  writeFile(fixture, 'pnpm-workspace.yaml', [
    'onlyBuiltDependencies:',
    '  - sharp',
    'overrides:',
    "  postcss: '>=8.5.10'"
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-pnpm-workspace-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert(report.findings.some((finding) => finding.checkId === 'D2' && finding.file === 'pnpm-workspace.yaml'), 'malformed pnpm workspace should be reported');
}

function testHighRiskWithoutAssuranceBlocks() {
  const fixture = makeTempProject('rock-house-high-risk-no-assurance-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'high-risk-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'high-risk-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'app/api/payments/route.ts', 'export async function POST() { return Response.json({ ok: true }); }');

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high'
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.notStrictEqual(result.status, 0, 'high-risk project without assurance bundle should fail');
  const report = readJson(output);
  assert.strictEqual(report.certification, 'Bloqueado');
  assert(report.findings.some((finding) => finding.checkId === 'R0'), 'missing assurance bundle must be reported');
}

function testHighRiskAssuranceAllowsProgress() {
  const fixture = makeTempProject('rock-house-high-risk-assurance-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'high-risk-assurance-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'high-risk-assurance-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'app/api/payments/route.ts', 'export async function POST() { return Response.json({ ok: true }); }');
  writeFile(fixture, 'assurance.json', JSON.stringify({
    dynamicTesting: { completed: true, environment: 'staging', date: '2026-05-30' },
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: { humanApproved: true, approver: 'release-manager', date: '2026-05-30' }
  }, null, 2));

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: path.join(fixture, 'assurance.json')
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.result, 'passed');
  assert.strictEqual(report.riskProfile, 'high');
  assert.strictEqual(report.assurance.file, path.join(fixture, 'assurance.json'));
  assert.strictEqual(report.findings.some((finding) => /^R[0-4]$/.test(finding.checkId)), false, 'assurance findings should not exist when bundle is complete');
  assert(report.gates.some((gate) => gate.id === 'R1' && gate.status === 'PASS'), 'dynamic testing gate should pass');
}

function testSuppressionsAreAudited() {
  const fixture = makeTempProject('rock-house-suppress-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'suppress-fixture',
    private: true,
    dependencies: {
      next: 'latest'
    }
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'suppress-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));

  const output = path.join(fixture, 'report.json');
  const markdown = path.join(fixture, 'summary.md');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    markdown,
    suppressions: [
      {
        checkId: 'D4',
        path: 'package.json',
        reason: 'Test suppression for loose dependency version.',
        expires: '2999-12-31'
      }
    ]
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.findings.some((finding) => finding.checkId === 'D4'), false, 'suppressed D4 should not count as active finding');
  assert.strictEqual(report.suppressed.length, 1, 'suppressed finding must remain in report');
  assert.strictEqual(report.suppressed[0].suppression.reason, 'Test suppression for loose dependency version.');
  assert(fs.readFileSync(markdown, 'utf8').includes('## Supressoes'), 'Markdown must include suppressions section');
}

function testCriticalSuppressionsBlockedByDefault() {
  const fixture = makeTempProject('rock-house-critical-suppress-');
  writeFile(fixture, 'app/page.tsx', [
    'export default function Page() {',
    '  return <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;',
    '}'
  ].join('\n'));

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    suppressions: [
      {
        checkId: 'I3',
        path: 'app/page.tsx',
        reason: 'Attempted critical suppression should not apply.'
      }
    ]
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.notStrictEqual(result.status, 0, 'critical finding should still block by default');
  const report = readJson(output);
  assert(report.findings.some((finding) => finding.checkId === 'I3'), 'critical finding must remain active');
  assert.strictEqual(report.suppressed.length, 0);
}

function testVulnerableDemoBlocks() {
  const target = path.join(repoRoot, 'examples', 'vulnerable-next-supabase');
  const output = path.join(os.tmpdir(), `rock-house-vulnerable-${Date.now()}.json`);
  const sarifOutput = path.join(os.tmpdir(), `rock-house-vulnerable-${Date.now()}.sarif`);
  const markdownOutput = path.join(os.tmpdir(), `rock-house-vulnerable-${Date.now()}.md`);
  const stepSummary = path.join(os.tmpdir(), `rock-house-step-summary-${Date.now()}.md`);
  const githubOutput = path.join(os.tmpdir(), `rock-house-github-output-${Date.now()}.txt`);
  const result = runScanner(target, output, 'prata', { sarifOutput, markdownOutput, stepSummary, githubOutput });

  assert.notStrictEqual(result.status, 0, 'vulnerable demo must fail the gate');
  const report = readJson(output);
  assert.strictEqual(report.result, 'blocked');
  assert.strictEqual(report.certification, 'Bloqueado');
  assert(report.summary.critical >= 1, 'vulnerable demo must report critical findings');
  assert(report.findings.some((finding) => finding.checkId === 'S4'), 'must detect NEXT_PUBLIC service exposure');
  assert(report.findings.some((finding) => finding.checkId === 'I3'), 'must detect dangerouslySetInnerHTML');
  const s4Finding = report.findings.find((finding) => finding.checkId === 'S4');
  assert(s4Finding.rule.owasp.includes('A02:2021 Cryptographic Failures'), 'JSON finding must include OWASP mapping');
  assert(s4Finding.rule.cwe.includes('CWE-798'), 'JSON finding must include CWE mapping');

  const sarif = readJson(sarifOutput);
  assert.strictEqual(sarif.version, '2.1.0');
  assert.strictEqual(sarif.runs[0].tool.driver.informationUri, 'https://github.com/angellovedpl-a11y/rock-house');
  assert(sarif.runs[0].results.length >= report.findings.length, 'SARIF must include findings');
  assert(sarif.runs[0].results.some((resultItem) => resultItem.ruleId === 'S4'), 'SARIF must include S4 finding');
  assert(sarif.runs[0].results.every((resultItem) => resultItem.locations[0].physicalLocation.artifactLocation.uri), 'SARIF findings must include file locations');
  const s4Rule = sarif.runs[0].tool.driver.rules.find((rule) => rule.id === 'S4');
  assert(s4Rule.properties.tags.includes('CWE-798'), 'SARIF rule must include CWE tag');
  assert(s4Rule.properties.tags.includes('A02:2021 Cryptographic Failures'), 'SARIF rule must include OWASP tag');

  const markdown = fs.readFileSync(markdownOutput, 'utf8');
  assert(markdown.includes('# Rock House Security Gate'), 'Markdown summary must have title');
  assert(markdown.includes('**Certificacao:** Bloqueado'), 'Markdown summary must include certification');
  assert(markdown.includes('## Bloqueios / Findings'), 'Markdown summary must include findings section');
  assert(markdown.includes('CWE-798'), 'Markdown summary must include CWE mapping');

  const stepSummaryContent = fs.readFileSync(stepSummary, 'utf8');
  assert(stepSummaryContent.includes('# Rock House Security Gate'), 'GitHub step summary must receive Markdown content');

  const githubOutputContent = fs.readFileSync(githubOutput, 'utf8');
  assert(githubOutputContent.includes('result=blocked'), 'GitHub output must include result');
  assert(githubOutputContent.includes('certification=Bloqueado'), 'GitHub output must include certification');
  assert(githubOutputContent.includes(`report=${output}`), 'GitHub output must include report path');
}

function testCleanFixturePasses() {
  const fixture = makeTempProject('rock-house-clean-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'clean-fixture',
    private: true,
    dependencies: {
      next: '^15.0.0',
      react: '^19.0.0'
    }
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'clean-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'app/api/profile/route.ts', [
    'import { NextResponse } from "next/server";',
    'export async function GET() {',
    '  return NextResponse.json({ ok: true });',
    '}'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-clean-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.result, 'passed');
  assert.notStrictEqual(report.certification, 'Bloqueado');
  assert.strictEqual(report.summary.critical, 0);
  assert.strictEqual(report.summary.high, 0);
}

function testMissingPathErrors() {
  const output = path.join(os.tmpdir(), `rock-house-missing-${Date.now()}.json`);
  const result = runScanner(path.join(os.tmpdir(), 'rock-house-does-not-exist'), output, 'bronze');
  assert.strictEqual(result.status, 2, 'missing path should return usage/runtime error code 2');
  assert(!fs.existsSync(output), 'missing path should not create a report');
}

function testConfigControlsScan() {
  const fixture = makeTempProject('rock-house-config-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'config-fixture',
    private: true,
    dependencies: {
      next: '^15.0.0'
    }
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'config-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'excluded/page.tsx', [
    'export default function Page() {',
    '  return <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;',
    '}'
  ].join('\n'));

  const output = path.join(fixture, 'out', 'report.json');
  const markdown = path.join(fixture, 'out', 'summary.md');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    markdown,
    exclude: ['excluded']
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.result, 'passed');
  assert.strictEqual(report.findings.some((finding) => finding.checkId === 'I3'), false, 'excluded directory must not be scanned');
  assert(fs.existsSync(markdown), 'markdown output from config should be written');
}

function testMissingConfigErrors() {
  const result = spawnSync(process.execPath, [
    scanner,
    '--config', path.join(os.tmpdir(), 'rock-house-missing-config.json')
  ], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 2, 'missing config should return error code 2');
}

function testInvalidConfigErrors() {
  assertInvalidConfig({ minlevel: 'prata' }, 'unknown config key should fail');
  assertInvalidConfig({ minLevel: 'gold' }, 'invalid minLevel should fail');
  assertInvalidConfig({ riskProfile: 'critical' }, 'invalid riskProfile should fail');
  assertInvalidConfig({ assurance: true }, 'assurance must be string');
  assertInvalidConfig({ exclude: 'docs' }, 'exclude must be array of strings');
  assertInvalidConfig({ allowCriticalSuppressions: 'yes' }, 'allowCriticalSuppressions must be boolean');
  assertInvalidConfig({ failOnNewOnly: 'yes' }, 'failOnNewOnly must be boolean');
  assertInvalidConfig({ baseline: 123 }, 'baseline must be string');
  assertInvalidConfig({ suppressions: [{ checkId: 'D4' }] }, 'suppression without reason should fail');
  assertInvalidConfig({
    suppressions: [{ checkId: 'D4', reason: 'x', severity: 'Critical' }]
  }, 'invalid suppression severity should fail');
  assertInvalidConfig({
    suppressions: [{ checkId: 'D4', reason: 'x', expires: 'not-a-date' }]
  }, 'invalid suppression expiration should fail');
}

function assertInvalidConfig(config, message) {
  const fixture = makeTempProject('rock-house-invalid-config-');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    ...config
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 2, message);
}

function runScanner(target, output, minLevel, options = {}) {
  const args = [
    scanner,
    '--path', target,
    '--min-level', minLevel,
    '--output', output
  ];

  if (options.sarifOutput) {
    args.push('--sarif', options.sarifOutput);
  }
  if (options.markdownOutput) {
    args.push('--markdown', options.markdownOutput);
  }

  const env = { ...process.env };
  if (options.stepSummary) {
    env.GITHUB_STEP_SUMMARY = options.stepSummary;
  }
  if (options.githubOutput) {
    env.GITHUB_OUTPUT = options.githubOutput;
  }

  return spawnSync(process.execPath, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env
  });
}

function makeTempProject(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFile(root, relativePath, content) {
  const file = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${content}\n`, 'utf8');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
