#!/usr/bin/env node

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const scanner = path.join(repoRoot, 'scripts', 'rock-house-ci.js');
const assuranceTool = path.join(repoRoot, 'scripts', 'rock-house-assurance.js');
const assuranceKeygenTool = path.join(repoRoot, 'scripts', 'rock-house-assurance-keygen.js');

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

async function run() {
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
  await testDastDetectsRuntimeHeaders();
  await testDastAdvancedProbes();
  testHighRiskWithoutAssuranceBlocks();
  await testHighRiskAssuranceUsesDastEvidence();
  testExpiredStructuredApprovalBlocks();
  testInvalidStructuredApprovalErrors();
  testTamperedAssuranceDigestBlocks();
  testUnsignedAssuranceBlocks();
  testExternalTrustPolicyPasses();
  testRevokedSigningKeyBlocks();
  testDisallowedSigningKeyBlocks();
  testAssurancePolicyEnvironmentBlocks();
  testAssurancePolicyReferenceBlocks();
  testAssurancePolicyValidityBlocks();
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

async function testDastDetectsRuntimeHeaders() {
  const server = await startServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('X-Powered-By', 'express');
    res.end('<html><body>ok</body></html>');
  });

  try {
    const fixture = makeTempProject('rock-house-dast-runtime-');
    writeFile(fixture, 'app/page.tsx', 'export default function Page() { return <div>ok</div>; }');
    const output = path.join(fixture, 'report.json');
    const configPath = path.join(fixture, 'rock-house.config.json');
    writeFile(fixture, 'rock-house.config.json', JSON.stringify({
      path: fixture,
      minLevel: 'bronze',
      output,
      dast: {
        url: server.url,
        paths: ['/'],
        timeoutMs: 2000
      }
    }, null, 2));

    const result = await runScannerAsyncFromConfig(configPath);

    assert.notStrictEqual(result.status, 0, 'runtime CORS issue should keep certification below bronze target when critical');
    const report = readJson(output);
    assert.strictEqual(report.dast.executed, true);
    assert(report.findings.some((finding) => finding.checkId === 'H1'), 'dynamic scan should detect missing CSP');
    assert(report.findings.some((finding) => finding.checkId === 'H4'), 'dynamic scan should detect wildcard CORS with credentials');
  } finally {
    await closeServer(server.instance);
  }
}

async function testDastAdvancedProbes() {
  const server = await startServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/admin') {
      res.statusCode = 200;
      res.end('admin panel');
      return;
    }
    if (url.pathname === '/redirect') {
      res.statusCode = 302;
      res.setHeader('Location', url.searchParams.get('next') || '/');
      res.end();
      return;
    }
    if (url.pathname === '/boom') {
      res.statusCode = 500;
      res.end('TypeError: fail\n    at handler (/app/server.js:10:3)');
      return;
    }
    res.statusCode = 200;
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.end('ok');
  });

  try {
    const fixture = makeTempProject('rock-house-dast-advanced-');
    writeFile(fixture, 'app/page.tsx', 'export default function Page() { return <div>ok</div>; }');
    const output = path.join(fixture, 'report.json');
    const configPath = path.join(fixture, 'rock-house.config.json');
    writeFile(fixture, 'rock-house.config.json', JSON.stringify({
      path: fixture,
      minLevel: 'bronze',
      output,
      dast: {
        url: server.url,
        paths: ['/redirect'],
        authProtectedPaths: ['/admin'],
        errorPaths: ['/boom'],
        redirectParamNames: ['next'],
        timeoutMs: 2000
      }
    }, null, 2));

    const result = await runScannerAsyncFromConfig(configPath);

    assert.notStrictEqual(result.status, 0, 'advanced probes should fail when protected route, redirect, and error route are unsafe');
    const report = readJson(output);
    assert(report.findings.some((finding) => finding.checkId === 'A4'), 'auth probe should detect unprotected route');
    assert(report.findings.some((finding) => finding.checkId === 'H7'), 'redirect probe should detect open redirect');
    assert(report.findings.some((finding) => finding.checkId === 'S7' && finding.file.includes('/boom')), 'error-route probe should detect stack disclosure');
  } finally {
    await closeServer(server.instance);
  }
}

async function testHighRiskAssuranceUsesDastEvidence() {
  const server = await startServer((req, res) => {
    res.statusCode = 200;
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.end('ok');
  });

  try {
  const fixture = makeTempProject('rock-house-high-risk-assurance-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'high-risk-assurance-fixture',
    private: true,
    dependencies: {
      '@sentry/nextjs': '^8.0.0'
    }
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'high-risk-assurance-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'app/api/payments/route.ts', 'export async function POST() { return Response.json({ ok: true }); }');
  writeFile(fixture, 'app/api/health/route.ts', 'export async function GET() { return Response.json({ ok: true }); }');
  writeFile(fixture, 'instrumentation.ts', 'import * as Sentry from "@sentry/nextjs";\nSentry.init({ dsn: process.env.SENTRY_DSN });');
  writeFile(fixture, 'assurance.json', JSON.stringify({
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout',
      reference: 'CR-2026-051'
    }
  }, null, 2));
  const keys = createSigningKeys(fixture);
  signAssuranceFile(path.join(fixture, 'assurance.json'), keys.privateKey, keys.keyId);
  writeFile(fixture, 'observability.json', JSON.stringify({
    auditLogs: true,
    alerts: true
  }, null, 2));

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: path.join(fixture, 'assurance.json'),
    assuranceTrust: {
      publicKeys: [
        { keyId: keys.keyId, path: keys.publicKey }
      ]
    },
    observability: {
      evidence: path.join(fixture, 'observability.json')
    },
    dast: {
      url: server.url,
      paths: ['/'],
      timeoutMs: 2000
    }
  }, null, 2));

  const result = await runScannerAsyncFromConfig(configPath);

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.result, 'passed');
  assert.strictEqual(report.riskProfile, 'high');
  assert.strictEqual(report.assurance.file, path.join(fixture, 'assurance.json'));
  assert.strictEqual(report.observability.evidenceFile, path.join(fixture, 'observability.json'));
  assert.deepStrictEqual(report.observability.providers, ['sentry']);
  assert.strictEqual(report.findings.some((finding) => /^R[0-4]$/.test(finding.checkId)), false, 'assurance findings should not exist when bundle is complete');
  assert(report.gates.some((gate) => gate.id === 'R1' && gate.status === 'PASS'), 'dynamic testing gate should pass');
  assert(report.gates.some((gate) => gate.id === 'R2' && gate.status === 'PASS'), 'monitoring gate should pass');
  } finally {
    await closeServer(server.instance);
  }
}

function testExpiredStructuredApprovalBlocks() {
  const fixture = makeTempProject('rock-house-expired-approval-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'expired-approval-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'expired-approval-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'app/api/payments/route.ts', 'export async function POST() { return Response.json({ ok: true }); }');
  writeFile(fixture, 'assurance.json', JSON.stringify({
    dynamicTesting: { completed: true, environment: 'staging', date: '2026-05-30' },
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout',
      reference: 'CR-2026-052',
      expires: '2026-05-29'
    }
  }, null, 2));
  const keys = createSigningKeys(fixture);
  signAssuranceFile(path.join(fixture, 'assurance.json'), keys.privateKey, keys.keyId);

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: path.join(fixture, 'assurance.json'),
    assuranceTrust: {
      publicKeys: [
        { keyId: keys.keyId, path: keys.publicKey }
      ]
    }
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.notStrictEqual(result.status, 0, 'expired approval should fail high-risk certification');
  const report = readJson(output);
  assert(report.findings.some((finding) => finding.checkId === 'R4'), 'expired structured approval must fail R4');
}

function testExternalTrustPolicyPasses() {
  const fixture = makeTempProject('rock-house-trust-file-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'production',
    reference: 'CR-2026-058',
    expires: '2026-06-30'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const trustPath = writeTrustPolicy(fixture, keys.keyId, keys.publicKey, {
    allowedKeyIds: [keys.keyId],
    revokedKeyIds: ['NEXT_PUBLIC_SERVICE_SECRET_TEST']
  });

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: assurancePath,
    assuranceTrustFile: trustPath
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  const report = readJson(output);
  assert.strictEqual(report.assurance.trustFile, trustPath);
  assert(report.gates.some((gate) => gate.id === 'R6' && gate.status === 'PASS'), 'external trust policy must validate signature');
  assert.strictEqual(report.findings.some((finding) => finding.file === 'assurance-trust.json'), false, 'trust policy manifest must be excluded from source scanning');
}

function testInvalidStructuredApprovalErrors() {
  const fixture = makeTempProject('rock-house-invalid-approval-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'invalid-approval-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'invalid-approval-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  writeFile(fixture, 'assurance.json', JSON.stringify({
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout'
    }
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

  assert.strictEqual(result.status, 2, 'invalid structured approval should fail fast');
}

function testTamperedAssuranceDigestBlocks() {
  const fixture = makeTempProject('rock-house-tampered-assurance-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'tampered-assurance-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'tampered-assurance-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  const assurancePath = path.join(fixture, 'assurance.json');
  writeFile(fixture, 'assurance.json', JSON.stringify({
    dynamicTesting: { completed: true, environment: 'staging', date: '2026-05-30' },
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout',
      reference: 'CR-2026-053'
    }
  }, null, 2));
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);

  const assurance = readJson(assurancePath);
  assurance.approval.scope = 'tampered scope';
  fs.writeFileSync(assurancePath, `${JSON.stringify(assurance, null, 2)}\n`, 'utf8');

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: assurancePath,
    assuranceTrust: {
      publicKeys: [
        { keyId: keys.keyId, path: keys.publicKey }
      ]
    }
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.notStrictEqual(result.status, 0, 'tampered assurance digest should fail high-risk certification');
  const report = readJson(output);
  assert(report.findings.some((finding) => finding.checkId === 'R5'), 'tampered assurance digest must fail R5');
  assert(report.findings.some((finding) => finding.checkId === 'R6'), 'tampered assurance signature must fail R6');
}

function testUnsignedAssuranceBlocks() {
  const fixture = makeTempProject('rock-house-unsigned-assurance-');
  writeFile(fixture, 'package.json', JSON.stringify({
    name: 'unsigned-assurance-fixture',
    private: true
  }, null, 2));
  writeFile(fixture, 'package-lock.json', JSON.stringify({
    name: 'unsigned-assurance-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  const assurancePath = path.join(fixture, 'assurance.json');
  writeFile(fixture, 'assurance.json', JSON.stringify({
    dynamicTesting: { completed: true, environment: 'staging', date: '2026-05-30' },
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout',
      reference: 'CR-2026-054'
    }
  }, null, 2));
  const keys = createSigningKeys(fixture);
  writeAssuranceIntegrity(assurancePath);

  const output = path.join(fixture, 'report.json');
  const configPath = path.join(fixture, 'rock-house.config.json');
  writeFile(fixture, 'rock-house.config.json', JSON.stringify({
    path: fixture,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: assurancePath,
    assuranceTrust: {
      publicKeys: [
        { keyId: keys.keyId, path: keys.publicKey }
      ]
    }
  }, null, 2));

  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });

  assert.notStrictEqual(result.status, 0, 'unsigned assurance should fail high-risk certification');
  const report = readJson(output);
  assert(report.findings.some((finding) => finding.checkId === 'R6'), 'missing signature must fail R6');
}

function testRevokedSigningKeyBlocks() {
  const fixture = makeTempProject('rock-house-revoked-key-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'production',
    reference: 'CR-2026-058',
    expires: '2026-06-01'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const report = runPolicyScan(fixture, assurancePath, keys.publicKey, keys.keyId, null, {
    revokedKeyIds: [keys.keyId]
  });
  assert(report.findings.some((finding) => finding.checkId === 'R10'), 'revoked signing key must fail R10');
}

function testDisallowedSigningKeyBlocks() {
  const fixture = makeTempProject('rock-house-disallowed-key-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'production',
    reference: 'CR-2026-059',
    expires: '2026-06-01'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const report = runPolicyScan(fixture, assurancePath, keys.publicKey, keys.keyId, null, {
    allowedKeyIds: ['release-signing-2']
  });
  assert(report.findings.some((finding) => finding.checkId === 'R11'), 'disallowed signing key must fail R11');
}

function testAssurancePolicyEnvironmentBlocks() {
  const fixture = makeTempProject('rock-house-policy-env-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'staging',
    reference: 'CR-2026-055',
    expires: '2026-06-01'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const report = runPolicyScan(fixture, assurancePath, keys.publicKey, keys.keyId, {
    requiredEnvironment: 'production'
  });
  assert(report.findings.some((finding) => finding.checkId === 'R7'), 'environment policy mismatch must fail R7');
}

function testAssurancePolicyReferenceBlocks() {
  const fixture = makeTempProject('rock-house-policy-ref-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'production',
    reference: 'ticket-55',
    expires: '2026-06-01'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const report = runPolicyScan(fixture, assurancePath, keys.publicKey, keys.keyId, {
    referencePattern: '^CR-[0-9]{4}-[0-9]{3}$'
  });
  assert(report.findings.some((finding) => finding.checkId === 'R8'), 'reference policy mismatch must fail R8');
}

function testAssurancePolicyValidityBlocks() {
  const fixture = makeTempProject('rock-house-policy-validity-');
  const assurancePath = writePolicyFixture(fixture, {
    environment: 'production',
    reference: 'CR-2026-056',
    expires: '2026-07-15'
  });
  const keys = createSigningKeys(fixture);
  signAssuranceFile(assurancePath, keys.privateKey, keys.keyId);
  const report = runPolicyScan(fixture, assurancePath, keys.publicKey, keys.keyId, {
    requireExpires: true,
    maxApprovalAgeDays: 10,
    maxExpiryDays: 7
  });
  assert(report.findings.some((finding) => finding.checkId === 'R9'), 'approval validity policy mismatch must fail R9');
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
  assertInvalidConfig({ assuranceTrustFile: true }, 'assuranceTrustFile must be string');
  assertInvalidConfig({ assuranceTrust: true }, 'assuranceTrust must be object');
  assertInvalidConfig({ assuranceTrust: { publicKeys: [] } }, 'assuranceTrust publicKeys must be non-empty');
  assertInvalidConfig({ assuranceTrust: { publicKeys: [{ keyId: 'a' }] } }, 'assuranceTrust public key path is required');
  assertInvalidConfig({ assuranceTrust: { publicKeys: [{ keyId: 'a', path: 'k.pem' }], revokedKeyIds: true } }, 'assuranceTrust revokedKeyIds must be string array');
  assertInvalidConfig({ assuranceTrust: { publicKeys: [{ keyId: 'a', path: 'k.pem' }], allowedKeyIds: true } }, 'assuranceTrust allowedKeyIds must be string array');
  assertInvalidConfig({ assurancePolicy: true }, 'assurancePolicy must be object');
  assertInvalidConfig({ assurancePolicy: { referencePattern: '[' } }, 'assurancePolicy referencePattern must be valid regex');
  assertInvalidConfig({ assurancePolicy: { maxApprovalAgeDays: 0 } }, 'assurancePolicy maxApprovalAgeDays must be positive');
  assertInvalidConfig({ dast: true }, 'dast must be object');
  assertInvalidConfig({ dast: { url: 123 } }, 'dast url must be string');
  assertInvalidConfig({ dast: { url: 'http://127.0.0.1:3000', timeoutMs: 0 } }, 'dast timeout must be positive');
  assertInvalidConfig({ dast: { url: 'http://127.0.0.1:3000', authProtectedPaths: true } }, 'dast auth paths must be string array');
  assertInvalidConfig({ dast: { url: 'http://127.0.0.1:3000', errorPaths: true } }, 'dast error paths must be string array');
  assertInvalidConfig({ dast: { url: 'http://127.0.0.1:3000', redirectParamNames: true } }, 'dast redirect params must be string array');
  assertInvalidConfig({ observability: true }, 'observability must be object');
  assertInvalidConfig({ observability: { evidence: true } }, 'observability evidence must be string');
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

function runScannerAsyncFromConfig(configPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scanner, '--config', configPath], {
      cwd: repoRoot,
      env: process.env
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (status) => {
      resolve({ status, stdout, stderr });
    });
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

function signAssuranceFile(file, privateKey, keyId) {
  const result = spawnSync(process.execPath, [assuranceTool, '--file', file, '--write', '--sign', '--private-key', privateKey, '--key-id', keyId], {
    cwd: repoRoot,
    encoding: 'utf8'
  });
  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
}

function writeAssuranceIntegrity(file) {
  const result = spawnSync(process.execPath, [assuranceTool, '--file', file, '--write'], {
    cwd: repoRoot,
    encoding: 'utf8'
  });
  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
}

function createSigningKeys(root) {
  const privateKey = path.join(root, 'assurance-private.pem');
  const publicKey = path.join(root, 'assurance-public.pem');
  const keyId = 'release-signing-1';
  const result = spawnSync(process.execPath, [assuranceKeygenTool, '--private-out', privateKey, '--public-out', publicKey], {
    cwd: repoRoot,
    encoding: 'utf8'
  });
  assert.strictEqual(result.status, 0, result.stdout + result.stderr);
  return { privateKey, publicKey, keyId };
}

function writeTrustPolicy(root, keyId, publicKey, overrides = {}) {
  const trustPath = path.join(root, 'assurance-trust.json');
  writeFile(root, 'assurance-trust.json', JSON.stringify({
    publicKeys: [
      { keyId, path: publicKey }
    ],
    ...overrides
  }, null, 2));
  return trustPath;
}

function writePolicyFixture(root, approvalOverrides = {}) {
  writeFile(root, 'package.json', JSON.stringify({
    name: 'policy-fixture',
    private: true
  }, null, 2));
  writeFile(root, 'package-lock.json', JSON.stringify({
    name: 'policy-fixture',
    lockfileVersion: 3,
    packages: {}
  }, null, 2));
  const assurancePath = path.join(root, 'assurance.json');
  writeFile(root, 'assurance.json', JSON.stringify({
    dynamicTesting: { completed: true, environment: 'staging', date: '2026-05-30' },
    monitoring: { errorTracking: true, auditLogs: true, alerts: true, healthChecks: true },
    review: { completed: true, reviewer: 'security-team', date: '2026-05-30' },
    approval: {
      schemaVersion: 1,
      status: 'approved',
      approver: 'release-manager',
      date: '2026-05-30',
      environment: 'production',
      scope: 'payments rollout',
      reference: 'CR-2026-057',
      ...approvalOverrides
    }
  }, null, 2));
  return assurancePath;
}

function runPolicyScan(root, assurancePath, publicKey, keyId, assurancePolicy, trustOverrides = {}) {
  const output = path.join(root, 'report.json');
  const configPath = path.join(root, 'rock-house.config.json');
  const config = {
    path: root,
    minLevel: 'bronze',
    output,
    riskProfile: 'high',
    assurance: assurancePath,
    assuranceTrust: {
      publicKeys: [
        { keyId, path: publicKey }
      ],
      ...trustOverrides
    }
  };
  if (assurancePolicy) config.assurancePolicy = assurancePolicy;
  writeFile(root, 'rock-house.config.json', JSON.stringify(config, null, 2));
  const result = spawnSync(process.execPath, [scanner, '--config', configPath], {
    cwd: repoRoot,
    encoding: 'utf8'
  });
  assert.notStrictEqual(result.status, 0, result.stdout + result.stderr);
  return readJson(output);
}

function startServer(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        instance: server,
        url: `http://127.0.0.1:${address.port}`
      });
    });
    server.on('error', reject);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
