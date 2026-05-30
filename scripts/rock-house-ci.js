#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const {
  LEVEL_RANK,
  loadConfig,
  parseArgs,
  readBoolean,
  resolveConfigPath
} = require('./lib/config');
const { evaluateAssurance, loadAssurance } = require('./lib/assurance');
const { runDast } = require('./lib/dast');
const { shouldFlagInnerHtml } = require('./lib/js-detection');
const { toMarkdown, toSarif } = require('./lib/report-formatters');
const { impactFor, ruleFor } = require('./lib/rules');
const { scanPnpmWorkspace } = require('./lib/supply-chain-detection');

const args = parseArgs(process.argv.slice(2));

const configPath = resolveConfigPath(args.config || process.env.INPUT_CONFIG);
const config = loadConfig(configPath);
const targetRoot = path.resolve(args.path || process.env.INPUT_PATH || config.path || process.cwd());
const outputInput = args.output || process.env.INPUT_OUTPUT || config.output;
const outputPath = outputInput ? path.resolve(outputInput) : path.join(targetRoot, 'rock-house-report.json');
const sarifInput = args.sarif || process.env.INPUT_SARIF || config.sarif;
const sarifPath = sarifInput ? path.resolve(sarifInput) : '';
const markdownInput = args.markdown || process.env.INPUT_MARKDOWN || config.markdown;
const markdownPath = markdownInput ? path.resolve(markdownInput) : '';
const minLevel = (args['min-level'] || process.env.INPUT_MIN_LEVEL || config.minLevel || 'prata').toLowerCase();
const riskProfile = String(args['risk-profile'] || process.env.INPUT_RISK_PROFILE || config.riskProfile || 'standard').toLowerCase();
const dast = resolveDastConfig(args, config);
const extraExclude = Array.isArray(config.exclude) ? config.exclude.map(normalizePath) : [];
const suppressions = Array.isArray(config.suppressions) ? config.suppressions : [];
const allowCriticalSuppressions = config.allowCriticalSuppressions === true;
const baselineInput = args.baseline || process.env.INPUT_BASELINE || config.baseline;
const baselinePath = baselineInput ? path.resolve(baselineInput) : '';
const assuranceInput = args.assurance || process.env.INPUT_ASSURANCE || config.assurance;
const assurancePath = assuranceInput ? path.resolve(assuranceInput) : '';
const assurance = loadAssurance(assurancePath, fail);
const baselineFingerprints = loadBaseline(baselinePath);
const failOnNewOnly = readBoolean(args['fail-on-new-only'], process.env.INPUT_FAIL_ON_NEW_ONLY, config.failOnNewOnly);
const annotationsEnabled = readBoolean(args.annotations, process.env.INPUT_ANNOTATIONS, config.annotations, true);
const scannerArtifactPaths = new Set([
  configPath,
  assurancePath,
  outputPath,
  sarifPath,
  markdownPath,
  baselinePath
].filter(Boolean).map((file) => path.resolve(file)));

const SCANNER_ARTIFACT_FILES = new Set([
  'rock-house-report.json',
  'rock-house-baseline.json',
  'rock-house.sarif',
  'rock-house-summary.md'
]);

const SOURCE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.sql', '.html', '.css', '.json', '.yaml', '.yml', '.toml'
]);

const EXCLUDED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', '.next', 'coverage', 'artifacts',
  '__pycache__', 'venv', '.venv'
]);

const findings = [];
const suppressed = [];
const unknown = [];
const gates = [];

main().catch((error) => {
  fail(error.message);
});

async function main() {
  if (!fs.existsSync(targetRoot)) {
    fail(`Target path does not exist: ${targetRoot}`);
  }

  const files = listFiles(targetRoot);
  const packageJsonPath = path.join(targetRoot, 'package.json');
  const hasPackageJson = fs.existsSync(packageJsonPath);
  const hasGit = fs.existsSync(path.join(targetRoot, '.git'));

  scanFiles(files);
  scanPackageJson(packageJsonPath, hasPackageJson);
  scanLockfile(hasPackageJson);
  scanPnpmWorkspace(targetRoot, hasPackageJson, addFinding);
  const dastReport = await runDast({ dast, addFinding, addUnknown, gates, fail });
  evaluateAssurance({
    assurance,
    assuranceFile: assurancePath,
    riskProfile,
    dynamicTestingCompleted: dastReport.executed,
    dynamicTestingEvidence: dastReport.executed ? `Dynamic DAST completed against ${dastReport.url}.` : '',
    addFinding,
    gates
  });

  if (!hasGit) {
    addUnknown('S2', 'Secrets', 'No .git directory found; git history scan unavailable.', 'Run in a git checkout and run Gitleaks history scan.', 'Ouro');
  }

  if (hasPackageJson) {
    addUnknown('D2', 'Supply Chain', 'Dependency CVE audit was not executed by this dependency-free CI scanner.', 'Run npm audit/pnpm audit/pip-audit and feed results into Rock House.', 'Ouro');
    addUnknown('D3', 'Supply Chain', 'Current advisory database was not queried.', 'Run an advisory-backed scanner such as npm audit, OSV, or GitHub Advanced Security.', 'Ouro');
  }

  const newFindings = findings.filter((finding) => !finding.baseline);
  const baselineFindings = findings.filter((finding) => finding.baseline);
  const gateFindings = failOnNewOnly ? newFindings : findings;
  const summary = summarize(gateFindings, unknown);
  const score = calculateScore(summary);
  const confidence = calculateConfidence(summary);
  const certification = decideCertification(summary, score, confidence);
  const result = certification === 'Bloqueado' ? 'blocked' : 'passed';

  const report = {
    tool: 'rock-house',
    version: '0.1-ci',
    target: targetRoot,
    config: configPath || null,
    riskProfile,
    assurance: {
      file: assurancePath || null
    },
    dast: dastReport,
    result,
    certification,
    score,
    confidence,
    summary,
    findings,
    suppressed,
    unknown,
    gates,
    baseline: {
      path: baselinePath || null,
      failOnNewOnly,
      matched: baselineFindings.length,
      new: newFindings.length
    }
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

  if (sarifPath) {
    fs.mkdirSync(path.dirname(sarifPath), { recursive: true });
    fs.writeFileSync(sarifPath, `${JSON.stringify(toSarif(report), null, 2)}\n`, 'utf8');
  }

  const markdown = toMarkdown(report);
  if (markdownPath) {
    fs.mkdirSync(path.dirname(markdownPath), { recursive: true });
    fs.writeFileSync(markdownPath, markdown, 'utf8');
  }
  writeGithubStepSummary(markdown);

  printSummary(report);
  writeGithubAnnotations(report);
  writeGithubOutputs(report);

  const minRank = LEVEL_RANK[minLevel] ?? LEVEL_RANK.prata;
  const actualRank = LEVEL_RANK[certification.toLowerCase()] ?? 0;

  if (result === 'blocked' || actualRank < minRank) {
    process.exitCode = 1;
  }
}

function resolveDastConfig(parsedArgs, currentConfig) {
  const configValue = currentConfig.dast && typeof currentConfig.dast === 'object' ? currentConfig.dast : null;
  const url = parsedArgs['dast-url'] || process.env.INPUT_DAST_URL || configValue?.url;
  if (!url) return null;

  const pathsInput = parsedArgs['dast-paths'] || process.env.INPUT_DAST_PATHS;
  const timeoutInput = parsedArgs['dast-timeout-ms'] || process.env.INPUT_DAST_TIMEOUT_MS;
  return {
    url,
    paths: pathsInput ? String(pathsInput).split(',').map((item) => item.trim()).filter(Boolean) : configValue?.paths,
    timeoutMs: timeoutInput ? Number(timeoutInput) : configValue?.timeoutMs
  };
}

function loadBaseline(file) {
  if (!file) return new Set();
  if (!fs.existsSync(file)) {
    fail(`Baseline file does not exist: ${file}`);
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    const baselineFindings = Array.isArray(parsed.findings) ? parsed.findings : [];
    return new Set(baselineFindings.map((finding) => finding.fingerprint || fingerprintFor(finding)).filter(Boolean));
  } catch (error) {
    fail(`Could not parse baseline file ${file}: ${error.message}`);
  }
}

function listFiles(root) {
  const result = [];
  walk(root);
  return result;

  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name)) walk(full);
        continue;
      }
      const ext = path.extname(entry.name);
      if (SOURCE_EXTENSIONS.has(ext) && !isExcluded(full)) result.push(full);
    }
  }
}

function isExcluded(file) {
  if (SCANNER_ARTIFACT_FILES.has(path.basename(file))) return true;
  if (scannerArtifactPaths.has(path.resolve(file))) return true;
  const rel = normalizePath(path.relative(targetRoot, file));
  return extraExclude.some((pattern) => {
    const clean = pattern.replace(/\/+$/, '');
    return rel === clean || rel.startsWith(`${clean}/`);
  });
}

function normalizePath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.?\//, '');
}

function scanFiles(files) {
  for (const file of files) {
    const rel = path.relative(targetRoot, file).replace(/\\/g, '/');
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split(/\r?\n/);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;

      if (/NEXT_PUBLIC_.*(SERVICE|SECRET|PRIVATE|ADMIN|PASSWORD)/i.test(line)) {
        addFinding('Critico', 'S4', 'Secrets', rel, lineNumber, 'Sensitive-looking NEXT_PUBLIC variable exposed to client bundle.', 'Move the value to a server-only environment variable.');
      }

      if (/SUPABASE_SERVICE_ROLE|service_role/i.test(line) && isClientPath(rel)) {
        addFinding('Critico', 'A1', 'Auth & Access', rel, lineNumber, 'Supabase service role reference appears in client-side code.', 'Use service role only in server routes or server actions.');
      }

      if (/dangerouslySetInnerHTML/.test(line)) {
        addFinding('Critico', 'I3', 'Injection', rel, lineNumber, 'React dangerouslySetInnerHTML can create XSS if content is user-controlled.', 'Render text normally or sanitize HTML with a reviewed sanitizer.');
      }

      if (shouldFlagInnerHtml(lines, index)) {
        addFinding('Alto', 'I2', 'Injection', rel, lineNumber, 'innerHTML assignment can create DOM XSS.', 'Use textContent or sanitize trusted HTML before inserting it.');
      }

      if (/\beval\s*\(|setTimeout\s*\([^,)]*(req|query|body|input|message)/.test(line)) {
        addFinding('Critico', 'I4', 'Injection', rel, lineNumber, 'External input appears to reach code execution.', 'Remove eval-like execution and validate input with a schema.');
      }

      if (/Access-Control-Allow-Origin['"]?\s*,?\s*value:\s*['"]\*/.test(line) || /origin\s*:\s*['"]\*/.test(line)) {
        addFinding('Alto', 'H4', 'Headers & CORS', rel, lineNumber, 'CORS allows every origin.', 'Use an explicit origin allowlist.');
      }

      if (/Access-Control-Allow-Credentials['"]?\s*,?\s*value:\s*['"]true/.test(line) || /credentials\s*:\s*true/.test(line)) {
        gates.push({
          id: 'H4',
          status: 'WARN',
          evidence: `${rel}:${lineNumber}`,
          note: 'Credentials are enabled; open CORS becomes critical if paired with wildcard origin.'
        });
      }

      if (/error\.stack|err\.stack/.test(line)) {
        addFinding('Alto', 'S7', 'Secrets', rel, lineNumber, 'Stack trace appears in client-visible error response.', 'Log internal details server-side and return a generic error.');
      }

      if (/\.eq\(['"]id['"],\s*params\.id\)/.test(line)) {
        const context = lines.slice(Math.max(0, index - 8), Math.min(lines.length, index + 8)).join('\n');
        if (!/user_id|owner|auth\.|getServerSession|getUser|session/.test(context)) {
          addFinding('Alto', 'A3', 'Auth & Access', rel, lineNumber, 'ID lookup does not show an ownership/auth check nearby.', 'Add ownership filtering such as user_id = authenticated user id.');
        }
      }
    });
  }
}

function scanPackageJson(packageJsonPath, hasPackageJson) {
  if (!hasPackageJson) {
    gates.push({ id: 'D1', status: 'N/A', evidence: 'No package.json', note: 'No Node dependency manifest detected.' });
    return;
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch (error) {
    addFinding('Alto', 'D1', 'Supply Chain', 'package.json', 1, 'package.json could not be parsed.', 'Fix package.json syntax.');
    return;
  }

  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[section] || {};
    for (const [name, version] of Object.entries(deps)) {
      if (version === 'latest' || version === '*' || /^>=/.test(version)) {
        addFinding('Medio', 'D4', 'Supply Chain', 'package.json', 1, `Dependency ${name} uses an unsafe loose version: ${version}.`, 'Pin to a reviewed version or compatible bounded range.');
      }
    }
  }
}

function scanLockfile(hasPackageJson) {
  if (!hasPackageJson) return;
  const lockfiles = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'];
  const found = lockfiles.some((file) => fs.existsSync(path.join(targetRoot, file)));
  if (!found) {
    addFinding('Medio', 'D1', 'Supply Chain', 'package.json', 1, 'No Node lockfile found.', 'Commit package-lock.json, pnpm-lock.yaml, or yarn.lock.');
  }
}

function addFinding(severity, checkId, vector, file, line, description, fix) {
  const rule = ruleFor(checkId);
  const finding = {
    severity,
    checkId,
    rule: {
      title: rule.title,
      owasp: rule.owasp,
      cwe: rule.cwe,
      helpUri: rule.helpUri
    },
    vector,
    file,
    line,
    description,
    impact: impactFor(severity),
    recommendation: fix
  };
  finding.fingerprint = fingerprintFor(finding);
  finding.baseline = baselineFingerprints.has(finding.fingerprint);

  const suppression = findSuppression(finding);
  if (suppression) {
    suppressed.push({
      ...finding,
      suppression: {
        reason: suppression.reason,
        expires: suppression.expires || null
      }
    });
    return;
  }

  findings.push(finding);
}

function findSuppression(finding) {
  for (const item of suppressions) {
    if (!item || typeof item !== 'object') continue;
    if (!item.reason || typeof item.reason !== 'string') continue;
    if (finding.severity === 'Critico' && !allowCriticalSuppressions) continue;
    if (isExpired(item.expires)) continue;
    if (item.checkId && item.checkId !== finding.checkId) continue;
    if (item.severity && item.severity !== finding.severity) continue;
    if (item.path && !normalizePath(finding.file).startsWith(normalizePath(item.path))) continue;
    return item;
  }
  return null;
}

function isExpired(value) {
  if (!value) return false;
  const expires = new Date(value);
  if (Number.isNaN(expires.getTime())) return true;
  return expires.getTime() < Date.now();
}

function addUnknown(checkId, area, whyUnknown, howToResolve, blocks) {
  const rule = ruleFor(checkId);
  unknown.push({
    checkId,
    rule: {
      title: rule.title,
      owasp: rule.owasp,
      cwe: rule.cwe,
      helpUri: rule.helpUri
    },
    area,
    whyUnknown,
    howToResolve,
    blocks
  });
}

function summarize(allFindings, allUnknown) {
  return {
    critical: allFindings.filter((f) => f.severity === 'Critico').length,
    high: allFindings.filter((f) => f.severity === 'Alto').length,
    medium: allFindings.filter((f) => f.severity === 'Medio').length,
    low: allFindings.filter((f) => f.severity === 'Baixo').length,
    unknown: allUnknown.length
  };
}

function fingerprintFor(finding) {
  if (!finding || !finding.checkId || !finding.file || !finding.description) return '';
  return [
    finding.checkId,
    normalizePath(finding.file),
    String(finding.description).trim().toLowerCase()
  ].join('|');
}

function calculateScore(summary) {
  let score = 10;
  score -= summary.critical * 3;
  score -= summary.high * 1.5;
  score -= summary.medium * 0.5;
  score -= summary.unknown * 0.4;
  if (summary.critical > 0) score = Math.min(score, 5);
  if (summary.high > 0) score = Math.min(score, 7);
  return Math.max(0, Number(score.toFixed(1)));
}

function calculateConfidence(summary) {
  if (summary.unknown > 4) return 'Baixa';
  if (summary.unknown > 1) return 'Media';
  return 'Alta';
}

function decideCertification(summary, score, confidence) {
  if (summary.critical > 0) return 'Bloqueado';
  if (confidence === 'Baixa') return 'Bloqueado';
  if (score < 6.1) return 'Bloqueado';
  if (summary.high > 0) return 'Bronze';
  if (score >= 8.5 && confidence === 'Alta' && summary.unknown === 0) return 'Ouro';
  if (score >= 7.5 && confidence !== 'Baixa') return 'Prata';
  return 'Bronze';
}

function printSummary(report) {
  console.log('Rock House CI');
  console.log(`Target: ${report.target}`);
  console.log(`Result: ${report.result}`);
  console.log(`Certification: ${report.certification}`);
  console.log(`Score: ${report.score}/10`);
  console.log(`Confidence: ${report.confidence}`);
  console.log(`Findings: C=${report.summary.critical} H=${report.summary.high} M=${report.summary.medium} L=${report.summary.low} UNKNOWN=${report.summary.unknown}`);
  console.log(`JSON: ${outputPath}`);
  if (sarifPath) console.log(`SARIF: ${sarifPath}`);
  if (markdownPath) console.log(`Markdown: ${markdownPath}`);
}

function writeGithubOutputs(report) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (!outputFile) return;
  const lines = [
    `result=${report.result}`,
    `certification=${report.certification}`,
    `score=${report.score}`,
    `confidence=${report.confidence}`,
    `critical=${report.summary.critical}`,
    `high=${report.summary.high}`,
    `unknown=${report.summary.unknown}`,
    `report=${outputPath}`,
    `sarif=${sarifPath}`,
    `markdown=${markdownPath}`
  ];
  fs.appendFileSync(outputFile, `${lines.join('\n')}\n`, 'utf8');
}

function writeGithubAnnotations(report) {
  if (!annotationsEnabled || !process.env.GITHUB_ACTIONS) return;
  for (const finding of report.findings) {
    const type = annotationType(finding.severity);
    const props = [
      `file=${escapeAnnotationProperty(finding.file)}`,
      `line=${Math.max(1, finding.line || 1)}`,
      `title=${escapeAnnotationProperty(`${finding.checkId} ${finding.rule?.title || finding.description}`)}`
    ].join(',');
    const message = `${finding.severity}: ${finding.description} Recommendation: ${finding.recommendation}`;
    console.log(`::${type} ${props}::${escapeAnnotationMessage(message)}`);
  }
}

function annotationType(severity) {
  if (severity === 'Critico' || severity === 'Alto') return 'error';
  if (severity === 'Medio') return 'warning';
  return 'notice';
}

function escapeAnnotationProperty(value) {
  return String(value ?? '')
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A')
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
}

function escapeAnnotationMessage(value) {
  return String(value ?? '')
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

function writeGithubStepSummary(markdown) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryFile) return;
  fs.appendFileSync(summaryFile, markdown, 'utf8');
}

function isClientPath(rel) {
  return /(^|\/)(app|pages|components|hooks)\//.test(rel) && !/\/api\//.test(rel) && !/server/.test(rel);
}

function fail(message) {
  console.error(`Rock House CI error: ${message}`);
  process.exit(2);
}
