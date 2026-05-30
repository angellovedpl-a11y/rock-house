const fs = require('fs');
const path = require('path');

const ERROR_TRACKING_PACKAGES = {
  sentry: ['@sentry/nextjs', '@sentry/node', '@sentry/react', '@sentry/browser'],
  datadog: ['dd-trace', 'datadog-lambda-js', '@datadog/browser-logs', '@datadog/browser-rum'],
  opentelemetry: ['@opentelemetry/api', '@opentelemetry/sdk-node', '@vercel/otel']
};

const ERROR_TRACKING_PATTERNS = [
  { provider: 'sentry', pattern: /\bSentry\.init\s*\(/ },
  { provider: 'datadog', pattern: /\bdd-trace\b|DD_LOGS|datadog/i },
  { provider: 'opentelemetry', pattern: /@opentelemetry|registerOTel|instrumentation/i }
];

const HEALTH_PATH_PATTERNS = [
  /(^|\/)(health|healthz|ready|readyz|live|livez|status)(\/|\.|$)/i,
  /\/api\/health/i
];

function resolveObservabilityConfig(args, config) {
  const configValue = config.observability && typeof config.observability === 'object' ? config.observability : null;
  const evidence = args['observability-evidence'] || process.env.INPUT_OBSERVABILITY_EVIDENCE || configValue?.evidence;
  if (!evidence) return null;
  return {
    evidence: path.resolve(evidence)
  };
}

function evaluateObservability(options) {
  const {
    targetRoot,
    files,
    packageJsonPath,
    observability,
    fail
  } = options;

  const evidencePath = observability?.evidence || '';
  const evidence = loadEvidence(evidencePath, fail);
  const providers = detectProviders(files, packageJsonPath);
  const coverage = {
    errorTracking: providers.length > 0 || evidence.errorTracking === true,
    auditLogs: evidence.auditLogs === true,
    alerts: evidence.alerts === true,
    healthChecks: detectHealthChecks(files) || evidence.healthChecks === true
  };

  return {
    configured: Boolean(observability),
    evidenceFile: evidencePath || null,
    providers,
    coverage,
    note: summarizeObservability(coverage, providers, evidencePath ? path.basename(evidencePath) : '')
  };
}

function loadEvidence(file, fail) {
  if (!file) return {};
  if (!fs.existsSync(file)) {
    fail(`Observability evidence file does not exist: ${file}`);
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    validateEvidence(parsed, file, fail);
    return parsed;
  } catch (error) {
    if (error && error.code === 'ROCK_HOUSE_OBSERVABILITY') throw error;
    fail(`Could not parse observability evidence file ${file}: ${error.message}`);
  }
}

function validateEvidence(value, file, fail) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    failObservability(`Observability evidence file must contain a JSON object: ${file}`, fail);
  }
  const allowed = new Set(['errorTracking', 'auditLogs', 'alerts', 'healthChecks']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      failObservability(`Unknown observability evidence key "${key}" in ${file}`, fail);
    }
    if (typeof value[key] !== 'boolean') {
      failObservability(`Observability evidence field "${key}" must be boolean in ${file}`, fail);
    }
  }
}

function failObservability(message, fail) {
  const error = new Error(message);
  error.code = 'ROCK_HOUSE_OBSERVABILITY';
  fail(message);
}

function detectProviders(files, packageJsonPath) {
  const providers = new Set();
  const pkgDeps = readDependencies(packageJsonPath);
  for (const [provider, packages] of Object.entries(ERROR_TRACKING_PACKAGES)) {
    if (packages.some((name) => pkgDeps.has(name))) providers.add(provider);
  }

  for (const file of files) {
    const rel = normalizePath(file);
    if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(rel)) continue;
    if (!/sentry|instrumentation|telemetry|monitor|observability|logging|tracing|datadog/i.test(rel)) continue;
    const content = fs.readFileSync(file, 'utf8');
    for (const check of ERROR_TRACKING_PATTERNS) {
      if (check.pattern.test(content)) providers.add(check.provider);
    }
  }

  return Array.from(providers.values()).sort();
}

function readDependencies(packageJsonPath) {
  if (!packageJsonPath || !fs.existsSync(packageJsonPath)) return new Set();
  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    return new Set([
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.devDependencies || {}),
      ...Object.keys(pkg.optionalDependencies || {})
    ]);
  } catch {
    return new Set();
  }
}

function detectHealthChecks(files) {
  return files.some((file) => {
    const rel = normalizePath(file);
    return HEALTH_PATH_PATTERNS.some((pattern) => pattern.test(rel));
  });
}

function summarizeObservability(coverage, providers, evidenceName) {
  const coverageBits = Object.entries(coverage)
    .filter(([, value]) => value === true)
    .map(([key]) => key)
    .join(', ');
  const providerBits = providers.length ? `providers=${providers.join('+')}` : 'providers=none';
  const evidenceBits = evidenceName ? `evidence=${evidenceName}` : 'evidence=none';
  return `${providerBits}; ${evidenceBits}; coverage=${coverageBits || 'none'}`;
}

function normalizePath(value) {
  return String(value || '').replace(/\\/g, '/');
}

module.exports = {
  evaluateObservability,
  resolveObservabilityConfig
};
