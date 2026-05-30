const fs = require('fs');
const path = require('path');

const CONFIG_KEYS = new Set([
  'path',
  'minLevel',
  'output',
  'sarif',
  'markdown',
  'riskProfile',
  'assurance',
  'dast',
  'observability',
  'exclude',
  'allowCriticalSuppressions',
  'suppressions',
  'baseline',
  'failOnNewOnly',
  'annotations'
]);

const LEVEL_RANK = {
  bloqueado: 0,
  bronze: 1,
  prata: 2,
  ouro: 3
};

const SEVERITIES = new Set(['Critico', 'Alto', 'Medio', 'Baixo']);
const RISK_PROFILES = new Set(['standard', 'high']);

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      parsed[key] = true;
    } else {
      parsed[key] = next;
      i += 1;
    }
  }
  return parsed;
}

function readBoolean(cliValue, envValue, configValue, defaultValue) {
  if (cliValue !== undefined) return cliValue === true || String(cliValue).toLowerCase() === 'true';
  if (envValue !== undefined && envValue !== '') return String(envValue).toLowerCase() === 'true';
  if (configValue !== undefined) return configValue === true;
  return defaultValue === true;
}

function resolveConfigPath(input) {
  if (input) return path.resolve(input);
  const defaultPath = path.resolve(process.cwd(), 'rock-house.config.json');
  return fs.existsSync(defaultPath) ? defaultPath : '';
}

function loadConfig(file) {
  if (!file) return {};
  if (!fs.existsSync(file)) {
    throwUsageError(`Config file does not exist: ${file}`);
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throwUsageError(`Config file must contain a JSON object: ${file}`);
    }
    validateConfig(parsed, file);
    return parsed;
  } catch (error) {
    if (error && error.code === 'ROCK_HOUSE_USAGE') throw error;
    throwUsageError(`Could not parse config file ${file}: ${error.message}`);
  }
}

function validateConfig(configValue, file) {
  for (const key of Object.keys(configValue)) {
    if (!CONFIG_KEYS.has(key)) {
      throwUsageError(`Unknown config key "${key}" in ${file}`);
    }
  }

  for (const key of ['path', 'minLevel', 'output', 'sarif', 'markdown', 'assurance']) {
    if (configValue[key] !== undefined && typeof configValue[key] !== 'string') {
      throwUsageError(`Config key "${key}" must be a string in ${file}`);
    }
  }

  if (configValue.minLevel && !LEVEL_RANK[configValue.minLevel.toLowerCase()]) {
    throwUsageError(`Config key "minLevel" must be bronze, prata, or ouro in ${file}`);
  }

  if (configValue.riskProfile !== undefined) {
    if (typeof configValue.riskProfile !== 'string' || !RISK_PROFILES.has(configValue.riskProfile.toLowerCase())) {
      throwUsageError(`Config key "riskProfile" must be standard or high in ${file}`);
    }
  }

  if (configValue.dast !== undefined) {
    validateDast(configValue.dast, file);
  }

  if (configValue.observability !== undefined) {
    validateObservability(configValue.observability, file);
  }

  if (configValue.exclude !== undefined) {
    validateStringArray(configValue.exclude, 'exclude', file);
  }

  if (configValue.allowCriticalSuppressions !== undefined && typeof configValue.allowCriticalSuppressions !== 'boolean') {
    throwUsageError(`Config key "allowCriticalSuppressions" must be a boolean in ${file}`);
  }

  if (configValue.failOnNewOnly !== undefined && typeof configValue.failOnNewOnly !== 'boolean') {
    throwUsageError(`Config key "failOnNewOnly" must be a boolean in ${file}`);
  }

  if (configValue.annotations !== undefined && typeof configValue.annotations !== 'boolean') {
    throwUsageError(`Config key "annotations" must be a boolean in ${file}`);
  }

  if (configValue.baseline !== undefined && typeof configValue.baseline !== 'string') {
    throwUsageError(`Config key "baseline" must be a string in ${file}`);
  }

  if (configValue.suppressions !== undefined) {
    if (!Array.isArray(configValue.suppressions)) {
      throwUsageError(`Config key "suppressions" must be an array in ${file}`);
    }
    configValue.suppressions.forEach((item, index) => validateSuppression(item, index, file));
  }
}

function validateStringArray(value, key, file) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throwUsageError(`Config key "${key}" must be an array of strings in ${file}`);
  }
}

function validateSuppression(item, index, file) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    throwUsageError(`Suppression at index ${index} must be an object in ${file}`);
  }

  const allowed = new Set(['checkId', 'path', 'severity', 'reason', 'expires']);
  for (const key of Object.keys(item)) {
    if (!allowed.has(key)) {
      throwUsageError(`Unknown suppression key "${key}" at index ${index} in ${file}`);
    }
  }

  if (!item.reason || typeof item.reason !== 'string') {
    throwUsageError(`Suppression at index ${index} must include a non-empty string reason in ${file}`);
  }

  for (const key of ['checkId', 'path', 'severity', 'expires']) {
    if (item[key] !== undefined && typeof item[key] !== 'string') {
      throwUsageError(`Suppression key "${key}" at index ${index} must be a string in ${file}`);
    }
  }

  if (item.severity && !SEVERITIES.has(item.severity)) {
    throwUsageError(`Suppression severity at index ${index} must be Critico, Alto, Medio, or Baixo in ${file}`);
  }

  if (item.expires && Number.isNaN(new Date(item.expires).getTime())) {
    throwUsageError(`Suppression expires at index ${index} must be a valid date in ${file}`);
  }
}

function validateDast(value, file) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throwUsageError(`Config key "dast" must be an object in ${file}`);
  }

  const allowed = new Set(['url', 'paths', 'timeoutMs', 'authProtectedPaths', 'errorPaths', 'redirectParamNames']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throwUsageError(`Unknown dast key "${key}" in ${file}`);
    }
  }

  if (!value.url || typeof value.url !== 'string') {
    throwUsageError(`Config key "dast.url" must be a non-empty string in ${file}`);
  }

  if (value.paths !== undefined) {
    validateStringArray(value.paths, 'dast.paths', file);
  }

  if (value.authProtectedPaths !== undefined) {
    validateStringArray(value.authProtectedPaths, 'dast.authProtectedPaths', file);
  }

  if (value.errorPaths !== undefined) {
    validateStringArray(value.errorPaths, 'dast.errorPaths', file);
  }

  if (value.redirectParamNames !== undefined) {
    validateStringArray(value.redirectParamNames, 'dast.redirectParamNames', file);
  }

  if (value.timeoutMs !== undefined) {
    if (typeof value.timeoutMs !== 'number' || !Number.isFinite(value.timeoutMs) || value.timeoutMs <= 0) {
      throwUsageError(`Config key "dast.timeoutMs" must be a positive number in ${file}`);
    }
  }
}

function validateObservability(value, file) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throwUsageError(`Config key "observability" must be an object in ${file}`);
  }

  const allowed = new Set(['evidence']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throwUsageError(`Unknown observability key "${key}" in ${file}`);
    }
  }

  if (!value.evidence || typeof value.evidence !== 'string') {
    throwUsageError(`Config key "observability.evidence" must be a non-empty string in ${file}`);
  }
}

function throwUsageError(message) {
  console.error(`Rock House CI error: ${message}`);
  process.exit(2);
}

module.exports = {
  LEVEL_RANK,
  loadConfig,
  parseArgs,
  RISK_PROFILES,
  readBoolean,
  resolveConfigPath
};
