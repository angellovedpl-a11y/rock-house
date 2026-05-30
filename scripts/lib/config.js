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
  'assuranceTrust',
  'assurancePolicy',
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

  if (configValue.assuranceTrust !== undefined) {
    validateAssuranceTrust(configValue.assuranceTrust, file);
  }

  if (configValue.assurancePolicy !== undefined) {
    validateAssurancePolicy(configValue.assurancePolicy, file);
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

function validateAssuranceTrust(value, file) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throwUsageError(`Config key "assuranceTrust" must be an object in ${file}`);
  }

  const allowed = new Set(['publicKeys']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throwUsageError(`Unknown assuranceTrust key "${key}" in ${file}`);
    }
  }

  if (!Array.isArray(value.publicKeys) || value.publicKeys.length === 0) {
    throwUsageError(`Config key "assuranceTrust.publicKeys" must be a non-empty array in ${file}`);
  }

  value.publicKeys.forEach((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throwUsageError(`assuranceTrust.publicKeys[${index}] must be an object in ${file}`);
    }
    const entryAllowed = new Set(['keyId', 'path']);
    for (const key of Object.keys(entry)) {
      if (!entryAllowed.has(key)) {
        throwUsageError(`Unknown assuranceTrust.publicKeys[${index}] key "${key}" in ${file}`);
      }
    }
    if (!entry.keyId || typeof entry.keyId !== 'string') {
      throwUsageError(`assuranceTrust.publicKeys[${index}].keyId must be a non-empty string in ${file}`);
    }
    if (!entry.path || typeof entry.path !== 'string') {
      throwUsageError(`assuranceTrust.publicKeys[${index}].path must be a non-empty string in ${file}`);
    }
  });
}

function validateAssurancePolicy(value, file) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throwUsageError(`Config key "assurancePolicy" must be an object in ${file}`);
  }

  const allowed = new Set(['requiredEnvironment', 'referencePattern', 'maxApprovalAgeDays', 'requireExpires', 'maxExpiryDays']);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throwUsageError(`Unknown assurancePolicy key "${key}" in ${file}`);
    }
  }

  if (value.requiredEnvironment !== undefined && typeof value.requiredEnvironment !== 'string') {
    throwUsageError(`Config key "assurancePolicy.requiredEnvironment" must be a string in ${file}`);
  }

  if (value.referencePattern !== undefined) {
    if (typeof value.referencePattern !== 'string') {
      throwUsageError(`Config key "assurancePolicy.referencePattern" must be a string in ${file}`);
    }
    try {
      new RegExp(value.referencePattern);
    } catch (error) {
      throwUsageError(`Config key "assurancePolicy.referencePattern" must be a valid regular expression in ${file}: ${error.message}`);
    }
  }

  for (const key of ['maxApprovalAgeDays', 'maxExpiryDays']) {
    if (value[key] !== undefined && (!Number.isFinite(value[key]) || value[key] <= 0)) {
      throwUsageError(`Config key "assurancePolicy.${key}" must be a positive number in ${file}`);
    }
  }

  if (value.requireExpires !== undefined && typeof value.requireExpires !== 'boolean') {
    throwUsageError(`Config key "assurancePolicy.requireExpires" must be a boolean in ${file}`);
  }
}

function throwUsageError(message) {
  console.error(`Rock House CI error: ${message}`);
  process.exit(2);
}

function resolveDastConfig(parsedArgs, currentConfig) {
  const configValue = currentConfig.dast && typeof currentConfig.dast === 'object' ? currentConfig.dast : null;
  const url = parsedArgs['dast-url'] || process.env.INPUT_DAST_URL || configValue?.url;
  if (!url) return null;

  const pathsInput = parsedArgs['dast-paths'] || process.env.INPUT_DAST_PATHS;
  const authPathsInput = parsedArgs['dast-auth-paths'] || process.env.INPUT_DAST_AUTH_PATHS;
  const errorPathsInput = parsedArgs['dast-error-paths'] || process.env.INPUT_DAST_ERROR_PATHS;
  const redirectParamsInput = parsedArgs['dast-redirect-params'] || process.env.INPUT_DAST_REDIRECT_PARAMS;
  const timeoutInput = parsedArgs['dast-timeout-ms'] || process.env.INPUT_DAST_TIMEOUT_MS;
  return {
    url,
    paths: pathsInput ? String(pathsInput).split(',').map((item) => item.trim()).filter(Boolean) : configValue?.paths,
    authProtectedPaths: authPathsInput ? String(authPathsInput).split(',').map((item) => item.trim()).filter(Boolean) : configValue?.authProtectedPaths,
    errorPaths: errorPathsInput ? String(errorPathsInput).split(',').map((item) => item.trim()).filter(Boolean) : configValue?.errorPaths,
    redirectParamNames: redirectParamsInput ? String(redirectParamsInput).split(',').map((item) => item.trim()).filter(Boolean) : configValue?.redirectParamNames,
    timeoutMs: timeoutInput ? Number(timeoutInput) : configValue?.timeoutMs
  };
}

function resolveAssuranceTrust(parsedArgs, currentConfig, fail) {
  const configValue = currentConfig.assuranceTrust && typeof currentConfig.assuranceTrust === 'object'
    ? currentConfig.assuranceTrust
    : { publicKeys: [] };
  const cliPublicKey = parsedArgs['assurance-public-key'] || process.env.INPUT_ASSURANCE_PUBLIC_KEY;
  const cliKeyId = parsedArgs['assurance-key-id'] || process.env.INPUT_ASSURANCE_KEY_ID;
  if (cliPublicKey || cliKeyId) {
    if (!cliPublicKey || !cliKeyId) {
      fail('Both assurance-public-key and assurance-key-id are required together.');
    }
    return {
      publicKeys: [
        {
          keyId: String(cliKeyId),
          path: path.resolve(String(cliPublicKey))
        }
      ]
    };
  }

  return {
    publicKeys: Array.isArray(configValue.publicKeys)
      ? configValue.publicKeys.map((entry) => ({
        keyId: entry.keyId,
        path: path.resolve(entry.path)
      }))
      : []
  };
}

module.exports = {
  LEVEL_RANK,
  loadConfig,
  parseArgs,
  RISK_PROFILES,
  readBoolean,
  validateAssurancePolicy,
  resolveAssuranceTrust,
  resolveDastConfig,
  resolveConfigPath
};
