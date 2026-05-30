const fs = require('fs');
const path = require('path');

function loadAssurance(file, fail) {
  if (!file) return null;
  if (!fs.existsSync(file)) {
    fail(`Assurance file does not exist: ${file}`);
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    validateAssurance(parsed, file, fail);
    return parsed;
  } catch (error) {
    if (error && error.code === 'ROCK_HOUSE_ASSURANCE') throw error;
    fail(`Could not parse assurance file ${file}: ${error.message}`);
  }
}

function validateAssurance(value, file, fail) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    failAssurance(`Assurance file must contain a JSON object: ${file}`, fail);
  }

  const sections = ['dynamicTesting', 'monitoring', 'review', 'approval'];
  for (const key of Object.keys(value)) {
    if (!sections.includes(key)) {
      failAssurance(`Unknown assurance key "${key}" in ${file}`, fail);
    }
  }

  validateBooleanSection(value.dynamicTesting, ['completed'], 'dynamicTesting', file, fail);
  validateBooleanSection(value.review, ['completed'], 'review', file, fail);
  validateBooleanSection(value.approval, ['humanApproved'], 'approval', file, fail);
  validateBooleanSection(value.monitoring, ['errorTracking', 'auditLogs', 'alerts', 'healthChecks'], 'monitoring', file, fail);

  validateOptionalString(value.dynamicTesting, 'environment', 'dynamicTesting', file, fail);
  validateOptionalString(value.review, 'reviewer', 'review', file, fail);
  validateOptionalString(value.approval, 'approver', 'approval', file, fail);
  validateOptionalDate(value.dynamicTesting, 'date', 'dynamicTesting', file, fail);
  validateOptionalDate(value.review, 'date', 'review', file, fail);
  validateOptionalDate(value.approval, 'date', 'approval', file, fail);
}

function validateBooleanSection(section, keys, name, file, fail) {
  if (section === undefined) return;
  if (!section || typeof section !== 'object' || Array.isArray(section)) {
    failAssurance(`Assurance section "${name}" must be an object in ${file}`, fail);
  }
  for (const key of keys) {
    if (section[key] !== undefined && typeof section[key] !== 'boolean') {
      failAssurance(`Assurance field "${name}.${key}" must be a boolean in ${file}`, fail);
    }
  }
}

function validateOptionalString(section, key, name, file, fail) {
  if (!section || section[key] === undefined) return;
  if (typeof section[key] !== 'string') {
    failAssurance(`Assurance field "${name}.${key}" must be a string in ${file}`, fail);
  }
}

function validateOptionalDate(section, key, name, file, fail) {
  if (!section || section[key] === undefined) return;
  if (typeof section[key] !== 'string' || Number.isNaN(new Date(section[key]).getTime())) {
    failAssurance(`Assurance field "${name}.${key}" must be a valid date string in ${file}`, fail);
  }
}

function failAssurance(message, fail) {
  const error = new Error(message);
  error.code = 'ROCK_HOUSE_ASSURANCE';
  fail(message);
}

function evaluateAssurance(options) {
  const {
    assurance,
    assuranceFile,
    riskProfile,
    dynamicTestingCompleted,
    dynamicTestingEvidence,
    monitoringCoverage,
    monitoringEvidence,
    addFinding,
    gates
  } = options;

  if (riskProfile !== 'high') return;

  const evidenceRef = assuranceFile ? path.basename(assuranceFile) : 'rock-house.config.json';
  if (!assurance) {
    addFinding(
      'Critico',
      'R0',
      'Assurance',
      evidenceRef,
      1,
      'High-risk project has no assurance evidence bundle for dynamic testing, monitoring, review, and approval.',
      'Provide an assurance JSON and configure it with "assurance" in rock-house.config.json.'
    );
    gates.push({
      id: 'R0',
      status: 'FAIL',
      evidence: evidenceRef,
      note: 'High-risk certification requires an assurance evidence bundle.'
    });
    return;
  }

  evaluateBooleanRequirement(assurance.dynamicTesting?.completed === true || dynamicTestingCompleted === true, {
    checkId: 'R1',
    file: evidenceRef,
    description: 'High-risk project is missing evidence of dynamic security testing.',
    recommendation: 'Attach DAST or pentest evidence in the assurance bundle before deploy.',
    passNote: dynamicTestingEvidence || `Dynamic testing evidence present${assurance.dynamicTesting?.environment ? ` (${assurance.dynamicTesting.environment})` : ''}.`,
    addFinding,
    gates
  });

  evaluateBooleanRequirement(hasMonitoringCoverage(assurance.monitoring) || hasMonitoringCoverage(monitoringCoverage), {
    checkId: 'R2',
    file: evidenceRef,
    description: 'High-risk project is missing runtime monitoring evidence (error tracking, audit logs, alerts, or health checks).',
    recommendation: 'Provide monitoring evidence showing error tracking, audit logs, alerts, and health checks.',
    passNote: monitoringEvidence || 'Runtime monitoring evidence present.',
    addFinding,
    gates
  });

  evaluateBooleanRequirement(assurance.review?.completed, {
    checkId: 'R3',
    file: evidenceRef,
    description: 'High-risk project is missing specialized security review evidence.',
    recommendation: 'Attach a completed security review with reviewer and date in the assurance bundle.',
    passNote: `Security review evidence present${assurance.review?.reviewer ? ` (${assurance.review.reviewer})` : ''}.`,
    addFinding,
    gates
  });

  evaluateBooleanRequirement(assurance.approval?.humanApproved, {
    checkId: 'R4',
    file: evidenceRef,
    description: 'High-risk project is missing human approval evidence for deploy.',
    recommendation: 'Attach explicit human approval evidence in the assurance bundle before deploy.',
    passNote: `Human approval evidence present${assurance.approval?.approver ? ` (${assurance.approval.approver})` : ''}.`,
    addFinding,
    gates
  });
}

function evaluateBooleanRequirement(value, options) {
  const {
    checkId,
    file,
    description,
    recommendation,
    passNote,
    addFinding,
    gates
  } = options;

  if (value === true) {
    gates.push({
      id: checkId,
      status: 'PASS',
      evidence: file,
      note: passNote
    });
    return;
  }

  addFinding('Critico', checkId, 'Assurance', file, 1, description, recommendation);
  gates.push({
    id: checkId,
    status: 'FAIL',
    evidence: file,
    note: description
  });
}

function hasMonitoringCoverage(monitoring) {
  if (!monitoring) return false;
  return monitoring.errorTracking === true
    && monitoring.auditLogs === true
    && monitoring.alerts === true
    && monitoring.healthChecks === true;
}

module.exports = {
  evaluateAssurance,
  loadAssurance
};
