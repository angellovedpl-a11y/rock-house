const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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

  const sections = ['dynamicTesting', 'monitoring', 'review', 'approval', 'integrity', 'signature'];
  for (const key of Object.keys(value)) {
    if (!sections.includes(key)) {
      failAssurance(`Unknown assurance key "${key}" in ${file}`, fail);
    }
  }

  validateBooleanSection(value.dynamicTesting, ['completed'], 'dynamicTesting', file, fail);
  validateBooleanSection(value.review, ['completed'], 'review', file, fail);
  validateApproval(value.approval, file, fail);
  validateIntegrity(value.integrity, file, fail);
  validateSignature(value.signature, file, fail);
  validateBooleanSection(value.monitoring, ['errorTracking', 'auditLogs', 'alerts', 'healthChecks'], 'monitoring', file, fail);

  validateOptionalString(value.dynamicTesting, 'environment', 'dynamicTesting', file, fail);
  validateOptionalString(value.review, 'reviewer', 'review', file, fail);
  validateOptionalDate(value.dynamicTesting, 'date', 'dynamicTesting', file, fail);
  validateOptionalDate(value.review, 'date', 'review', file, fail);
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

function validateApproval(section, file, fail) {
  if (section === undefined) return;
  if (!section || typeof section !== 'object' || Array.isArray(section)) {
    failAssurance(`Assurance section "approval" must be an object in ${file}`, fail);
  }

  if ('humanApproved' in section) {
    validateBooleanSection(section, ['humanApproved'], 'approval', file, fail);
    validateOptionalString(section, 'approver', 'approval', file, fail);
    validateOptionalDate(section, 'date', 'approval', file, fail);
    return;
  }

  const allowed = new Set(['schemaVersion', 'status', 'approver', 'date', 'environment', 'scope', 'reference', 'expires']);
  for (const key of Object.keys(section)) {
    if (!allowed.has(key)) {
      failAssurance(`Unknown approval field "${key}" in ${file}`, fail);
    }
  }

  if (section.schemaVersion !== 1) {
    failAssurance(`Assurance field "approval.schemaVersion" must be 1 in ${file}`, fail);
  }

  if (section.status !== 'approved') {
    failAssurance(`Assurance field "approval.status" must be "approved" in ${file}`, fail);
  }

  for (const key of ['approver', 'environment', 'scope', 'reference']) {
    if (!section[key] || typeof section[key] !== 'string') {
      failAssurance(`Assurance field "approval.${key}" must be a non-empty string in ${file}`, fail);
    }
  }

  if (!section.date || typeof section.date !== 'string' || Number.isNaN(new Date(section.date).getTime())) {
    failAssurance(`Assurance field "approval.date" must be a valid date string in ${file}`, fail);
  }

  if (section.expires !== undefined && (typeof section.expires !== 'string' || Number.isNaN(new Date(section.expires).getTime()))) {
    failAssurance(`Assurance field "approval.expires" must be a valid date string in ${file}`, fail);
  }
}

function validateIntegrity(section, file, fail) {
  if (section === undefined) return;
  if (!section || typeof section !== 'object' || Array.isArray(section)) {
    failAssurance(`Assurance section "integrity" must be an object in ${file}`, fail);
  }

  const allowed = new Set(['schemaVersion', 'algorithm', 'digest']);
  for (const key of Object.keys(section)) {
    if (!allowed.has(key)) {
      failAssurance(`Unknown integrity field "${key}" in ${file}`, fail);
    }
  }

  if (section.schemaVersion !== 1) {
    failAssurance(`Assurance field "integrity.schemaVersion" must be 1 in ${file}`, fail);
  }

  if (section.algorithm !== 'sha256') {
    failAssurance(`Assurance field "integrity.algorithm" must be "sha256" in ${file}`, fail);
  }

  if (!/^[a-f0-9]{64}$/i.test(String(section.digest || ''))) {
    failAssurance(`Assurance field "integrity.digest" must be a 64-character sha256 hex string in ${file}`, fail);
  }
}

function validateSignature(section, file, fail) {
  if (section === undefined) return;
  if (!section || typeof section !== 'object' || Array.isArray(section)) {
    failAssurance(`Assurance section "signature" must be an object in ${file}`, fail);
  }

  const allowed = new Set(['schemaVersion', 'algorithm', 'keyId', 'signature']);
  for (const key of Object.keys(section)) {
    if (!allowed.has(key)) {
      failAssurance(`Unknown signature field "${key}" in ${file}`, fail);
    }
  }

  if (section.schemaVersion !== 1) {
    failAssurance(`Assurance field "signature.schemaVersion" must be 1 in ${file}`, fail);
  }

  if (section.algorithm !== 'ed25519') {
    failAssurance(`Assurance field "signature.algorithm" must be "ed25519" in ${file}`, fail);
  }

  if (!section.keyId || typeof section.keyId !== 'string') {
    failAssurance(`Assurance field "signature.keyId" must be a non-empty string in ${file}`, fail);
  }

  if (!section.signature || typeof section.signature !== 'string') {
    failAssurance(`Assurance field "signature.signature" must be a non-empty base64 string in ${file}`, fail);
  }
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
    assuranceTrust,
    assurancePolicy,
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

  evaluateBooleanRequirement(isApprovalAccepted(assurance.approval), {
    checkId: 'R4',
    file: evidenceRef,
    description: 'High-risk project is missing human approval evidence for deploy.',
    recommendation: 'Attach explicit human approval evidence with approver, date, environment, scope, reference, and validity in the assurance bundle before deploy.',
    passNote: approvalPassNote(assurance.approval),
    addFinding,
    gates
  });

  evaluateBooleanRequirement(hasValidIntegrity(assurance), {
    checkId: 'R5',
    file: evidenceRef,
    description: 'High-risk project is missing a valid assurance integrity digest.',
    recommendation: 'Generate a sha256 integrity digest for the assurance bundle and keep it updated after approved changes.',
    passNote: 'Assurance integrity digest is valid.',
    addFinding,
    gates
  });

  evaluateBooleanRequirement(hasValidSignature(assurance, assuranceTrust), {
    checkId: 'R6',
    file: evidenceRef,
    description: 'High-risk project is missing a valid assurance signature trusted by Rock House.',
    recommendation: 'Sign the assurance bundle with a trusted private key and configure the matching public key in assuranceTrust.',
    passNote: signaturePassNote(assurance.signature),
    addFinding,
    gates
  });

  evaluateAssurancePolicy({
    approval: assurance.approval,
    assurancePolicy,
    file: evidenceRef,
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

function isApprovalAccepted(approval) {
  if (!approval || typeof approval !== 'object') return false;
  if ('humanApproved' in approval) return approval.humanApproved === true;
  if (approval.schemaVersion !== 1) return false;
  if (approval.status !== 'approved') return false;
  if (approval.expires && new Date(approval.expires).getTime() < Date.now()) return false;
  return true;
}

function approvalPassNote(approval) {
  if (!approval || typeof approval !== 'object') return 'Human approval evidence present.';
  if ('humanApproved' in approval) {
    return `Human approval evidence present${approval.approver ? ` (${approval.approver})` : ''}.`;
  }
  const details = [
    approval.approver,
    approval.environment,
    approval.scope,
    approval.reference
  ].filter(Boolean).join(', ');
  return `Human approval evidence present${details ? ` (${details})` : ''}.`;
}

function hasValidIntegrity(assurance) {
  if (!assurance || typeof assurance !== 'object') return false;
  if (!assurance.integrity || typeof assurance.integrity !== 'object') return false;
  return computeAssuranceDigest(assurance) === assurance.integrity.digest;
}

function computeAssuranceDigest(assurance) {
  const canonical = canonicalize(removeSignature(removeIntegrity(assurance)));
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function signablePayload(assurance) {
  return canonicalize(removeSignature(assurance));
}

function removeIntegrity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const clone = {};
  for (const key of Object.keys(value)) {
    if (key === 'integrity') continue;
    clone[key] = value[key];
  }
  return clone;
}

function removeSignature(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const clone = {};
  for (const key of Object.keys(value)) {
    if (key === 'signature') continue;
    clone[key] = value[key];
  }
  return clone;
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hasValidSignature(assurance, assuranceTrust) {
  if (!assurance || typeof assurance !== 'object') return false;
  if (!assurance.signature || typeof assurance.signature !== 'object') return false;
  if (!assuranceTrust || !Array.isArray(assuranceTrust.publicKeys) || assuranceTrust.publicKeys.length === 0) return false;
  const entry = assuranceTrust.publicKeys.find((item) => item.keyId === assurance.signature.keyId);
  if (!entry || !entry.path || !fs.existsSync(entry.path)) return false;
  try {
    const publicKey = fs.readFileSync(entry.path, 'utf8');
    return crypto.verify(
      null,
      Buffer.from(signablePayload(assurance), 'utf8'),
      publicKey,
      Buffer.from(String(assurance.signature.signature), 'base64')
    );
  } catch {
    return false;
  }
}

function signaturePassNote(signature) {
  if (!signature || typeof signature !== 'object') return 'Assurance signature is valid.';
  return `Assurance signature is valid (${signature.keyId}).`;
}

function evaluateAssurancePolicy(options) {
  const {
    approval,
    assurancePolicy,
    file,
    addFinding,
    gates
  } = options;
  if (!assurancePolicy || !approval || typeof approval !== 'object' || 'humanApproved' in approval) return;

  if (assurancePolicy.requiredEnvironment) {
    evaluateBooleanRequirement(
      String(approval.environment || '').toLowerCase() === String(assurancePolicy.requiredEnvironment).toLowerCase(),
      {
        checkId: 'R7',
        file,
        description: `Approval environment does not match required environment "${assurancePolicy.requiredEnvironment}".`,
        recommendation: 'Issue a new approval for the intended environment or update assurancePolicy to match the deploy target.',
        passNote: `Approval environment matches policy (${approval.environment}).`,
        addFinding,
        gates
      }
    );
  }

  if (assurancePolicy.referencePattern) {
    const pattern = new RegExp(assurancePolicy.referencePattern);
    evaluateBooleanRequirement(
      pattern.test(String(approval.reference || '')),
      {
        checkId: 'R8',
        file,
        description: 'Approval reference does not match the required assurance policy pattern.',
        recommendation: 'Use a change or release reference that matches assurancePolicy.referencePattern.',
        passNote: `Approval reference matches policy (${approval.reference}).`,
        addFinding,
        gates
      }
    );
  }

  if (assurancePolicy.requireExpires === true || assurancePolicy.maxApprovalAgeDays || assurancePolicy.maxExpiryDays) {
    evaluateBooleanRequirement(
      approvalValidityPasses(approval, assurancePolicy),
      {
        checkId: 'R9',
        file,
        description: 'Approval validity does not satisfy assurance policy requirements.',
        recommendation: 'Refresh the approval date/expiry or relax assurancePolicy only if that matches the actual release process.',
        passNote: approvalValidityNote(approval, assurancePolicy),
        addFinding,
        gates
      }
    );
  }
}

function approvalValidityPasses(approval, assurancePolicy) {
  const now = Date.now();
  const approvedAt = new Date(approval.date).getTime();
  if (Number.isNaN(approvedAt)) return false;
  if (assurancePolicy.requireExpires === true && !approval.expires) return false;
  if (assurancePolicy.maxApprovalAgeDays) {
    const maxAgeMs = assurancePolicy.maxApprovalAgeDays * 24 * 60 * 60 * 1000;
    if ((now - approvedAt) > maxAgeMs) return false;
  }
  if (assurancePolicy.maxExpiryDays && approval.expires) {
    const expiresAt = new Date(approval.expires).getTime();
    if (Number.isNaN(expiresAt)) return false;
    const maxExpiryMs = assurancePolicy.maxExpiryDays * 24 * 60 * 60 * 1000;
    if ((expiresAt - approvedAt) > maxExpiryMs) return false;
  }
  return true;
}

function approvalValidityNote(approval, assurancePolicy) {
  const parts = [`approved=${approval.date}`];
  if (approval.expires) parts.push(`expires=${approval.expires}`);
  if (assurancePolicy.maxApprovalAgeDays) parts.push(`maxAgeDays=${assurancePolicy.maxApprovalAgeDays}`);
  if (assurancePolicy.maxExpiryDays) parts.push(`maxExpiryDays=${assurancePolicy.maxExpiryDays}`);
  return `Approval validity matches policy (${parts.join(', ')}).`;
}

module.exports = {
  computeAssuranceDigest,
  evaluateAssurance,
  hasValidSignature,
  loadAssurance,
  signablePayload
};
