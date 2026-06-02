// Dotted-name prefixes whose values are untrusted (Flask request surface).
const SOURCE_PREFIXES = [
  'request.args', 'request.form', 'request.values', 'request.json',
  'request.data', 'request.files', 'request.cookies', 'request.headers',
  'request.get_json'
];

// Sink callee (dotted) -> { id, severity, class }. Matched by callee suffix.
const SINKS = [
  { match: ['cursor.execute', 'cursor.executemany', '.execute', '.executemany'], id: 'TAINT-SQLI', severity: 'Critico', cls: 'SQL injection' },
  { match: ['render_template_string'], id: 'TAINT-SSTI', severity: 'Critico', cls: 'Server-side template injection' },
  { match: ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output'], id: 'TAINT-RCE', severity: 'Critico', cls: 'Command injection' },
  { match: ['eval', 'exec'], id: 'TAINT-RCE', severity: 'Critico', cls: 'Code execution' },
  { match: ['pickle.loads', 'pickle.load'], id: 'TAINT-DESERIALIZE', severity: 'Alto', cls: 'Unsafe deserialization' },
  { match: ['yaml.load'], id: 'TAINT-DESERIALIZE', severity: 'Alto', cls: 'Unsafe deserialization' },
  { match: ['open', 'send_file', 'send_from_directory'], id: 'TAINT-PATH', severity: 'Alto', cls: 'Path traversal' },
  { match: ['redirect'], id: 'TAINT-REDIRECT', severity: 'Alto', cls: 'Open redirect' }
];

// Function names (last segment) that neutralize taint on their argument/result.
const SANITIZERS = new Set([
  'int', 'float', 'escape', 'secure_filename', 'clean', 'quote', 'bleach'
]);

function isSourceExpr(dotted) {
  return SOURCE_PREFIXES.some((p) => dotted === p || dotted.startsWith(`${p}.`) || dotted.startsWith(`${p}[`));
}

function sinkFor(calleeDotted) {
  for (const s of SINKS) {
    if (s.match.some((m) => calleeDotted === m || calleeDotted.endsWith(m))) return s;
  }
  return null;
}

function isSanitizer(calleeLastSegment) {
  return SANITIZERS.has(calleeLastSegment);
}

module.exports = { SOURCE_PREFIXES, SINKS, SANITIZERS, isSourceExpr, sinkFor, isSanitizer };
