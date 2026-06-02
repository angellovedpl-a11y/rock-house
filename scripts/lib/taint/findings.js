const FIXPACKS = {
  'TAINT-SQLI': { why: 'Input do usuário chega na query — SQL injection.', before: 'cur.execute(f"SELECT ... {x}")', after: 'cur.execute("SELECT ... %s", (x,))', refs: ['OWASP A03', 'CWE-89'] },
  'TAINT-SSTI': { why: 'Input do usuário renderizado como template — execução no servidor.', before: 'render_template_string("Hi " + x)', after: 'render_template("hi.html", name=x)', refs: ['OWASP A03', 'CWE-94'] },
  'TAINT-RCE': { why: 'Input do usuário chega em execução de comando/código.', before: 'os.system("ping " + x)', after: 'subprocess.run(["ping", x])  # valide x', refs: ['OWASP A03', 'CWE-78'] },
  'TAINT-DESERIALIZE': { why: 'Input do usuário desserializado — execução de código.', before: 'pickle.loads(x)', after: 'json.loads(x)', refs: ['OWASP A08', 'CWE-502'] },
  'TAINT-PATH': { why: 'Input do usuário vira caminho de arquivo — path traversal.', before: 'open(x)', after: 'p = safe_join(BASE, secure_filename(x))', refs: ['OWASP A01', 'CWE-22'] },
  'TAINT-REDIRECT': { why: 'Input do usuário vira destino de redirect — open redirect.', before: 'redirect(x)', after: 'redirect(ALLOWED.get(x, "/"))', refs: ['OWASP A01', 'CWE-601'] }
};

const VECTOR_BY_ID = {
  'TAINT-SQLI': 'Injection', 'TAINT-SSTI': 'Injection', 'TAINT-RCE': 'Injection',
  'TAINT-DESERIALIZE': 'Injection', 'TAINT-PATH': 'Injection', 'TAINT-REDIRECT': 'Headers & CORS'
};

function renderTrace(hops) {
  return hops.map((h) => `${h.text} (${h.file}:${h.line})`).join(' → ');
}

function emitTaintFinding(taintPath, addFinding) {
  const sink = taintPath.hops[taintPath.hops.length - 1];
  const vector = VECTOR_BY_ID[taintPath.sinkId] || 'Injection';
  const trace = renderTrace(taintPath.hops);
  const description = `Fluxo de dado não confiável: ${trace}`;
  const recommendation = (FIXPACKS[taintPath.sinkId] || {}).after || 'Valide/sanitize a entrada antes do sink.';
  const fixPack = FIXPACKS[taintPath.sinkId] || null;
  const finding = addFinding(taintPath.severity, taintPath.sinkId, vector, sink.file, sink.line, description, recommendation, fixPack);
  if (finding && typeof finding === 'object') finding.taintTrace = taintPath.hops;
  return finding;
}

module.exports = { emitTaintFinding, renderTrace };
