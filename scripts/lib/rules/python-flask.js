module.exports = [
  {
    id: 'PY-DEBUG', severity: 'Alto', vector: 'Headers & CORS', languages: ['py'],
    pattern: /\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/,
    message: 'Flask debug mode enabled — exposes the Werkzeug console (RCE) in production.',
    recommendation: 'Set debug=False in production and gate it behind an env var.',
    fixPack: {
      why: 'debug=True liga um console que executa Python remoto se alguém alcançar a página de erro.',
      before: 'app.run(debug=True)',
      after: 'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
      refs: ['OWASP A05', 'CWE-489']
    }
  },
  {
    id: 'PY-SHELL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /subprocess\.[a-z_]+\([^)]*shell\s*=\s*True|\bos\.system\(|\bos\.popen\(/,
    message: 'Shell execution with shell=True / os.system can lead to command injection.',
    recommendation: 'Pass an argument list without shell=True and never interpolate user input.',
    fixPack: {
      why: 'shell=True com qualquer parte vinda do usuário vira injeção de comando no servidor.',
      before: 'subprocess.call(cmd, shell=True)',
      after: 'subprocess.run(["git", "clone", repo_url])  # lista, sem shell',
      refs: ['OWASP A03', 'CWE-78']
    }
  },
  {
    id: 'PY-PICKLE', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /\bpickle\.loads?\(/,
    message: 'pickle deserialization of untrusted data allows arbitrary code execution.',
    recommendation: 'Use json for data interchange; never unpickle untrusted bytes.',
    fixPack: {
      why: 'pickle.loads executa código embutido no payload — RCE se o dado não for confiável.',
      before: 'data = pickle.loads(payload)',
      after: 'data = json.loads(payload)',
      refs: ['OWASP A08', 'CWE-502']
    }
  },
  {
    id: 'PY-YAML', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/,
    message: 'yaml.load without SafeLoader can instantiate arbitrary Python objects.',
    recommendation: 'Use yaml.safe_load() for untrusted input.',
    fixPack: {
      why: 'yaml.load constrói objetos Python arbitrários a partir do texto — execução de código.',
      before: 'cfg = yaml.load(stream)',
      after: 'cfg = yaml.safe_load(stream)',
      refs: ['OWASP A08', 'CWE-502']
    }
  },
  {
    id: 'PY-SQL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /(execute|executemany)\s*\(\s*f?["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*(\{|%s?\s*%|"\s*\+|'\s*\+|\.format\()/i,
    message: 'SQL query appears to be built with string formatting — SQL injection risk.',
    recommendation: 'Use parameterized queries (placeholders), never f-strings or concatenation.',
    fixPack: {
      why: 'Montar SQL com f-string/format deixa o usuário reescrever a consulta (SQLi).',
      before: 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
      after: 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))',
      refs: ['OWASP A03', 'CWE-89']
    }
  },
  {
    id: 'PY-SQL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*=\s*f["']|f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/i,
    message: 'SQL string built with an f-string — SQL injection risk.',
    recommendation: 'Build queries with parameter placeholders, not f-strings.',
    fixPack: {
      why: 'f-string em SQL interpola entrada direta na consulta (SQLi).',
      before: 'query = f"SELECT * FROM users WHERE id = {user_id}"',
      after: 'query = "SELECT * FROM users WHERE id = %s"  # e passe (user_id,)',
      refs: ['OWASP A03', 'CWE-89']
    }
  },
  {
    id: 'PY-TEMPLATE', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /render_template_string\s*\(\s*[^)'"]*(request|input|user|f["'])/,
    message: 'render_template_string with dynamic input enables server-side template injection.',
    recommendation: 'Render static templates; pass user data as context variables, not into the template string.',
    fixPack: {
      why: 'Jinja avaliando string controlada pelo usuário = execução de código no servidor (SSTI).',
      before: 'render_template_string("Hi " + request.args["name"])',
      after: 'render_template("hi.html", name=request.args["name"])',
      refs: ['OWASP A03', 'CWE-94']
    }
  },
  {
    id: 'PY-RATELIMIT', severity: 'Medio', vector: 'Auth & Access', languages: ['py'],
    // Dispara só no memory:// HARDCODED. O idioma seguro
    // os.environ.get("RATELIMIT_STORAGE_URI", "memory://") é ignorado pelo lineAllowlist:
    // ali o memory:// é só fallback de dev e produção sobrescreve por env.
    pattern: /RATELIMIT_STORAGE_URI\s*=\s*["']memory:\/\/|storage_uri\s*=\s*["']memory:\/\//i,
    lineAllowlist: [/os\.environ|getenv|environ\.get|config\.get/],
    message: 'Rate-limit com storage memory:// hardcoded — ineficaz em servidor multi-worker (gunicorn/uwsgi).',
    recommendation: 'Use um store compartilhado (redis://) em produção; deixe memory:// só pra dev local, via override por env.',
    fixPack: {
      why: 'memory:// conta por processo: com N workers do gunicorn o limite multiplica por N e zera a cada restart/deploy — o rate limit de login vira ineficaz contra brute-force.',
      before: 'RATELIMIT_STORAGE_URI = "memory://"',
      after: 'RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")  # prod: redis://host:6379/0',
      refs: ['OWASP A04', 'CWE-770']
    }
  }
];
