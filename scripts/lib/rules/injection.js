const { shouldFlagInnerHtml } = require('../js-detection');

module.exports = [
  {
    id: 'I3', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /dangerouslySetInnerHTML/,
    message: 'React dangerouslySetInnerHTML can create XSS if content is user-controlled.',
    recommendation: 'Render text normally or sanitize HTML with a reviewed sanitizer.',
    fixPack: {
      why: 'HTML controlado pelo usuário vira execução de script no navegador da vítima.',
      before: '<div dangerouslySetInnerHTML={{ __html: comment }} />',
      after: '<div>{comment}</div>  // ou DOMPurify.sanitize(comment)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I2', severity: 'Alto', vector: 'Injection', languages: ['js', 'html'],
    customMatch: (lines, index) => shouldFlagInnerHtml(lines, index),
    message: 'innerHTML assignment can create DOM XSS.',
    recommendation: 'Use textContent or sanitize trusted HTML before inserting it.',
    fixPack: {
      why: 'innerHTML com dado dinâmico executa <script>/onerror injetado.',
      before: 'el.innerHTML = `<b>${user.name}</b>`;',
      after: 'el.textContent = user.name;  // ou DOMPurify.sanitize(...)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I4', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /\beval\s*\(|setTimeout\s*\([^,)]*(req|query|body|input|message)/,
    message: 'External input appears to reach code execution.',
    recommendation: 'Remove eval-like execution and validate input with a schema.',
    fixPack: {
      why: 'Entrada externa chegando em eval = execução remota de código.',
      before: 'eval(req.query.expr)',
      after: 'const value = schema.parse(req.query.expr);  // sem eval',
      refs: ['OWASP A03', 'CWE-95']
    }
  },
  {
    id: 'I5', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /\b(?:child_process\.)?exec(?:Sync)?\s*\([^)]*(\+|`[^`]*\$\{|req\.|request\.|params\.|input)/,
    message: 'Shell command built with external input (command injection).',
    recommendation: 'Use execFile with an argument array; never concatenate user input into a shell string.',
    fixPack: {
      why: 'Concatenar entrada do usuário num comando de shell deixa rodar comando arbitrário.',
      before: 'exec("ping " + req.query.host)',
      after: 'execFile("ping", ["-c", "1", host])  // valide host antes',
      refs: ['OWASP A03', 'CWE-78']
    }
  },
  {
    id: 'I6', severity: 'Alto', vector: 'Injection', languages: ['js'],
    pattern: /\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|unlink)\s*\([^)]*(req\.|request\.|params\.|query\.|body\.)/,
    message: 'Filesystem path built from user input (path traversal).',
    recommendation: 'Resolve against a base dir and reject paths that escape it.',
    fixPack: {
      why: '../../ na entrada permite ler/escrever fora da pasta pretendida.',
      before: 'fs.readFile(req.query.file)',
      after: 'const p = path.resolve(BASE, name); if (!p.startsWith(BASE)) throw Error();',
      refs: ['OWASP A01', 'CWE-22']
    }
  },
  {
    id: 'I7', severity: 'Alto', vector: 'Injection', languages: ['js'],
    pattern: /\b(?:fetch|axios(?:\.get|\.post)?)\s*\([^)]*(req\.|request\.|params\.|query\.|body\.)/,
    message: 'Outbound request target built from user input (SSRF).',
    recommendation: 'Allowlist destination hosts; block internal/metadata addresses.',
    fixPack: {
      why: 'URL controlada pelo usuário deixa o servidor bater em 169.254.169.254 e na rede interna.',
      before: 'fetch(req.query.url)',
      after: 'if (!ALLOWED_HOSTS.includes(new URL(url).host)) throw Error();',
      refs: ['OWASP A10', 'CWE-918']
    }
  },
  {
    id: 'C1', severity: 'Medio', vector: 'Secrets', languages: ['js'],
    pattern: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)/,
    message: 'Weak hash (md5/sha1) used.',
    recommendation: 'Use SHA-256+ for integrity and bcrypt/argon2 for passwords.',
    fixPack: {
      why: 'md5/sha1 são quebráveis — ruins para senha ou integridade.',
      before: "crypto.createHash('md5')",
      after: "crypto.createHash('sha256')  // senha: use bcrypt/argon2",
      refs: ['OWASP A02', 'CWE-327']
    }
  },
  {
    id: 'C2', severity: 'Medio', vector: 'Secrets', languages: ['js'],
    pattern: /\b(?:token|secret|password|otp|nonce|salt)\b[^\n;]*Math\.random\(\)|Math\.random\(\)[^\n;]*\b(?:token|secret|password|otp|nonce|salt)\b/i,
    message: 'Math.random() used to generate a secret/token (predictable).',
    recommendation: 'Use crypto.randomBytes / crypto.randomUUID for security tokens.',
    fixPack: {
      why: 'Math.random() é previsível: tokens viram adivinháveis.',
      before: 'const token = Math.random().toString(36)',
      after: 'const token = crypto.randomBytes(32).toString("hex")',
      refs: ['OWASP A02', 'CWE-338']
    }
  }
];
