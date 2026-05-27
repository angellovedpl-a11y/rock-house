# Vector Module: Secrets & Exposure

Detects leaked secrets, missing security headers, and CORS misconfigurations.

## VEC-SEC-01: Secrets in Code

### Primary: Gitleaks Scan

Gitleaks is the recommended tool for secrets detection. It covers 100+ secret patterns
including git history scanning, which regex alone cannot do reliably.

#### Detection Flow

1. **Check if Gitleaks is available:**

```bash
# Linux/Mac
which gitleaks

# Windows
where.exe gitleaks
```

2. **If NOT found:** ask the user:

> Gitleaks nao foi encontrado no PATH.
> Quer instalar Gitleaks? (recomendado)
> - Sim → executar `scripts/install-gitleaks.sh` (Linux/Mac) ou `scripts/install-gitleaks.ps1` (Windows)
> - Nao → usar fallback com regex patterns (cobertura limitada, sem scan de historico)

3. **If found (or after install):** run current-files scan:

```bash
gitleaks detect --no-banner --report-format json
```

4. **Check if `.git` directory exists:**
   - **If `.git` exists:** also run history scan (60s timeout):

```bash
# Full git history scan — may take time on large repos
timeout 60 gitleaks detect --no-banner --report-format json --log-opts="--all"
```

   - **If `.git` does NOT exist:** warn user and run with `--no-git`:

> ⚠ Diretorio .git nao encontrado. Scan de historico indisponivel.

```bash
gitleaks detect --no-banner --report-format json --no-git
```

#### Filtering False Positives

Skip findings that match ANY of these conditions:
- File path contains: `node_modules/`, `.git/`, `dist/`, `build/`, `vendor/`, `__pycache__/`
- File extension is: `.md`, `.txt`, `.example`, `.sample`, `.template`
- File path contains: `docs/`, `.planning/`, `references/`, `examples/`
- Variable/key name contains: `ANON`, `PUBLIC`, `anon`, `public` (e.g. `NEXT_PUBLIC_SUPABASE_ANON_KEY`)
- Finding is listed in `.gitleaksignore` file at project root

Documentation files (markdown, text, examples) contain pattern descriptions, code
snippets, and vulnerability references that are NOT real secrets. A regex pattern
like `AKIA[0-9A-Z]{16}` written as an example in a `.md` file is not a leaked key.

#### CRITICAL SAFETY RULE

> **NEVER copy the `match` field from Gitleaks JSON output.**
> The `match` field contains the ACTUAL SECRET VALUE.
> Only use these safe fields: `file`, `startLine`, `endLine`, `rule`, `description`, `author`, `date`, `commit`.
> When reporting findings, show rule name + file + line — never the matched content.

#### Severity Mapping (Gitleaks → Rock House)

| Gitleaks Severity | Rock House Level | Emoji |
|-------------------|------------------|-------|
| critical | Critico | 🔴 |
| high | Alto | 🟠 |
| medium | Medio | 🟡 |
| low | Baixo | 🟢 |

### Fallback: Regex Patterns

Used when Gitleaks is not installed and user declines installation.

> ⚠ Scan de historico git indisponivel sem Gitleaks. Apenas arquivos atuais serao verificados.

#### All 30 Patterns

```
# Cloud providers
AKIA[0-9A-Z]{16}                              # AWS Access Key
aws_secret_access_key\s*=\s*["'][^"']+         # AWS Secret
AIza[0-9A-Za-z_-]{35}                          # Google/Firebase API Key

# Code platforms
ghp_[a-zA-Z0-9]{36}                            # GitHub PAT
gho_[a-zA-Z0-9]{36}                            # GitHub OAuth
github_pat_[a-zA-Z0-9_]{82}                    # GitHub fine-grained PAT
glpat-[a-zA-Z0-9_-]{20}                        # GitLab PAT

# Payment
sk_live_[a-zA-Z0-9]{24,}                       # Stripe live secret
rk_live_[a-zA-Z0-9]{24,}                       # Stripe restricted

# AI providers
sk-[a-zA-Z0-9]{48,}                            # OpenAI
sk-ant-[a-zA-Z0-9_-]{90,}                      # Anthropic

# Communication
xoxb-[0-9]{10,}-[a-zA-Z0-9-]+                  # Slack bot
xoxp-[0-9]{10,}-[a-zA-Z0-9-]+                  # Slack user
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}      # SendGrid
key-[a-f0-9]{32}                                # Mailgun

# Infrastructure
SK[a-f0-9]{32}                                  # Twilio
mongodb(\+srv)?://[^:]+:[^@]+@                  # MongoDB connection string
postgres(ql)?://[^:]+:[^@]+@                    # PostgreSQL connection string
mysql://[^:]+:[^@]+@                            # MySQL connection string
redis://:[^@]+@                                 # Redis connection string

# Auth/Crypto
-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY # Private keys
(password|passwd|pwd|senha)\s*[:=]\s*["'][^"']{4,}  # Passwords

# Client-side exposure
NEXT_PUBLIC_.*(SERVICE|SECRET|PRIVATE|ADMIN|PASSWORD) # Next.js sensitive
```

Apply the same false-positive filters as Gitleaks: skip `node_modules/`, `.git/`, `dist/`, `build/`,
and skip variables with `ANON`/`PUBLIC`/`anon` in the name.

**Documentation filter:** DISCARD any match found in `.md`, `.txt`, `.example`,
`.sample`, or `.template` files, or inside `docs/`, `.planning/`, `references/`,
`examples/` directories. These are descriptions of vulnerabilities, not actual secrets.
Only flag matches in executable/deployed files (`.ts`, `.js`, `.py`, `.sql`, `.env`, `.json`, etc.).

### NEXT_PUBLIC_ Exposure

Search for environment variables with `NEXT_PUBLIC_` prefix that expose sensitive data:

```
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE
NEXT_PUBLIC_.*SECRET
NEXT_PUBLIC_.*PRIVATE
NEXT_PUBLIC_.*PASSWORD
NEXT_PUBLIC_.*TOKEN(?!.*anon)
```

Any `NEXT_PUBLIC_` variable is exposed in the client-side JavaScript bundle. Only public-safe values should use this prefix.

### .env Files in Git

Check if `.env` files are tracked by git:
- Run: `git ls-files | grep -i '\.env'`
- Check if `.gitignore` contains `.env*` pattern
- Check git history: `git log --all --diff-filter=A -- '*.env' '.env*'`

Even if .env is now gitignored, it may exist in git history.

### Severity Assignment

| Finding | Source | Severity |
|---------|--------|----------|
| Live API key (AWS, Stripe sk_live, production tokens) | Gitleaks or Fallback | 🔴 Critico |
| Secret found in git history | Gitleaks only | 🔴 Critico |
| NEXT_PUBLIC_ with service role key | Gitleaks or Fallback | 🔴 Critico |
| .env committed to git (current) | Gitleaks or Fallback | 🔴 Critico |
| Private key file detected | Gitleaks or Fallback | 🔴 Critico |
| .env in git history only | Gitleaks only | 🟠 Alto |
| Test/dev API key exposed | Gitleaks or Fallback | 🟠 Alto |
| Password in code or comment | Gitleaks or Fallback | 🟠 Alto |
| Database connection string with credentials | Gitleaks or Fallback | 🟠 Alto |
| Generic secret pattern (may be false positive) | Fallback only | 🟡 Medio |
| Missing .gitignore for .env | Gitleaks or Fallback | 🟡 Medio |
| Low-confidence pattern match | Fallback only | 🟢 Baixo |

### Fix Suggestions

**For hardcoded keys:**
```
// ❌ Errado
const apiKey = "sk-abc123...";

// ✅ Correto
const apiKey = process.env.API_KEY;
```

**For NEXT_PUBLIC_ exposure:**
```
// ❌ Errado — service key no client
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...

// ✅ Correto — service key só no server
SUPABASE_SERVICE_ROLE_KEY=eyJ...
// Usar em API routes ou Server Actions, nunca no client
```

**For .env in git:**
```bash
# Adicionar ao .gitignore
echo ".env*" >> .gitignore

# Remover do tracking (mantém o arquivo local)
git rm --cached .env

# Se já está no histórico, rotacionar TODAS as chaves
# O git history é permanente — considere git-filter-repo para limpar
```

---

## VEC-SEC-01b: Error Disclosure & Debug Mode

### What to Look For

Stack traces, debug modes, and verbose error messages in production leak internal
paths, library versions, database schemas, and query structures — giving attackers
a detailed map of the application.

#### Debug mode enabled

```javascript
// Express debug in production
app.set('env', 'development')
// or: NODE_ENV not set (defaults to development)

// Next.js — check if dev mode flags leak
// next.config.js with reactStrictMode is fine, but check for:
devIndicators: { buildActivity: true }  // visible in prod = info leak

// Flask debug mode
app.run(debug=True)
FLASK_DEBUG=1
FLASK_ENV=development
```

#### What to search for (Grep patterns)

```
NODE_ENV.*development
NODE_ENV.*dev
debug.*true
debug.*True
FLASK_DEBUG
FLASK_ENV.*development
app.run(debug
DEBUG\s*=\s*True
DEBUG\s*=\s*true
```

Then check if this is production config (not just local dev scripts).

#### Stack traces sent to client

```javascript
// Express — error handler that leaks stack
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// Unhandled errors that fall through to default Express handler
// Default Express handler shows stack in development mode

// Next.js — custom error pages that expose details
// pages/_error.js or app/error.tsx that renders err.message
```

```python
# Flask — traceback visible in browser
# Default behavior when debug=True

# Django — DEBUG=True in settings.py shows full traceback
DEBUG = True
```

#### Verbose error messages

```javascript
// Database errors forwarded to client
catch (err) {
  res.json({ error: err.message });  // may contain SQL, table names, column names
}

// Authentication errors that leak info
if (!user) return res.json({ error: 'User not found' });       // reveals user exists
if (!valid) return res.json({ error: 'Wrong password' });      // confirms user exists
// vs safe: "Invalid credentials" for both cases
```

#### What to search for (Grep patterns)

```
err\.message
err\.stack
error\.message
error\.stack
traceback
res.json.*err
res.send.*err
# Then check if these reach the client response
```

For account enumeration:
```
[Uu]ser not found
[Uu]suario nao encontrado
[Ee]mail not found
[Ee]mail nao encontrado
[Ww]rong password
[Ss]enha incorreta
# Different messages for "not found" vs "wrong password" = enumeration
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| DEBUG=True / debug mode in production config | Alto |
| Stack trace sent in error response | Alto |
| Database error messages forwarded to client | Medio |
| Different error messages for user-not-found vs wrong-password | Medio |
| NODE_ENV not explicitly set to production | Medio |
| Verbose error logging to client-visible output | Medio |

### Fix Suggestions

```javascript
// ❌ Errado — stack trace no response
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// ✅ Correto — mensagem generica pro client, detalhes no log
app.use((err, req, res, next) => {
  console.error(err);  // log interno — visivel so no servidor
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// ✅ Auth sem enumeration
// ❌ "Usuario nao encontrado" / "Senha incorreta"
// ✅ "Credenciais invalidas" (mesma mensagem pra ambos)
```

```python
# ❌ Errado — debug em producao
app.run(debug=True)

# ✅ Correto
app.run(debug=False)
# Ou via env var: FLASK_DEBUG=0
```

```javascript
// ✅ Garantir NODE_ENV em producao
// package.json
"scripts": {
  "start": "NODE_ENV=production node server.js"
}
// Ou no Dockerfile / Vercel / hosting config
```

---

## VEC-SEC-02: Security Headers

### What to Look For

Check if the project configures security headers. Search for header configuration in:

**Next.js:** `next.config.js` or `next.config.ts` → `headers()` function
**Express/Node:** middleware setting response headers
**Flask:** `@app.after_request` or Flask-Talisman
**Vercel:** `vercel.json` → `headers` array
**Static:** `_headers` file (Netlify) or `.htaccess`

### Required Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS, prevent downgrade |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control URL leakage |
| `Content-Security-Policy` | project-specific | Prevent XSS, control resource loading |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disable unused browser APIs |

### Severity Assignment

| Finding | Severity |
|---------|----------|
| No security headers configured at all | 🟠 Alto |
| Missing CSP header | 🟠 Alto |
| Missing HSTS | 🟡 Médio |
| Missing X-Frame-Options | 🟡 Médio |
| Missing X-Content-Type-Options | 🟡 Médio |
| Missing Referrer-Policy | 🟢 Baixo |
| Missing Permissions-Policy | 🟢 Baixo |

### Fix Suggestions

**Next.js (next.config.js):**
```javascript
const nextConfig = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
      ],
    }];
  },
};
```

**Express:**
```javascript
const helmet = require('helmet');
app.use(helmet());
```

**Flask:**
```python
from flask_talisman import Talisman
Talisman(app, content_security_policy=csp)
```

---

## VEC-SEC-03: CORS Misconfiguration

### What to Look For

Search for CORS configuration patterns:

```
Access-Control-Allow-Origin: *
cors({ origin: '*' })
cors({ origin: true })
CORS(app, resources={r"/*": {"origins": "*"}})
@cross_origin()  # without specific origins
```

### What Makes CORS Dangerous

`Access-Control-Allow-Origin: *` allows ANY website to make requests to your API. Combined with `Access-Control-Allow-Credentials: true`, an attacker's site can make authenticated requests on behalf of logged-in users.

### Severity Assignment

| Finding | Severity |
|---------|----------|
| `origin: '*'` with credentials enabled | 🔴 Crítico |
| `origin: '*'` on API with auth endpoints | 🟠 Alto |
| `origin: '*'` on public-only API (no auth) | 🟡 Médio |
| `origin: true` (reflects any origin) | 🟠 Alto |
| CORS not configured (defaults vary by framework) | 🟡 Médio |

### Fix Suggestions

```javascript
// ❌ Errado — aceita qualquer origem
app.use(cors({ origin: '*' }));

// ✅ Correto — whitelist de origens
app.use(cors({
  origin: ['https://meusite.com', 'https://app.meusite.com'],
  credentials: true,
}));
```

```python
# ❌ Errado
CORS(app, resources={r"/*": {"origins": "*"}})

# ✅ Correto
CORS(app, resources={r"/api/*": {"origins": ["https://meusite.com"]}})
```
