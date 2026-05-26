# Vector Module: Secrets & Exposure

Detects leaked secrets, missing security headers, and CORS misconfigurations.

## VEC-SEC-01: Secrets in Code

### What to Look For

Search project files for hardcoded secrets using these patterns:

#### API Keys and Tokens (Grep patterns)

```
# AWS
AKIA[0-9A-Z]{16}
aws_secret_access_key\s*=\s*["\'][^"\']+

# OpenAI
sk-[a-zA-Z0-9]{48}

# Stripe
sk_live_[a-zA-Z0-9]{24}
sk_test_[a-zA-Z0-9]{24}
rk_live_[a-zA-Z0-9]{24}

# Supabase service role key
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+

# Firebase
AIza[0-9A-Za-z_-]{35}

# Generic patterns
(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9_\-./+=]{8,}

# Passwords
(password|passwd|pwd|senha)\s*[:=]\s*["\'][^"\']{4,}
```

#### NEXT_PUBLIC_ Exposure

Search for environment variables with `NEXT_PUBLIC_` prefix that expose sensitive data:

```
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE
NEXT_PUBLIC_.*SECRET
NEXT_PUBLIC_.*PRIVATE
NEXT_PUBLIC_.*PASSWORD
NEXT_PUBLIC_.*TOKEN(?!.*anon)
```

Any `NEXT_PUBLIC_` variable is exposed in the client-side JavaScript bundle. Only public-safe values should use this prefix.

#### .env Files in Git

Check if `.env` files are tracked by git:
- Run: `git ls-files | grep -i '\.env'`
- Check if `.gitignore` contains `.env*` pattern
- Check git history: `git log --all --diff-filter=A -- '*.env' '.env*'`

Even if .env is now gitignored, it may exist in git history.

#### Hardcoded in Comments

Search for secrets accidentally left in comments:
```
// password: 
// secret: 
// key: 
# TODO: remove this key
// temporary credentials
```

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Live API key (AWS, Stripe sk_live, production tokens) | 🔴 Crítico |
| NEXT_PUBLIC_ with service role key | 🔴 Crítico |
| .env committed to git (current) | 🔴 Crítico |
| .env in git history only | 🟠 Alto |
| Test/dev API key exposed | 🟠 Alto |
| Password in code comment | 🟠 Alto |
| Generic secret pattern (may be false positive) | 🟡 Médio |
| Missing .gitignore for .env | 🟡 Médio |

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
