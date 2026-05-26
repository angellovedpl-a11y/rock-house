# Stack Rules: Infrastructure / Deploy

Stack-specific detection patterns for deployment and hosting configuration.

## Elevated Risks

- Missing security headers at platform level
- Rate limiting not configured
- DDoS protection disabled
- Secrets in deployment config
- No HTTPS enforcement

## Detection Patterns

### Vercel (vercel.json)

Check vercel.json for:
```json
// Missing headers configuration
{
  "headers": []  // empty or missing = no security headers
}
```

Check for secrets in vercel.json (should be in Vercel dashboard):
```json
"env": {
  "API_KEY": "sk-actual-key-value"  // 🔴 Crítico
}
```

### Netlify (_headers, netlify.toml)

Check `_headers` file or `netlify.toml [headers]` section exists.
If missing → no security headers configured.

### Docker / docker-compose

```yaml
# Running as root
USER root
# or no USER directive at all (defaults to root)

# Exposing debug ports
ports:
  - "5555:5555"  # debugger
  - "9229:9229"  # node inspect

# Secrets in docker-compose
environment:
  - API_KEY=sk-actual-value  # should use secrets/env_file
```

### Replit (.replit)

Check for secrets in `.replit` file instead of Secrets tool:
```toml
[env]
DATABASE_URL = "postgres://actual-credentials"
```
Severity: 🔴 Crítico — .replit is committed to git.

### General infrastructure checks

| Check | Where | Severity if Missing |
|-------|-------|-------------------|
| HTTPS enforced | Platform config | 🟠 Alto |
| Rate limiting | WAF or middleware | 🟠 Alto |
| DDoS protection | Cloudflare/Vercel | 🟡 Médio |
| Deployment protection | Vercel/Netlify | 🟡 Médio |
| Access logs enabled | Platform | 🟢 Baixo |
| Error pages (no stack trace) | App config | 🟡 Médio |

## Fix Patterns

```json
// ✅ vercel.json with security headers
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=()" }
      ]
    }
  ]
}
```
