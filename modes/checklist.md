# Checklist Mode

Pre-deploy gate that validates defense-in-depth across all relevant risks before shipping.

## How This Mode Works

1. Receive detected stack from SKILL.md Step 1
2. Filter checklist items to only those relevant to the detected stack
3. Present items organized by RISK CATEGORY (not by technology)
4. Each risk requires at least 2 independent defense layers to pass
5. Mark each item pass/fail/warning
6. Generate summary with overall readiness assessment

## Step 1: Confirm Stack and Scope

Show the user what will be checked:

> "Checklist pré-deploy para stack: [stacks detectadas]"
> "[N] itens serão verificados. Iniciando..."

## Step 2: Run Checklist by Risk Category

For each risk category below, check ONLY the items relevant to the detected stack. Skip items marked with a stack tag that doesn't match.

### RISCO: Vazamento de Secrets

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 1 | Nenhum secret hardcoded no código | Todas | Grep for API keys, passwords, tokens in source files |
| 2 | `.env` no `.gitignore` | Todas | Check `.gitignore` contains `.env*` |
| 3 | `NEXT_PUBLIC_` só com dados públicos | Next.js | Check no service keys in NEXT_PUBLIC_ vars |
| 4 | Service key só no servidor | Supabase | Check service_role not in client code |
| 5 | Lockfile commitado | Node.js, Python | Check package-lock.json or requirements.txt in git |

**Automacao:** Items 1, 3, 4 are verified automatically via Gitleaks/regex scan and Grep.

**Camadas independentes necessárias:** .gitignore + env vars no servidor + scan de secrets
**Mínimo pra passar:** 2 camadas ✅

### RISCO: Injection (XSS / SQLi)

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 6 | Inputs sanitizados no servidor | Todas | Check server-side validation exists |
| 7 | Queries parametrizadas | Node.js, Python, Supabase | No string concatenation in queries |
| 8 | CSP header configurado | Todas | Content-Security-Policy present |
| 9 | Output encoding/escape no render | React, Flask, HTML | React auto-escapes; check Flask templates |

**Automacao:** Item 8 (CSP) is verified automatically via headers check.
Items 6, 7, 9 are verified via code pattern scanning.

**Camadas:** sanitização server + queries parametrizadas + CSP + output encoding
**Mínimo pra passar:** 2 camadas ✅

### RISCO: Autenticação e Acesso

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 10 | RLS habilitado em TODAS as tabelas | Supabase | Check migrations/policies |
| 11 | Policies pra SELECT, INSERT, UPDATE, DELETE | Supabase | Complete policy coverage |
| 12 | JWT com expiração | Todas com auth | Check expiresIn in token creation |
| 13 | Cookies com HttpOnly + Secure + SameSite | Todas com auth | Check cookie configuration |
| 14 | Rate limiting em login/auth | Todas com auth | Check rate limit middleware |

**Camadas:** RLS + middleware auth + JWT expiration + rate limiting
**Mínimo pra passar:** 2 camadas ✅

### RISCO: Upload e SSRF

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 15 | Upload valida tipo por magic bytes | Todas com upload | Not just extension check |
| 16 | Filename renomeado (UUID) | Todas com upload | No user filename passed through |
| 17 | Arquivos fora do webroot | Todas com upload | Stored in S3/R2, not public/ |
| 18 | URLs externas bloqueadas ou whitelisted | Todas com URL fetch | No open SSRF |

**Camadas:** validação de tipo + rename + storage externo
**Mínimo pra passar:** 2 camadas ✅

### RISCO: Headers e Infraestrutura

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 19 | HTTPS forçado (HSTS) | Todas | Strict-Transport-Security header |
| 20 | X-Frame-Options | Todas | DENY or SAMEORIGIN |
| 21 | X-Content-Type-Options | Todas | nosniff |
| 22 | CORS restritivo | Todas com API | Not `origin: *` |
| 23 | Rate limiting geral | Todas com API | On API endpoints |

**Automacao:** Items 19-22 are verified automatically via static config analysis.
Note: For Vercel/Netlify projects, some headers are added by the platform.
Use dynamic check (with URL) for accurate results.

**Camadas:** HSTS + CSP + CORS + rate limit
**Mínimo pra passar:** 2 camadas ✅

### RISCO: Dependências

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 24 | `npm audit` sem CVEs críticos | Node.js | Ask user to run npm audit |
| 25 | `pip audit` sem CVEs críticos | Python | Ask user to run pip audit |
| 26 | Versões pinadas | Todas | Lockfile + specific versions |

**Automacao:** Items 24, 25 are verified automatically via npm audit / pip audit.
Item 26 is verified via lockfile check.

**Camadas:** audit limpo + lockfile + versões pinadas
**Mínimo pra passar:** 2 camadas ✅

### RISCO: IA / Chatbot (se aplicável)

| # | Item | Stack | Verificar |
|---|------|-------|-----------|
| 27 | System prompt blindado | Projetos com IA | Check isolation instructions |
| 28 | Output da IA validado antes de ações | Projetos com IA | No eval/db.query on AI output |
| 29 | IA sem acesso admin ao banco | Projetos com IA | No service key in AI context |
| 30 | Rate limit em endpoints de IA | Projetos com IA | Rate limiting on AI routes |

**Camadas:** system prompt + output validation + access control
**Mínimo pra passar:** 2 camadas ✅

## Step 3: Generate Summary

```markdown
# 🏠 Checklist Pré-Deploy — Rock House

**Projeto:** [nome]
**Data:** [YYYY-MM-DD]
**Stack:** [stacks]

## Resultado por Risco

| Risco | Itens | ✅ | ❌ | ⚠️ | Camadas | Status |
|-------|-------|-----|-----|-----|---------|--------|
| Secrets | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| Injection | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| Auth | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| Upload | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| Headers | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| Deps | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |
| IA | [N] | [n] | [n] | [n] | [N]/2 | [🪨/🪵/💨] |

## Veredicto

[Se todos os riscos têm ≥2 camadas:]
🏠🪨 **Casa de pedra — pronto para deploy!**

[Se algum risco tem <2 camadas:]
🏠🪵 **Casa de madeira — corrija os itens ❌ antes de publicar.**
[Lista dos itens que falharam com fix sugerido]

[Se múltiplos riscos sem nenhuma camada:]
🏠💨 **Casa de palha — NÃO publique. Corrija os itens críticos primeiro.**
```

## Step 4: Offer Follow-Up

After the checklist:
1. "Quer que eu corrija os itens que falharam?"
2. "Quer uma auditoria completa?" → routes to audit mode
3. "Tudo certo, pode publicar!" → end
