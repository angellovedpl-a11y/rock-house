# Preventive Mode

Generates defense-in-depth planning tables BEFORE writing code for a new feature.

## How This Mode Works

1. Receive detected stack from SKILL.md Step 1
2. Ask user what feature they want to build
3. Identify the feature type and applicable risks
4. Generate defense table with ≥2 independent layers per risk
5. Provide stack-specific code examples
6. User approves the defense plan, THEN starts coding

## Step 1: Ask About the Feature

> "Qual feature você quer implementar? Descreva em uma frase."

Wait for user response.

## Step 2: Classify Feature Type

Based on the user's description, classify into one or more types:

| Type | Trigger Words | Applicable Risks |
|------|--------------|-----------------|
| **auth** | login, cadastro, senha, register, sign up, authentication | Credential stuffing, session hijack, brute force, weak passwords |
| **form** | formulário, form, input, contato, feedback | XSS, injection, CSRF, spam |
| **api** | endpoint, API, rota, route, REST | Injection, IDOR, rate limiting, CORS, auth bypass |
| **payment** | pagamento, payment, Stripe, checkout, billing | Data theft, CSRF, insufficient logging, PCI compliance |
| **upload** | upload, arquivo, file, imagem, image, PDF | Webshell, SSRF, path traversal, size abuse |
| **session** | sessão, session, cookie, token, JWT | Hijack, fixation, replay, expiration |
| **webhook** | webhook, callback, notification, event | SSRF, replay, signature verification |
| **chatbot** | chatbot, IA, AI, LLM, GPT, Claude, assistente | Prompt injection, data exfiltration, abuse |

A feature can have multiple types (e.g., "upload de avatar com autenticação" = upload + auth).

## Step 3: Generate Defense Table

For each applicable risk, generate a table with at least 2 independent defense layers and code examples in the detected stack.

### Template

```markdown
## 🏠 Plano de Defesa — [nome da feature]

**Stack:** [detected stack]
**Tipo:** [feature types]

### [Risco 1: nome do risco]

| Camada | Defesa | Independente? | Implementação |
|--------|--------|:------------:|---------------|
| 1 | [defesa] | ✅ | [code example] |
| 2 | [defesa] | ✅ | [code example] |
| 3 | [defesa] | ✅ | [code example] |

### [Risco 2: nome do risco]

| Camada | Defesa | Independente? | Implementação |
|--------|--------|:------------:|---------------|
| 1 | [defesa] | ✅ | [code example] |
| 2 | [defesa] | ✅ | [code example] |
```

## Defense Tables by Feature Type

### auth — Login / Cadastro / Senha

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| Credential stuffing | Rate-limit no middleware | Rate-limit no WAF | Captcha após N falhas |
| Senha fraca | Validação Zod no server (min 8 chars) | Política no auth provider | UX com indicador de força |
| Session hijack | Cookies HttpOnly+Secure+SameSite | Rotação de token no login | IP/UA fingerprint check |
| Brute force | Account lockout após 5 tentativas | Rate-limit por IP | Alerta por email |

### form — Formulário / Input

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| XSS | Sanitização no server (DOMPurify/bleach) | Escape no render (React auto) | CSP header restritivo |
| CSRF | Token CSRF no form | SameSite cookie | Verificar Origin header |
| Spam | Honeypot field | Rate-limit | Captcha |
| Injection | Validação Zod/Pydantic | Prepared statements | WAF rules |

### api — Endpoint / Rota

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| IDOR | WHERE user_id = auth.uid() | Middleware de ownership | RLS no banco |
| Rate abuse | Rate-limit no middleware | Rate-limit no WAF | Quota por usuário |
| Auth bypass | JWT verification middleware | RLS policies | API key rotation |
| Data leak | Response filtering (select fields) | Serializer/DTO | Audit logging |

### upload — Arquivo / Imagem

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| Webshell | Validar magic bytes (file-type) | Rename pra UUID | Storage fora do webroot (S3) |
| SSRF | Rejeitar URLs externas | Whitelist de domínios | CSP img-src restrito |
| Path traversal | Sanitizar filename | Path fixo no storage | Permissões no filesystem |
| Size abuse | Limit no middleware (10MB) | Limit no proxy/CDN | Limit no storage bucket |

### payment — Pagamento

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| Data theft | HTTPS obrigatório | Tokenização (Stripe/Kiwify) | Nunca armazenar dados de cartão |
| CSRF | Token CSRF | SameSite cookie | Verificação de webhook signature |
| Insufficient logging | Log de transações | Alertas de anomalia | Audit trail imutável |

### chatbot — IA / LLM

| Risco | Camada 1 | Camada 2 | Camada 3 |
|-------|----------|----------|----------|
| Prompt injection | System prompt blindado | Input sanitization | Output validation |
| Data exfiltration | IA sem acesso admin ao banco | Response filtering | Audit logging |
| Abuse | Rate-limit em endpoints IA | Max tokens por request | Quota por usuário |

## Step 4: Present and Confirm

After generating the defense table, present it to the user and ask:

> "Este é o plano de defesa para [feature]. Cada risco tem pelo menos 2 camadas independentes."
> "Posso começar a implementar seguindo este plano?"

If user approves, they can proceed to code with the defense table as reference.
If user wants changes, adjust the table.

## Step 5: Offer Next Steps

1. "Quer que eu implemente a feature seguindo este plano?"
2. "Quer salvar este plano como referência?" → write to a file
3. "Quer auditar o código depois de implementar?" → routes to audit mode
