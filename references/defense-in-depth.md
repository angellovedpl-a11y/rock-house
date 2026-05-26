# Defense in Depth — Teoria e Prática

## O Conceito

Defesa em profundidade significa construir múltiplas camadas de proteção independentes. Se uma camada falha, a próxima ainda bloqueia o ataque — sem depender da camada que caiu.

## A Metáfora Rock House

| Nível | Metáfora | Significado |
|-------|----------|-------------|
| 💨 Palha | Casa de palha | 0 camadas — o lobo derruba com um sopro |
| 🪵 Madeira | Casa de madeira | 1 camada — ponto-único-de-falha |
| 🪨 Pedra | Casa de pedra | 2 camadas independentes — defesa sólida |
| 🔒 Fortaleza | Fortaleza | 3+ camadas independentes — defesa em profundidade |

## O Princípio de Kerckhoffs

> "Se o sistema deixa de ser seguro só porque alguém viu o código, ele nunca foi seguro de verdade."

A segurança deve depender da chave/segredo, NUNCA do desconhecimento do código. O Linux é open source e roda 96% dos servidores da internet — é seguro PORQUE o design não depende de esconder nada.

## Camadas Independentes vs Dependentes

**❌ Camadas DEPENDENTES (kill-chain avança):**
- "Input validado no front, então o back confia" → atacante manda direto na API
- "RLS ligado, então uso service key" → service key vaza, RLS ignorado
- "CSP bloqueia inline, então não sanitizo" → CSP relaxa, XSS volta

**✅ Camadas INDEPENDENTES (kill-chain para):**
- Validação Zod no server **E** RLS no banco **E** CSP no browser
- Rate-limit no middleware **E** rate-limit no WAF **E** captcha
- Sanitização **E** escape no render **E** CSP restritivo

## Tipos de Camadas

### Técnicas (código e configuração)
- Validação de input (Zod, Pydantic)
- Autenticação e autorização (JWT, RLS, middleware)
- Criptografia (HTTPS, hashing, tokens)
- Headers de segurança (CSP, HSTS, X-Frame-Options)

### Administrativas (processo e política)
- Code review antes de merge
- Auditoria de segurança (Rock House!)
- Rotação de chaves
- Documentação de procedimentos

### Operacionais (infraestrutura)
- WAF (Cloudflare, Vercel Firewall)
- Rate limiting
- Monitoramento e alertas
- Backups automáticos
