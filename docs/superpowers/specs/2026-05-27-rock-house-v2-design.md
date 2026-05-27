# Rock House v2 — Design Spec

> Fechar todos os gaps de eficácia identificados na auto-auditoria da v1.
> Visão futura: sistema de prova/certificação de segurança para vibe coders.

---

## Contexto

A v1 foi auditada e recebeu nota 6.5/10 (casa de madeira reforçada). O core é sólido (vetores, kill-chain, stack rules, preventive mode), mas ~30% da skill é cosmética. Esta spec define as mudanças para alcançar 8+/10.

### Gaps identificados na v1

| Gap | Nível | Problema |
|-----|-------|---------|
| Scripts standalone | Palha | Existem mas a skill não pode executá-los (allowed-tools sem Bash) |
| Detecção de secrets | Madeira | Só 6 padrões regex; não checa git history |
| Supply chain | Palha | Só diz "roda npm audit"; não faz nada sozinho |
| Headers check | Madeira | Teoria certa, sem automação |
| Score gamificado | Palha | Não reproduzível — depende de quantos findings Claude reporta |
| CORS/CSRF | Madeira | Pega caso óbvio, perde os sutis |

### O que NÃO muda (já é real)

- Vetores de ataque (injection, auth, upload-network) — padrões concretos
- Kill-chain 3 perguntas — diferencial real
- Stack rules (Next.js, Flask, Supabase, HTML, Infra) — específicos
- Modo preventive — tabelas de defesa pré-código
- Report template — estrutura de findings clara

---

## 1. Arquitetura Geral

### allowed-tools

```yaml
allowed-tools: "Read Glob Grep Bash"
```

Bash habilitado para que a skill execute verificações automaticamente. Uma skill de segurança não pode pedir permissão para auditar.

### Estrutura de arquivos — mudanças

```
SKILL.md                          ← atualizar allowed-tools
modes/
  audit.md                        ← reescrever: integrar Gitleaks + npm audit + headers
  checklist.md                    ← atualizar: verificações automatizadas
  preventive.md                   ← sem mudança
  kill-chain.md                   ← sem mudança
  report-template.md              ← reescrever: score determinístico
vectors/
  secrets-exposure.md             ← reescrever: Gitleaks como motor + fallback 30 regex
  injection.md                    ← sem mudança
  auth-access.md                  ← sem mudança
  upload-network.md               ← sem mudança
  supply-chain.md                 ← reescrever: execução automática
stacks/                           ← sem mudança
references/                       ← sem mudança
scripts/
  scan-secrets.sh                 ← REMOVER (substituído por Gitleaks)
  scan-secrets.ps1                ← REMOVER
  install-gitleaks.sh             ← NOVO: instala Gitleaks Linux/Mac
  install-gitleaks.ps1            ← NOVO: instala Gitleaks Windows com SHA256
  check-headers.sh                ← REESCREVER: funcional
  check-headers.ps1               ← NOVO: versão Windows
```

---

## 2. Secrets Detection — Gitleaks + Fallback

### Fluxo principal

```
1. Checar se gitleaks está no PATH
   ├── SIM → passo 2
   └── NÃO → perguntar "Quer instalar Gitleaks? (recomendado)"
             ├── SIM → rodar script install-gitleaks (com verificação SHA256)
             └── NÃO → fallback regex expandido (30 padrões)

2. Checar se .git existe
   ├── SIM → gitleaks detect --no-banner --report-format json (arquivos atuais)
   │         + gitleaks detect --no-banner --report-format json --log-opts="--all" (history)
   │           com timeout de 60s e --depth 500 pra repos grandes
   └── NÃO → avisar "Sem .git — só scan de arquivos, sem histórico"
             gitleaks detect --no-banner --report-format json --no-git

3. Filtrar falsos positivos
   ├── Ignorar findings em node_modules/, .git/, dist/, build/
   ├── Ignorar vars com ANON, PUBLIC, anon no nome (Supabase anon key)
   ├── Respeitar .gitleaksignore se existir
   └── Se não existir, sugerir criação com padrões comuns

4. Converter findings → formato Rock House
   ├── Usar: file, line, rule, description do JSON
   ├── NUNCA copiar o campo "match" (contém o secret real)
   └── Mapear severity: gitleaks severity → Rock House severity
```

### Instalação segura (install-gitleaks)

**Linux/Mac (install-gitleaks.sh):**
- Download do GitHub Releases (último release estável)
- Verificar SHA256 contra checksums publicados no release
- Instalar em `~/.local/bin/` (sem sudo)

**Windows (install-gitleaks.ps1):**
- Download do .exe do GitHub Releases
- Verificar SHA256 com `Get-FileHash`
- Instalar em `$env:LOCALAPPDATA\Programs\gitleaks\`
- Adicionar ao PATH da sessão

### Fallback regex expandido (30 padrões)

Quando Gitleaks não está disponível, usar estes padrões via Grep:

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

# Git tracking
.env tracked by git (via git ls-files)

# JWT em código (exceto vars com ANON/PUBLIC)
# eyJ... pattern COM contexto: só flaggear se atribuído a const/var/let
# e NÃO contiver ANON ou PUBLIC no nome da variável
```

Limitação explícita do fallback: NÃO checa git history (só Gitleaks faz isso). Avisar no relatório: "Scan de histórico indisponível sem Gitleaks."

---

## 3. Supply Chain — Execução Automática

### Fluxo

```
1. Detectar package manager
   ├── package-lock.json existe → npm
   ├── yarn.lock existe (sem package-lock) → yarn (análise estática only)
   ├── pnpm-lock.yaml existe → pnpm (análise estática only)
   ├── requirements.txt / Pipfile.lock / poetry.lock → Python
   └── nenhum lockfile → FINDING: "Lockfile ausente" (Médio)

2. Audit automático
   ├── npm → npm audit --json (timeout 30s)
   │         parsear: .vulnerabilities → extrair name, severity, via, fixAvailable
   ├── pip → pip audit --format=json (timeout 30s)
   │         se pip-audit não instalado → avisar, fazer análise estática
   └── yarn/pnpm → análise estática only (formatos JSON inconsistentes)

3. Análise estática (sempre roda via Read)
   ├── Versões sem pin
   │   package.json: "*", "latest", ">=" → Médio
   │   requirements.txt: sem == → Médio
   ├── Pacotes comprometidos conhecidos (lista hardcoded):
   │   event-stream, ua-parser-js, colors@1.4.1+, faker@6.6.6,
   │   node-ipc@10.1.1+, flatmap-stream, coa@2.0.3+, rc@1.2.9+
   │   (lista é suplementar ao npm audit — atualizar nas releases)
   └── Typosquatting: lista curada fixa (NÃO Levenshtein)
       lodahs→lodash, axois→axios, expresss→express,
       reqeusts→requests, reeact→react, momnet→moment,
       undersocre→underscore, chak-ra→chakra, angualr→angular,
       babbel→babel, wepback→webpack, boostrap→bootstrap

4. Gerar findings no formato Rock House
   npm audit critical → 🔴 Crítico
   npm audit high → 🟠 Alto
   npm audit moderate → 🟡 Médio
   npm audit low → 🟢 Baixo
   Pacote comprometido → 🔴 Crítico
   Typosquatting detectado → 🟠 Alto
   Lockfile ausente → 🟡 Médio
   Versões sem pin → 🟡 Médio
```

---

## 4. Headers Check — Automatizado

### Fluxo

```
1. Análise estática (sempre roda — via Read/Grep)
   ├── Next.js → ler next.config.js/ts → buscar async headers()
   ├── Express → buscar require('helmet') ou res.setHeader manual
   ├── Flask → buscar Flask-Talisman ou @app.after_request
   ├── Vercel → ler vercel.json → buscar "headers"
   ├── Netlify → ler _headers ou netlify.toml
   └── Para cada header obrigatório: presente/ausente no config

2. Detecção de plataforma managed
   ├── Se vercel.json ou .vercel/ detectado → Vercel
   ├── Se netlify.toml ou .netlify/ detectado → Netlify
   └── Se managed: rebaixar "ausente no config" de Alto → Baixo
       + nota: "Plataforma pode adicionar headers automaticamente.
               Análise dinâmica (com URL) é mais precisa."

3. Análise dinâmica (opcional — via Bash)
   ├── Perguntar: "Tem URL de staging/preview? (opcional, mais preciso)"
   ├── SIM → executar curl (cross-platform):
   │         Linux/Mac: curl -sI --max-time 10 <url>
   │         Windows: curl.exe -sI --max-time 10 <url>
   │                  fallback: Invoke-WebRequest -Method Head -TimeoutSec 10
   │         Parsear response headers
   │         Comparar vs esperados
   │         Se 4xx/5xx/timeout → "URL não acessível, usando análise estática"
   └── NÃO → pular, usar só estática

Headers obrigatórios:
  Strict-Transport-Security (HSTS) — força HTTPS
  X-Frame-Options — anti-clickjacking
  X-Content-Type-Options — anti-MIME sniffing
  Content-Security-Policy — anti-XSS
  Referrer-Policy — controle de URL leakage
  Permissions-Policy — desabilita APIs do browser
```

---

## 5. Score Determinístico

### Sistema de checks binários

35 checks agrupados por categoria. Cada check é passa/falha. Checks não aplicáveis são removidos do total.

#### SECRETS (peso 3x — CVSS médio 9.1)

| # | Check | Detectado por |
|---|-------|---------------|
| S1 | Nenhum secret no código atual | Gitleaks / fallback regex |
| S2 | Nenhum secret no git history | Gitleaks --all |
| S3 | .env no .gitignore | Grep .gitignore |
| S4 | NEXT_PUBLIC_ só com dados públicos | Grep padrão |
| S5 | Nenhuma private key no repo | Gitleaks / regex |

#### INJECTION (peso 2x — CVSS médio 8.6)

| # | Check | Detectado por |
|---|-------|---------------|
| I1 | Sem concatenação SQL | vectors/injection.md |
| I2 | Sem innerHTML com input de usuário | vectors/injection.md |
| I3 | Sem dangerouslySetInnerHTML com input | vectors/injection.md |
| I4 | Sem eval() com input externo | vectors/injection.md |
| I5 | CSP header configurado | headers check |

#### AUTH & ACCESS (peso 2x — CVSS médio 8.0)

| # | Check | Detectado por |
|---|-------|---------------|
| A1 | Service key só no servidor | vectors/auth-access.md |
| A2 | RLS habilitado em todas tabelas | vectors/auth-access.md (Supabase only) |
| A3 | Ownership check em endpoints com ID | vectors/auth-access.md |
| A4 | JWT com expiração | vectors/auth-access.md |
| A5 | Cookies com HttpOnly+Secure+SameSite | vectors/auth-access.md |

#### SUPPLY CHAIN (peso 1x — CVSS médio 6.5)

| # | Check | Detectado por |
|---|-------|---------------|
| D1 | Lockfile commitado | Grep git ls-files |
| D2 | npm/pip audit sem CVEs críticos | npm audit --json |
| D3 | Sem pacotes comprometidos | lista hardcoded |
| D4 | Versões pinadas | análise package.json |

#### HEADERS (peso 1x — CVSS médio 5.3)

| # | Check | Detectado por |
|---|-------|---------------|
| H1 | HSTS configurado | headers check |
| H2 | X-Frame-Options configurado | headers check |
| H3 | X-Content-Type-Options configurado | headers check |
| H4 | CORS restritivo (não origin: *) | vectors/secrets-exposure.md |
| H5 | Referrer-Policy configurado | headers check |

#### NETWORK (peso 2x — CVSS médio 8.0)

| # | Check | Detectado por |
|---|-------|---------------|
| N1 | SSRF protegido (URL fetch validado) | vectors/upload-network.md |
| N2 | Upload com validação de tipo (magic bytes) | vectors/upload-network.md |
| N3 | Filenames sanitizados (UUID) | vectors/upload-network.md |
| N4 | Sem open redirect | vectors/upload-network.md |

#### AI (peso 2x — CVSS médio 8.0, se aplicável)

| # | Check | Detectado por |
|---|-------|---------------|
| AI1 | System prompt blindado | vectors/injection.md (prompt inj) |
| AI2 | Output da IA não executado como código | vectors/injection.md |
| AI3 | IA sem acesso admin ao banco | vectors/auth-access.md |
| AI4 | Rate limit em endpoints IA | vectors/auth-access.md |

### Cálculo do score

```
checks_passaram = soma(checks que passaram × peso da categoria)
checks_aplicáveis = soma(checks aplicáveis × peso da categoria)

score_base = (checks_passaram / checks_aplicáveis) × 10

# Bônus kill-chain: para cada risco com ≥3 camadas independentes
bonus = +0.5 por risco (máximo +2.0)

score_final = min(10, score_base + bonus)

# Threshold de complexidade
Se checks_aplicáveis < 12 → score_final = min(8.0, score_final)
   + nota: "Projeto simples — menos superfície de ataque testada"
```

### Escala

| Score | Nível | Metáfora |
|-------|-------|----------|
| 0 – 3.0 | Casa de palha | O lobo derruba com um sopro |
| 3.1 – 6.0 | Casa de madeira | Aguenta um pouco, mas cai |
| 6.1 – 8.0 | Casa de pedra | O lobo não derruba |
| 8.1 – 10 | Fortaleza | Nem com dinamite |

### Reprodutibilidade

O mesmo projeto com o mesmo código produz o mesmo score. Cada check tem resultado binário determinado por patterns de Grep ou output de ferramentas. Não há julgamento subjetivo do Claude na contagem.

---

## 6. Projeto-Isca (Testbed de Validação)

Repo propositalmente vulnerável com gabarito conhecido. Serve como crash test dummy — se a skill não encontra uma falha plantada, é gap comprovado.

### Estrutura do testbed

```
rock-house-testbed/
├── package.json          ← deps com CVEs + typosquatting plantado
├── .env                  ← commitado no git (erro proposital)
├── .gitignore            ← SEM .env (erro proposital)
├── next.config.js        ← ZERO headers de segurança
├── src/
│   ├── app/
│   │   ├── page.tsx              ← dangerouslySetInnerHTML com input
│   │   └── api/
│   │       ├── users/route.ts    ← IDOR (sem ownership check)
│   │       ├── login/route.ts    ← sem rate limit, JWT sem expiração
│   │       └── upload/route.ts   ← aceita qualquer arquivo, filename direto
│   ├── lib/
│   │   ├── db.ts                 ← SQL concatenado
│   │   ├── supabase.ts           ← service key no client
│   │   └── ai.ts                 ← prompt injection aberto, eval(aiResponse)
│   └── config/
│       └── secrets.ts            ← API keys hardcoded (fake mas padrão real)
├── supabase/
│   └── migrations/
│       └── 001_tables.sql        ← tabela sem RLS
└── cors-server.js                ← origin: '*' com credentials: true
```

### Gabarito — 22 falhas plantadas

| # | Categoria | Falha | Severidade esperada |
|---|-----------|-------|-------------------|
| 1 | Secrets | AWS key fake AKIA... em secrets.ts | Crítico |
| 2 | Secrets | Stripe sk_live_... fake em secrets.ts | Crítico |
| 3 | Secrets | .env commitado no git | Crítico |
| 4 | Secrets | NEXT_PUBLIC_SUPABASE_SERVICE_ROLE em .env | Crítico |
| 5 | Injection | innerHTML = userInput em page.tsx | Crítico |
| 6 | Injection | SELECT * FROM users WHERE id = ${id} em db.ts | Crítico |
| 7 | Injection | eval(aiResponse) em ai.ts | Crítico |
| 8 | Auth | Service key no client (supabase.ts) | Crítico |
| 9 | Auth | IDOR em /api/users (findById sem ownership) | Alto |
| 10 | Auth | JWT sem expiração em /api/login | Alto |
| 11 | Auth | Cookies sem HttpOnly/Secure/SameSite | Alto |
| 12 | Auth | Tabela sem RLS (migrations) | Crítico |
| 13 | Supply | event-stream no package.json | Crítico |
| 14 | Supply | axois (typosquatting) no package.json | Alto |
| 15 | Supply | Sem lockfile | Médio |
| 16 | Headers | Zero headers de segurança no next.config | Alto |
| 17 | Headers | CORS origin: * com credentials | Crítico |
| 18 | Network | Upload sem validação de tipo | Alto |
| 19 | Network | Filename do usuário direto (path traversal) | Crítico |
| 20 | Network | fetch(req.body.url) sem validação (SSRF) | Crítico |
| 21 | AI | System prompt sem blindagem | Alto |
| 22 | AI | AI output executado como código | Crítico |

### Protocolo de teste

```
1. Rodar Rock House v2 audit no projeto-isca
2. Comparar findings vs gabarito (22 falhas)
3. Classificar cada resultado:
   ✅ Acerto  = skill encontrou a falha
   ❌ Miss    = skill NÃO encontrou (gap real)
   ⚠️  Extra  = skill encontrou algo não plantado (falso positivo ou bônus)

4. Calcular taxa de detecção = acertos / 22
   Meta: ≥ 90% (≥20 de 22)

5. Se <90%: investigar cada miss, corrigir o módulo, re-testar
6. Se ≥90%: skill validada

7. Verificar score determinístico:
   Rodar audit 2x no mesmo testbed → score deve ser idêntico
   Se diferente → bug no sistema de score
```

### Critério de aprovação

- Taxa de detecção ≥ 90% (≥20/22 falhas encontradas)
- Zero falsos positivos críticos (flags que seriam alarmantes mas não são reais)
- Score reproduzível (2 runs = mesmo número)
- Cada categoria tem ≥1 acerto (sem categoria com 0% de detecção)

---

## Fora de escopo (futuro)

- Sistema de prova/certificação (JSON/hash verificável)
- Perfil do desenvolvedor (acumula auditorias)
- Plugin npm (distribuição via npx)
- SaaS comercial
- Integração CI/CD (GitHub Actions)

---

## Ordem de implementação

| Fase | O que muda | Arquivos |
|------|-----------|----------|
| 1 | Bash nas allowed-tools + Gitleaks integration | SKILL.md, vectors/secrets-exposure.md, scripts/install-gitleaks.* |
| 2 | Supply chain automático | vectors/supply-chain.md |
| 3 | Headers check funcional | modes/audit.md (seção headers), scripts/check-headers.* |
| 4 | Score determinístico | modes/report-template.md |
| 5 | Atualizar audit.md (integrar tudo) | modes/audit.md, modes/checklist.md |
| 6 | Remover scripts obsoletos | scripts/scan-secrets.* removidos |
| 7 | Criar testbed + validar skill | rock-house-testbed/ (repo separado), meta ≥90% detecção |
