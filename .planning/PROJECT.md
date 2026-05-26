# Rock House

## What This Is

Skill global do Claude Code que aplica defesa em profundidade em todo projeto de código, usando a metáfora dos 3 porquinhos: construir casa de pedra que o lobo (atacante) não derruba. Voltada para vibe coders que usam IA pra gerar código e precisam garantir segurança antes de ir pra produção. Evolui de skill local → plugin npm → SaaS comercial.

## Core Value

Todo projeto passa por auditoria de segurança com camadas independentes de defesa antes de ir pra produção — se uma camada cair, a próxima segura sozinha.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] SKILL-01: SKILL.md enxuto com roteamento e gatilhos automáticos
- [ ] MODE-01: Modo audit — auditoria de código existente contra 15 vetores
- [ ] MODE-02: Modo checklist — checklist pré-deploy com camadas independentes
- [ ] MODE-03: Modo preventive — tabela de defesa antes de codar feature nova
- [ ] VEC-01: Módulo injection (XSS, SQLi, CSRF, Prompt Injection)
- [ ] VEC-02: Módulo auth-access (RLS Bypass, IDOR, JWT/Session, Mass Assignment)
- [ ] VEC-03: Módulo secrets-exposure (Secrets no git, Security Headers, CORS)
- [ ] VEC-04: Módulo upload-network (SSRF, File Upload, Open Redirect)
- [ ] VEC-05: Módulo supply-chain (Dependency Vulnerabilities)
- [ ] STACK-01: Regras para HTML/CSS/JS puro
- [ ] STACK-02: Regras para Next.js / React
- [ ] STACK-03: Regras para Supabase / PostgreSQL
- [ ] STACK-04: Regras para Flask / Python
- [ ] STACK-05: Regras para Infra / Deploy
- [ ] REF-01: OWASP Top 10 em PT-BR com exemplos
- [ ] REF-02: OWASP API Top 10
- [ ] REF-03: Defense in Depth — teoria + kill-chain analysis
- [ ] REF-04: Operational Defense — guia de WAF, MFA, logs
- [ ] SCRIPT-01: scan-secrets (.ps1 + .sh)
- [ ] SCRIPT-02: audit-deps (.ps1 + .sh)
- [ ] SCRIPT-03: check-headers (.ps1 + .sh)
- [ ] SCORE-01: Score gamificado 0-10 (palha→madeira→pedra→fortaleza)
- [ ] DOC-01: README.md com instruções de instalação pro GitHub

### Out of Scope

- Plugin npm — só após skill local validada e com tração no GitHub
- SaaS web — fase 3 do roadmap, não agora
- WAF/SIEM/MFA real — a skill orienta, não substitui ferramentas operacionais
- Pentest humano — a skill prepara o código, não substitui profissional
- Scan de binários / mobile — foco é web apps

## Context

- **Autor:** Angelo Silva — maquinista de ferrovia, vibe coder, usa Claude Code como assistente principal
- **Motivação:** estudou cybersegurança (ataques a vibe coding, Argon2, Cloudflare) e quer aplicar defensivamente
- **Projetos-alvo iniciais:** Agenda Seiri (Flask/PostgreSQL), OrbitCode (Next.js/Firebase), Ferroviário Investidor (Next.js/Supabase), My Bank (planejamento)
- **Design v2 completo:** `10-Projects/DEV/rock-house/DESIGN.md` no vault Obsidian
- **Notas de estudo:** `10-Projects/ESTUDOS/cybersec/notas-cybersec.md` com 15 vetores + conteúdo Cloudflare
- **Design v1 superado:** `10-Projects/DEV/cyber-defense-skill/` (renomeado pra Rock House)
- **Princípio base:** Kerckhoffs — seguro mesmo com código aberto
- **Princípio de defesa:** camadas independentes — cada uma segura SOZINHA

## Constraints

- **Stack:** Markdown + PowerShell/Bash scripts — sem dependências externas (a skill precisa funcionar em qualquer máquina com Claude Code)
- **Tamanho:** SKILL.md ≤150 linhas (disclosure progressivo — economizar tokens)
- **Compatibilidade:** Windows (PowerShell) + Linux/Mac (Bash) — scripts em ambos
- **Idioma código:** Inglês (compartilhável no GitHub)
- **Idioma relatórios:** Português BR (público inicial é brasileiro)
- **Tempo:** Angelo tem tempo limitado (trabalha na ferrovia) — fases curtas e práticas

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Nome "Rock House" | Metáfora dos 3 porquinhos — casa de pedra que o lobo não derruba | — Pending |
| Skill antes de plugin | Mais rápido de implementar, design já pronto, funciona global | — Pending |
| Repo em Documents + symlink pra skills | Permite git/GitHub + Claude Code encontra a skill via junction | — Pending |
| Disclosure progressivo | Carrega só o que precisa — economiza tokens, manutenção fácil | — Pending |
| Scripts .ps1 + .sh | Compatibilidade Windows (Angelo) + Linux (Replit/deploy) | — Pending |
| Score gamificado | Torna segurança tangível — palha/madeira/pedra/fortaleza | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-26 after initialization*
