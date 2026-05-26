# Requirements: Rock House

**Defined:** 2026-05-26
**Core Value:** Todo projeto passa por auditoria de seguranca com camadas independentes de defesa antes de ir pra producao.

## v1 Requirements

### Core — Entry Point & Routing

- [ ] **CORE-01**: SKILL.md detecta stack do projeto automaticamente (package.json, requirements.txt, .html)
- [ ] **CORE-02**: SKILL.md roteia para o modo correto baseado no contexto (trigger phrases, file changes, explicit invocation)
- [ ] **CORE-03**: SKILL.md carrega apenas modulos relevantes (progressive disclosure)

### Modes — Audit

- [ ] **AUDIT-01**: Modo audit escaneia codigo existente contra vetores de ataque relevantes pra stack detectada
- [ ] **AUDIT-02**: Modo audit executa kill-chain analysis — testa se cada camada de defesa resiste sozinha
- [ ] **AUDIT-03**: Modo audit gera relatorio com severidade (Critico, Alto, Medio, Baixo)
- [ ] **AUDIT-04**: Cada finding inclui: arquivo:linha, descricao, impacto, camadas atuais vs recomendadas, fix sugerido

### Modes — Checklist

- [ ] **CHECK-01**: Modo checklist apresenta itens organizados por risco (nao por tecnologia)
- [ ] **CHECK-02**: Cada risco exige >=2 camadas independentes para passar
- [ ] **CHECK-03**: Checklist filtra itens por stack detectada (max ~30 itens relevantes)
- [ ] **CHECK-04**: Checklist marca pass/fail/warning em cada item e gera relatorio final

### Modes — Preventive

- [ ] **PREV-01**: Modo preventive identifica tipo de feature (auth, form, api, payment, upload, session, webhook, chatbot)
- [ ] **PREV-02**: Modo preventive retorna tabela de defesa em profundidade ANTES de escrever codigo
- [ ] **PREV-03**: Tabela especifica >=2 camadas independentes por risco, com code examples na stack do projeto

### Vectors — Injection

- [ ] **VEC-INJ-01**: Detectar XSS — inputs nao sanitizados, innerHTML, dangerouslySetInnerHTML
- [ ] **VEC-INJ-02**: Detectar SQL/NoSQL Injection — concatenacao de strings em queries
- [ ] **VEC-INJ-03**: Detectar CSRF — forms/APIs sem token de protecao
- [ ] **VEC-INJ-04**: Detectar Prompt Injection — inputs de chatbot/IA sem blindagem

### Vectors — Auth & Access

- [ ] **VEC-AUTH-01**: Detectar RLS Bypass — service key no client, policies incompletas, SECURITY DEFINER
- [ ] **VEC-AUTH-02**: Detectar IDOR — endpoints com ID sem verificacao de ownership
- [ ] **VEC-AUTH-03**: Detectar JWT/Session issues — alg none, secret fraco, sem expiracao, cookies sem flags
- [ ] **VEC-AUTH-04**: Detectar Mass Assignment — req.body direto no banco sem whitelist

### Vectors — Secrets & Exposure

- [ ] **VEC-SEC-01**: Detectar secrets no codigo — API keys hardcoded, .env commitado, NEXT_PUBLIC_ com service key
- [ ] **VEC-SEC-02**: Detectar security headers ausentes — HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- [ ] **VEC-SEC-03**: Detectar CORS misconfiguration — Access-Control-Allow-Origin: *

### Vectors — Upload & Network

- [ ] **VEC-NET-01**: Detectar SSRF — URLs externas aceitas em upload sem whitelist
- [ ] **VEC-NET-02**: Detectar File Upload attacks — sem validacao de magic bytes, path traversal
- [ ] **VEC-NET-03**: Detectar Open Redirect — redirecionamento pra URL externa via parametro

### Vectors — Supply Chain

- [ ] **VEC-SUP-01**: Detectar dependency vulnerabilities — CVEs em deps via npm audit / pip audit

### Stacks

- [ ] **STK-01**: Regras especificas para HTML/CSS/JS puro (XSS, CSP, SRI, localStorage)
- [ ] **STK-02**: Regras especificas para Next.js/React (NEXT_PUBLIC_, Server Actions, middleware, API routes)
- [ ] **STK-03**: Regras especificas para Supabase/PostgreSQL (RLS, service key, anon key, JWT)
- [ ] **STK-04**: Regras especificas para Flask/Python (injection, session, CORS, upload)
- [ ] **STK-05**: Regras especificas para Infra/Deploy (WAF, rate-limit, headers, DNS, certs)

### References

- [ ] **REF-01**: OWASP Top 10 em PT-BR com exemplos no contexto de vibe coding
- [ ] **REF-02**: OWASP API Top 10 em PT-BR
- [ ] **REF-03**: Defense in Depth — teoria + kill-chain analysis + exemplos
- [ ] **REF-04**: Operational Defense — guia de WAF, MFA, logs, backups (o que a skill NAO faz)

### Scripts

- [ ] **SCR-01**: scan-secrets — regex para chaves expostas (AWS, OpenAI, Stripe, Supabase, .env)
- [ ] **SCR-02**: audit-deps — npm audit + pip audit wrapper
- [ ] **SCR-03**: check-headers — testa headers de seguranca via curl

### Score & Polish

- [ ] **SCORE-01**: Score gamificado 0-10 com niveis visuais (palha/madeira/pedra/fortaleza)
- [ ] **DOC-01**: README.md com instrucoes de instalacao, uso, e exemplos pro GitHub

## v2 Requirements

### Plugin npm
- **PLUG-01**: Empacotar como npm package com servidor MCP
- **PLUG-02**: Instalacao via npm install -g

### SaaS
- **SAAS-01**: Web app para upload de projeto e scan automatico
- **SAAS-02**: Dashboard com score historico
- **SAAS-03**: Planos de assinatura (free/pago)

## Out of Scope

| Feature | Reason |
|---------|--------|
| WAF/SIEM/MFA real | Skill orienta, nao substitui ferramentas operacionais |
| Auto-fix de codigo | Seguranca precisa de revisao humana |
| CI/CD integration | Fase 2 (plugin) |
| Scan de binarios/mobile | Foco e web apps |
| Network scanning | Requer acesso ao app em producao |
| Custom rule editor | Complexidade alta, future feature |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CORE-01 | Phase 1 | Pending |
| CORE-02 | Phase 1 | Pending |
| CORE-03 | Phase 1 | Pending |
| AUDIT-01 | Phase 2 | Pending |
| AUDIT-02 | Phase 2 | Pending |
| AUDIT-03 | Phase 2 | Pending |
| AUDIT-04 | Phase 2 | Pending |
| VEC-SEC-01 | Phase 3 | Pending |
| VEC-SEC-02 | Phase 3 | Pending |
| VEC-SEC-03 | Phase 3 | Pending |
| VEC-AUTH-01 | Phase 4 | Pending |
| VEC-AUTH-02 | Phase 4 | Pending |
| VEC-AUTH-03 | Phase 4 | Pending |
| VEC-AUTH-04 | Phase 4 | Pending |
| VEC-INJ-01 | Phase 5 | Pending |
| VEC-INJ-02 | Phase 5 | Pending |
| VEC-INJ-03 | Phase 5 | Pending |
| VEC-INJ-04 | Phase 5 | Pending |
| VEC-NET-01 | Phase 6 | Pending |
| VEC-NET-02 | Phase 6 | Pending |
| VEC-NET-03 | Phase 6 | Pending |
| VEC-SUP-01 | Phase 6 | Pending |
| CHECK-01 | Phase 7 | Pending |
| CHECK-02 | Phase 7 | Pending |
| CHECK-03 | Phase 7 | Pending |
| CHECK-04 | Phase 7 | Pending |
| PREV-01 | Phase 8 | Pending |
| PREV-02 | Phase 8 | Pending |
| PREV-03 | Phase 8 | Pending |
| STK-01 | Phase 9 | Pending |
| STK-02 | Phase 9 | Pending |
| STK-03 | Phase 9 | Pending |
| STK-04 | Phase 9 | Pending |
| STK-05 | Phase 9 | Pending |
| REF-01 | Phase 10 | Pending |
| REF-02 | Phase 10 | Pending |
| REF-03 | Phase 10 | Pending |
| REF-04 | Phase 10 | Pending |
| SCR-01 | Phase 10 | Pending |
| SCR-02 | Phase 10 | Pending |
| SCR-03 | Phase 10 | Pending |
| SCORE-01 | Phase 11 | Pending |
| DOC-01 | Phase 11 | Pending |

---
*Defined: 2026-05-26*
