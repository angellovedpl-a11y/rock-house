# Research Summary — Rock House

## Key Findings

**Stack:** Claude Code Skill nativo (Markdown + YAML frontmatter), zero dependências externas. Claude é o motor de análise — os markdowns dizem O QUE procurar, Claude lê o código e aplica. Scripts (.ps1 + .sh) são auxiliares opcionais.

**Table Stakes:** Secret detection, OWASP Top 10 audit, dependency check, severity levels, fix suggestions, multi-stack, pre-deploy checklist.

**Differentiators:** Kill-chain analysis (camadas independentes), score gamificado (palha→fortaleza), preventive mode (ANTES de codar), vetores específicos de vibe coding, PT-BR, zero setup.

**Watch Out For:**
1. False positives matam confiança — ser conservador na severidade
2. Token bloat — progressive disclosure é obrigatório
3. Checklist fatigue — max 30 items, filtrar por stack
4. Over-engineering — ship SKILL.md + audit + 2 vetores primeiro

## Architecture Decision

```
SKILL.md (router) → modes/ (O QUÊ fazer) → vectors/ (O QUE checar) → stacks/ (COMO checar)
```

Cada camada carrega só o necessário. Budget: ~12K tokens por invocação.

## Build Order (recommended)

| Priority | Component | Value |
|----------|-----------|-------|
| 1 | SKILL.md | Tudo começa aqui — routing, detection |
| 2 | modes/audit.md | Maior valor imediato |
| 3 | vectors/secrets-exposure.md | Vetor mais fácil e mais impactante |
| 4 | vectors/auth-access.md | RLS bypass, IDOR, JWT — core |
| 5 | stacks/nextjs.md | Stack mais usada pelo público-alvo |
| 6 | scripts/scan-secrets | Automação de alto valor |
| 7 | modes/checklist.md | Gate de deploy |
| 8 | vectors/injection.md | XSS, SQLi |
| 9 | modes/preventive.md | Precisa vectors prontos |
| 10 | Remaining stacks + vectors | Completar cobertura |
| 11 | references/ | Base de conhecimento |
| 12 | Score + README | Polish + GitHub |

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| v1 nunca fica pronta | Ship após fase 3 (SKILL + audit + 2 vectors). Iterate. |
| Scripts quebram cross-platform | Scripts são opcionais. Core é o markdown + Claude. |
| Skill fica desatualizada | Módulos versionados, updates isolados por arquivo |
| Vibe coder não entende report | PT-BR, linguagem simples, code fix em cada finding |
