# Report Template

Defines the exact output format for Rock House audit reports. All reports are in PT-BR.

## Report Header

```markdown
# Relatorio de Auditoria de Seguranca — Rock House

**Projeto:** [nome do projeto]
**Data:** [YYYY-MM-DD]
**Stack detectada:** [frameworks e tecnologias encontradas]
**Modulos de vetor carregados:** [lista dos modulos usados]
**Avaliacao geral:** [palha/madeira/pedra/fortaleza] ([score]/10)
```

## Severity Definitions

Use these objective criteria — do not assign severity subjectively.

| Nivel | Criterio | Acao |
|-------|----------|------|
| Critico | Exploravel sem autenticacao. Pode causar vazamento de dados ou comprometimento total do sistema. | Corrigir imediatamente |
| Alto | Exploravel com esforco minimo. Impacto significativo na confidencialidade ou integridade. | Corrigir em 24h |
| Medio | Requer condicoes especificas para explorar. Impacto limitado. | Corrigir em 1 semana |
| Baixo | Risco teorico ou melhoria de hardening. Impacto minimo. | Corrigir quando possivel |

## Individual Finding Format

Each finding MUST use this exact structure:

```markdown
### Finding [NNN]: [titulo descritivo em PT-BR]

| Campo | Detalhe |
|-------|---------|
| **Severidade** | [Critico / Alto / Medio / Baixo] |
| **Vetor** | [categoria do ataque — ex: Injection, Auth & Access] |
| **Arquivo** | `[caminho/do/arquivo.ext]:[linha]` |
| **Descricao** | [o que foi encontrado, linguagem clara sem jargao] |
| **Impacto** | [o que um atacante poderia fazer] |
| **Defesa Atual** | [o que protege agora — "Nenhuma" se nao houver] |
| **Defesa Recomendada** | [o que deveria estar em vigor] |
| **Sugestao de Fix** | [exemplo de codigo ou configuracao concreta] |
```

IMPORTANT: Never include actual secret values in findings. Reference file:line only.
Use plain PT-BR language — the reader may be a vibe coder, not a security specialist.

## Kill-Chain Section (for Critico and Alto findings)

After each Critico or Alto finding, include the kill-chain analysis results from kill-chain.md:

```markdown
**Analise Kill-Chain:**
- Camadas encontradas: [lista]
- Teste de isolamento: [resultado por camada]
- Veredicto: [Protegido / Ponto-unico-de-falha / Sem-defesa]
```

## Summary Table

After all findings, include:

```markdown
## Resumo

| Severidade | Quantidade |
|------------|-----------|
| Critico | [N] |
| Alto | [N] |
| Medio | [N] |
| Baixo | [N] |
| **Total** | **[N]** |

## Proximos Passos

1. [Fix mais urgente — titulo + arquivo]
2. [Segundo mais urgente]
3. [Terceiro mais urgente]
```

## Empty Report

When no vector modules are loaded or no findings are detected:

```markdown
# Relatorio de Auditoria de Seguranca — Rock House

**Projeto:** [nome]
**Data:** [YYYY-MM-DD]
**Stack detectada:** [stack]

## Status

[Se nenhum modulo carregado:]
Nenhum modulo de vetor esta disponivel ainda. Os modulos serao adicionados nas proximas fases do Rock House.

[Se nenhuma vulnerabilidade encontrada:]
Nenhuma vulnerabilidade foi encontrada com os modulos de vetor disponiveis. Isso nao garante que o projeto esta livre de vulnerabilidades — apenas que os vetores testados nao encontraram problemas.

**Avaliacao:** A ser determinada quando modulos estiverem disponiveis.
```

## Score Calculation — Deterministic Binary Checks

The score is calculated from 35 binary checks (pass/fail). Checks not applicable
to the detected stack are REMOVED from the total (not counted as pass or fail).

### Check Registry

#### SECRETS (weight 3x — avg CVSS 9.1)

| ID | Check | Pass when |
|----|-------|-----------|
| S1 | No secrets in current code | Gitleaks / fallback regex finds 0 matches |
| S2 | No secrets in git history | Gitleaks --all finds 0 matches |
| S3 | .env in .gitignore | .gitignore contains .env* pattern |
| S4 | NEXT_PUBLIC_ safe only | No NEXT_PUBLIC_ with SERVICE/SECRET/PRIVATE/ADMIN |
| S5 | No private keys in repo | No -----BEGIN PRIVATE KEY patterns found |

#### INJECTION (weight 2x — avg CVSS 8.6)

| ID | Check | Pass when |
|----|-------|-----------|
| I1 | No SQL concatenation | No string-interpolated SQL queries found |
| I2 | No innerHTML with user input | No innerHTML assignments from external data |
| I3 | No dangerouslySetInnerHTML with user input | No unsanitized dangerouslySetInnerHTML |
| I4 | No eval with external input | No eval()/setTimeout()/setInterval() with user data |
| I5 | CSP header configured | Content-Security-Policy found in config or headers |

#### AUTH & ACCESS (weight 2x — avg CVSS 8.0)

| ID | Check | Pass when |
|----|-------|-----------|
| A1 | Service key server-only | No service_role/admin key in client-side files |
| A2 | RLS enabled on all tables | Every table in migrations has ENABLE ROW LEVEL SECURITY |
| A3 | Ownership check on ID endpoints | Endpoints with params.id include user_id/auth check |
| A4 | JWT with expiration | All jwt.sign() calls include expiresIn |
| A5 | Cookies with HttpOnly+Secure+SameSite | Cookie config includes all three flags |

#### SUPPLY CHAIN (weight 1x — avg CVSS 6.5)

| ID | Check | Pass when |
|----|-------|-----------|
| D1 | Lockfile committed | git ls-files shows lockfile |
| D2 | No critical audit CVEs | npm audit --json reports 0 critical |
| D3 | No compromised packages | No packages from compromised list found |
| D4 | Versions pinned | No "*", "latest", or ">=" in dependencies |

#### HEADERS (weight 1x — avg CVSS 5.3)

| ID | Check | Pass when |
|----|-------|-----------|
| H1 | HSTS configured | Strict-Transport-Security in config/headers |
| H2 | X-Frame-Options configured | X-Frame-Options in config/headers |
| H3 | X-Content-Type-Options configured | nosniff in config/headers |
| H4 | CORS restrictive | No origin: '*' or origin: true |
| H5 | Referrer-Policy configured | Referrer-Policy in config/headers |

#### NETWORK (weight 2x — avg CVSS 8.0)

| ID | Check | Pass when |
|----|-------|-----------|
| N1 | SSRF protected | URL fetch endpoints validate/blocklist URLs |
| N2 | Upload validates type | File type checked by magic bytes, not extension |
| N3 | Filenames sanitized | Uploaded files renamed to UUID |
| N4 | No open redirect | Redirect endpoints validate destination is relative |

#### AI (weight 2x — avg CVSS 8.0, skip if no AI detected)

| ID | Check | Pass when |
|----|-------|-----------|
| AI1 | System prompt hardened | System prompt includes boundary instructions |
| AI2 | AI output not executed as code | No eval/db.query on AI response |
| AI3 | AI has no admin DB access | AI context uses anon/user key, not service key |
| AI4 | Rate limit on AI endpoints | Rate limiting middleware on AI routes |

### Score Formula

```
passed_weighted = sum(passed_checks x category_weight)
applicable_weighted = sum(applicable_checks x category_weight)

score_base = (passed_weighted / applicable_weighted) x 10

# Kill-chain depth bonus
bonus = +0.5 for each critical risk with >=3 independent defense layers
bonus = min(bonus, 2.0)

score_final = min(10, score_base + bonus)

# Complexity threshold
if applicable_checks < 12:
    score_final = min(8.0, score_final)
    # Note: "Projeto simples — menos superficie de ataque testada"
```

### Score Scale

| Score | Level | Metaphor |
|-------|-------|----------|
| 0 – 3.0 | Casa de palha | O lobo derruba com um sopro |
| 3.1 – 6.0 | Casa de madeira | Aguenta um pouco, mas cai |
| 6.1 – 8.0 | Casa de pedra | O lobo nao derruba |
| 8.1 – 10 | Fortaleza | Nem com dinamite |

### Presenting the Score

After all findings, present the score table:

```markdown
## Score Deterministico

| Categoria | Checks | Passaram | Peso | Pontos |
|-----------|--------|----------|------|--------|
| Secrets | [N/5] | [n] | 3x | [n x 3] / [N x 3] |
| Injection | [N/5] | [n] | 2x | [n x 2] / [N x 2] |
| Auth | [N/5] | [n] | 2x | [n x 2] / [N x 2] |
| Supply | [N/4] | [n] | 1x | [n x 1] / [N x 1] |
| Headers | [N/5] | [n] | 1x | [n x 1] / [N x 1] |
| Network | [N/4] | [n] | 2x | [n x 2] / [N x 2] |
| AI | [N/4] | [n] | 2x | [n x 2] / [N x 2] |
| **Total** | **[T]** | **[P]** | | **[Pw] / [Aw]** |

**Score base:** [X.X] / 10
**Bonus kill-chain:** +[X.X]
**Score final:** [X.X] / 10 — [metaphor name]
```
