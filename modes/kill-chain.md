# Kill-Chain Analysis

Methodology for testing whether defense layers hold independently — the core principle of Rock House.

## What is Kill-Chain Analysis

An attacker (lobo) tries to break through defense layers (paredes) one by one. Each layer must stop the attack on its own. If the outer wall falls, the inner wall must still hold. This is NOT about checking if a wall EXISTS — it is about testing if each wall RESISTS without the others.

> "Se o sistema deixa de ser seguro só porque alguém viu o código, ele nunca foi seguro."
> — Princípio de Kerckhoffs

## The Three-Question Test

For every defense mechanism found during the audit, answer these three questions:

### Question 1 — Isolation Test
> "Se APENAS esta defesa existisse, o ataque seria bloqueado?"

Test the defense in isolation. Assume all other defenses are disabled. Does this single layer stop the attack?

- YES → the layer is independent (good)
- NO → the layer depends on something else (flag as dependent)

### Question 2 — Fallback Test
> "Se esta defesa FALHAR, qual é a próxima camada que segura?"

Identify what happens if this layer is bypassed. Is there another independent layer behind it?

- YES, another layer exists → defense in depth confirmed
- NO, nothing behind it → single point of failure

### Question 3 — Depth Test
> "Existem pelo menos 2 camadas independentes para este risco?"

Count the total independent layers for this specific risk.

- 0 layers → sem defesa (palha)
- 1 layer → ponto-único-de-falha (madeira)
- 2 layers → defesa sólida (pedra)
- 3+ layers → defesa em profundidade (fortaleza)

## Common Defense Layers by Risk Category

When performing the three-question test, look for these typical layers:

### Authentication Risks
- Input validation (Zod/joi on server)
- Rate limiting (middleware + WAF)
- Secure session management (HttpOnly, Secure, SameSite cookies)
- MFA (second factor)
- Account lockout after N failures

### Data Access Risks
- RLS policies (database level)
- Authorization middleware (server level)
- Ownership verification (WHERE user_id = auth.uid())
- Audit logging (detection layer)

### Injection Risks
- Input sanitization (server-side)
- Parameterized queries / ORM
- CSP headers (browser level)
- Output encoding/escaping (render level)

### Secret Exposure Risks
- Environment variables (not hardcoded)
- .gitignore covering .env files
- Key rotation mechanism
- Secret scanning in CI/CD

### Upload Risks
- File type validation (magic bytes, not extension)
- Filename sanitization (UUID rename)
- Storage outside webroot (S3/R2)
- Size limits (middleware + proxy)

## Kill-Chain Report Format

For each Crítico and Alto finding, include this analysis:

```markdown
**Análise Kill-Chain:**

| Camada | Presente | Isolamento | Status |
|--------|----------|-----------|--------|
| [Camada 1] | ✅/❌ | [segura sozinha? sim/não] | [independente/dependente] |
| [Camada 2] | ✅/❌ | [segura sozinha? sim/não] | [independente/dependente] |
| [Camada 3] | ✅/❌ | [segura sozinha? sim/não] | [independente/dependente] |

**Camadas independentes:** [N]
**Veredicto:** [💨 Sem-defesa / 🪵 Ponto-único-de-falha / 🪨 Protegido / 🔒 Fortaleza]
```

## Defense Depth Scoring

Each risk contributes to the overall project score based on its depth:

| Camadas Independentes | Nível | Metáfora | Contribuição ao Score |
|----------------------|-------|----------|----------------------|
| 0 | Sem defesa | 💨 Palha | Penalidade máxima por severidade |
| 1 | Ponto-único-de-falha | 🪵 Madeira | Penalidade por severidade (atenuada) |
| 2 | Defesa sólida | 🪨 Pedra | Sem penalidade |
| 3+ | Defesa em profundidade | 🔒 Fortaleza | Bônus +1 ao score |
