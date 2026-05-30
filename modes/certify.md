# Certify Mode

Strict deploy gate for projects that need an internal Rock House certification.
This mode is stricter than Audit and Checklist: it blocks when required evidence
is missing, when severe findings are open, or when confidence is low.

## Certification Goal

Certify only what was verified with evidence. Never certify assumptions.

The final result MUST be exactly one of:

| Result | Meaning |
|--------|---------|
| Bloqueado | Deploy must not proceed |
| Bronze | Preview/staging only |
| Prata | Production allowed with monitoring |
| Ouro | Production gate passed with high confidence |

## Step 1: Confirm Scope

Receive detected stack from `SKILL.md` and confirm with the user:

> "Vou rodar o modo CERTIFY. Ele e mais rigido que audit: UNKNOWN conta contra a certificacao e risco Critico/Alto pode bloquear deploy. Stack detectada: [stacks]. Posso prosseguir?"

If the user corrects the stack, update it before scanning.

## Step 2: Load Required Modules

Load these mode files:

- [modes/audit.md](audit.md)
- [modes/checklist.md](checklist.md)
- [modes/evidence-pack.md](evidence-pack.md)
- [modes/report-template.md](report-template.md)
- [modes/kill-chain.md](kill-chain.md)

Load all vector modules because certify is a full gate:

- [vectors/secrets-exposure.md](../vectors/secrets-exposure.md)
- [vectors/injection.md](../vectors/injection.md)
- [vectors/auth-access.md](../vectors/auth-access.md)
- [vectors/upload-network.md](../vectors/upload-network.md)
- [vectors/supply-chain.md](../vectors/supply-chain.md)

Load stack-specific rules matching the detected stack.

## Step 3: Required Evidence Gates

Each required gate must produce PASS, FAIL, UNKNOWN, or N/A. UNKNOWN is never a
pass. Use [modes/evidence-pack.md](evidence-pack.md) for evidence format.

| Gate | Required Evidence | Blocks When |
|------|-------------------|-------------|
| Secrets | Current code scan, `.env` ignore check, service-key exposure check | Any live secret, service key in client, private key, or S1 UNKNOWN |
| Git History | Gitleaks history scan when `.git` exists | Secret in history; UNKNOWN prevents Ouro |
| Dependencies | Lockfile and dependency audit when package manager exists | Critical CVE, missing lockfile, D2 UNKNOWN prevents Ouro |
| Auth & Access | Auth/session/ownership/RLS checks when auth or data APIs exist | Any Critico/Alto access-control finding |
| Injection | SQL/XSS/eval/prompt-injection checks | Any Critico injection finding |
| Upload & Network | SSRF/upload/redirect checks when relevant code exists | Any Critico network finding |
| Headers & CORS | Static config always; dynamic URL check when URL is provided | Open CORS with credentials; missing CSP/HSTS prevents Ouro |
| Debug/Error Exposure | Debug mode and stack-trace checks | Debug enabled in production or stack traces to client |

## Step 4: Run Audit Engine

Run the full process from [modes/audit.md](audit.md), but apply these stricter
rules:

- Do not skip an applicable category just because no obvious pattern is found.
  Mark it UNKNOWN if evidence is insufficient.
- If an automated tool is unavailable, ask whether to install or provide output.
  If unavailable after that, mark the affected checks UNKNOWN.
- If project size prevents full scanning, certify only the scanned scope and mark
  unscanned applicable areas UNKNOWN.
- If no source files are found, return Bloqueado.

## Step 5: Build Evidence Pack

After scanning, create the Evidence Pack using [modes/evidence-pack.md](evidence-pack.md).

Evidence Pack must include:

- Project path and detected stack
- Files/directories scanned
- Files/directories excluded
- Tools executed and status
- Check registry with PASS/FAIL/UNKNOWN/N/A
- Findings linked to check IDs
- Unknowns with reason and how to resolve
- Final certification decision

## Step 6: Certification Decision

Apply these rules in order:

1. If any open Critico finding exists -> Bloqueado.
2. If confidence is Baixa -> Bloqueado.
3. If UNKNOWN weighted ratio > 40% -> Bloqueado.
4. If score < 6.1 -> Bloqueado.
5. If any open Alto finding exists -> max Bronze.
6. If UNKNOWN weighted ratio > 20% -> max Bronze.
7. If dynamic headers/dependency/secrets checks were not completed -> max Prata.
8. If score >= 8.5, no Critico/Alto, UNKNOWN <= 10%, and required dynamic/tool checks completed -> Ouro.
9. If score >= 7.5, no Critico/Alto, UNKNOWN <= 20% -> Prata.
10. Otherwise -> Bronze.

## Step 7: Output Format

Report in PT-BR:

```markdown
# Certificacao Rock House

**Resultado:** [Bloqueado/Bronze/Prata/Ouro]
**Score:** [X.X]/10
**Confianca:** [Alta/Media/Baixa]
**Stack:** [stacks]

## Bloqueios

| Severidade | Check | Evidencia | Como resolver |
|------------|-------|-----------|---------------|
| [Critico/Alto/UNKNOWN] | [ID] | [file:line/tool status] | [fix concreto] |

## Evidence Pack

[summary from evidence-pack.md]

## Proximas Acoes

1. [Acao que remove bloqueio principal]
2. [Acao que reduz UNKNOWN]
3. [Acao para subir de nivel]
```

## Follow-Up

After output, offer only actionable next steps:

1. Fix blocking findings
2. Reduce UNKNOWN checks
3. Generate a JSON summary for CI/GitHub Action

## CI Scanner

For a dependency-free CI gate, use:

```bash
node scripts/rock-house-ci.js --path . --min-level prata --output rock-house-report.json
```

This scanner is intentionally conservative and limited. It checks high-signal
deploy blockers and produces the JSON shape from [modes/evidence-pack.md](evidence-pack.md).
The interactive skill remains the deeper review path.
