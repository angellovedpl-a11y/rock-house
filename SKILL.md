---
name: rock-house
description: "Security audit, certification gate, and defense-in-depth analysis for web projects. Use when the user asks to audit code security, certify a project, check for vulnerabilities, review OWASP compliance, run a pre-deploy security checklist, or plan defenses before coding a new feature."
when_to_use: "When user mentions: security audit, vulnerability scan, certify, certification, security gate, check security, OWASP, security headers, secrets in code, defense in depth, pre-deploy review, rock house, casa de pedra, auditoria de seguranca."
allowed-tools: "Read Glob Grep Bash"
---

# Rock House — Security Defense in Depth

Analyzes web projects for security vulnerabilities using independent defense layers.
Each layer must hold on its own — if one falls, the next stops the attack.
Rock House is an internal security gate: it can certify the evaluated evidence,
but it must never claim that a project is absolutely secure.

## Step 1: Detect Project Stack

Before anything else, detect what technologies this project uses:

1. Check if `package.json` exists. If yes, read it and identify frameworks:
   - `next` or `next.config.*` → Next.js
   - `react` → React
   - `express` → Express
   - `@supabase/supabase-js` → Supabase (client)
   - `firebase` → Firebase
   Record as **Node.js** plus specific frameworks found.

2. Check if `requirements.txt`, `pyproject.toml`, or `Pipfile` exists:
   - `flask` → Flask
   - `django` → Django
   - `fastapi` → FastAPI
   Record as **Python** plus specific frameworks.

3. Check if `.html` files exist in root or `public/` directory without package.json.
   Record as **Static HTML/CSS/JS**.

4. Check if `supabase/` directory exists or `.env` contains `SUPABASE` keys.
   Record as **Supabase** (adds to stack, does not replace).

5. Check if `vercel.json` exists. Record as **Vercel deployment**.

6. If none detected, ask the user what stack they are using.

Note: multiple stacks coexist (e.g., Next.js + Supabase). Record ALL detected.

## Step 2: Select Mode

Based on user intent, load the appropriate mode:

| User Intent | Mode | Load |
|---|---|---|
| "certify", "certification", "security gate", "approve deploy", "block deploy" | Certify | [modes/certify.md](modes/certify.md) |
| "audit", "scan", "check security", "review", "vulnerabilities" | Audit | [modes/audit.md](modes/audit.md) |
| "checklist", "pre-deploy", "ready to ship?", "deploy check" | Checklist | [modes/checklist.md](modes/checklist.md) |
| "planning", "new feature", "before I code", "defense table" | Preventive | [modes/preventive.md](modes/preventive.md) |

If intent is unclear, ask the user:
- **Audit** — scan existing code for vulnerabilities
- **Certify** — strict evidence gate that can block deploy
- **Checklist** — pre-deploy security gate
- **Preventive** — plan defenses before coding a new feature

## Step 3: Load Relevant Modules

Load ONLY modules relevant to the detected stack and selected mode.

### Vector Modules

| Module | Covers | File |
|---|---|---|
| Injection | XSS, SQLi, CSRF, Prompt Injection | [vectors/injection.md](vectors/injection.md) |
| Auth and Access | RLS Bypass, IDOR, JWT, Mass Assignment | [vectors/auth-access.md](vectors/auth-access.md) |
| Secrets and Exposure | Hardcoded keys, Security Headers, CORS | [vectors/secrets-exposure.md](vectors/secrets-exposure.md) |
| Upload and Network | SSRF, File Upload, Open Redirect | [vectors/upload-network.md](vectors/upload-network.md) |
| Supply Chain | Dependency vulnerabilities (npm/pip) | [vectors/supply-chain.md](vectors/supply-chain.md) |

### Stack-Specific Rules

| Stack Detected | File |
|---|---|
| HTML/CSS/JS | [stacks/html-js.md](stacks/html-js.md) |
| Next.js / React | [stacks/nextjs.md](stacks/nextjs.md) |
| Supabase / PostgreSQL | [stacks/supabase.md](stacks/supabase.md) |
| Flask / Python | [stacks/flask.md](stacks/flask.md) |
| Infrastructure / Deploy | [stacks/infra.md](stacks/infra.md) |

Load ONLY files matching the detected stack. Do NOT load all files.

## Reporting Rules

- All reports in Portuguese (PT-BR)
- Each finding MUST include: severity (Critico/Alto/Medio/Baixo), file:line, description, impact, current defense, recommended fix with code example
- Each check MUST be marked PASS, FAIL, UNKNOWN, or N/A. UNKNOWN means the skill could not verify the control with available evidence.
- Certification levels are internal gates only: Bloqueado, Bronze, Prata, Ouro. Do not call them external certification.
- Use metaphor: palha = no defense, madeira = partial, pedra = solid, fortaleza = independent layers
- Group findings by attack vector, not by file
- Kill-chain test: for each critical risk, verify each layer holds independently
- Never mark a project as production-safe if any Critico finding remains open or if confidence is Baixa.

## References (loaded on demand)

| Reference | File |
|---|---|
| OWASP Top 10 (PT-BR) | [references/owasp-top10.md](references/owasp-top10.md) |
| OWASP API Top 10 (PT-BR) | [references/owasp-api.md](references/owasp-api.md) |
| Defense in Depth | [references/defense-in-depth.md](references/defense-in-depth.md) |
| Operational Defense | [references/operational.md](references/operational.md) |

Load a reference ONLY when citing a specific OWASP category or explaining defense theory.
