# Audit Mode

Scans existing project code against security attack vectors, runs automated checks,
and generates a severity-graded report with deterministic scoring in PT-BR.

## Step 1: Receive Stack Context

This mode receives the detected stack from SKILL.md Step 1. Available information:
- Detected frameworks (Next.js, React, Flask, Supabase, etc.)
- Detected infrastructure (Vercel, static HTML, etc.)
- Project root path

Before proceeding, confirm the stack detection with the user:

> "Detectei: [stacks]. Esta correto? Posso prosseguir com a auditoria?"

If the user corrects the stack, update accordingly.

## Step 2: Load Vector Modules

Check which vector module files exist in the `vectors/` directory:

Expected files:
- [vectors/injection.md](../vectors/injection.md) — XSS, SQLi, CSRF, Prompt Injection
- [vectors/auth-access.md](../vectors/auth-access.md) — RLS Bypass, IDOR, JWT, Mass Assignment
- [vectors/secrets-exposure.md](../vectors/secrets-exposure.md) — Secrets, Headers, CORS
- [vectors/upload-network.md](../vectors/upload-network.md) — SSRF, File Upload, Open Redirect
- [vectors/supply-chain.md](../vectors/supply-chain.md) — Dependency vulnerabilities

Also check for any additional .md files in vectors/ (future modules).

**If NO vector modules exist** (only .gitkeep): skip to Step 8 and generate an empty report noting that no vector modules are available yet.

Track which modules were loaded for the report header.

## Step 3: Load Stack Rules

Check which stack rule files exist in `stacks/` that match the detected stack:

| Detected Stack | File |
|---|---|
| HTML/CSS/JS | [stacks/html-js.md](../stacks/html-js.md) |
| Next.js / React | [stacks/nextjs.md](../stacks/nextjs.md) |
| Supabase / PostgreSQL | [stacks/supabase.md](../stacks/supabase.md) |
| Flask / Python | [stacks/flask.md](../stacks/flask.md) |
| Infrastructure | [stacks/infra.md](../stacks/infra.md) |

If no matching stack rules exist, proceed with vector module generic rules only.
Stack rules augment vector detection with technology-specific patterns and severity adjustments.

## Step 4: Run Automated Scans (via Bash)

Before manual code scanning, run these automated checks. Each produces findings AND
updates the check registry (S1-S5, D1-D4, H1-H5) for deterministic scoring.

### 4a. Secrets Scan

Follow the flow in [vectors/secrets-exposure.md](../vectors/secrets-exposure.md):

1. Check if `gitleaks` is in PATH
   - If YES: run Gitleaks on current files + git history (with 60s timeout)
   - If NO: ask user if they want to install; if declined, use fallback regex (30 patterns)
2. Record findings (NEVER include the actual secret value)
3. Update checks: S1 (current code), S2 (history), S3 (.env in .gitignore), S4 (NEXT_PUBLIC_), S5 (private keys)

### 4b. Supply Chain Audit

Follow the flow in [vectors/supply-chain.md](../vectors/supply-chain.md):

1. Detect package manager (npm/yarn/pnpm/pip)
2. If npm: run `npm audit --json` (timeout 30s), parse vulnerabilities
3. Run static analysis: unpinned versions, compromised packages list, typosquatting list
4. Check lockfile committed to git
5. Update checks: D1 (lockfile), D2 (critical CVEs), D3 (compromised), D4 (pinned)

### 4c. Headers Check

Analyze security headers via static config analysis:

1. **Static analysis (always runs):**
   - Next.js: read next.config.js/ts, search for `async headers()`
   - Express: search for `require('helmet')` or `res.setHeader` with security headers
   - Flask: search for `Flask-Talisman` or `@app.after_request` with headers
   - Vercel: read vercel.json, search for `"headers"` section
   - Netlify: read `_headers` file or `netlify.toml` headers section

2. **Managed platform detection:**
   - If `vercel.json` or `.vercel/` detected: platform = Vercel
   - If `netlify.toml` or `.netlify/` detected: platform = Netlify
   - If managed platform: downgrade "header absent in config" from Alto to Baixo
   - Add note: "Plataforma pode adicionar headers automaticamente. Analise dinamica (com URL) e mais precisa."

3. **Dynamic analysis (optional):**
   - Ask: "Tem URL de staging/preview? (opcional, mais preciso)"
   - If YES: run header check script (check-headers.sh or check-headers.ps1)
   - If timeout/error: "URL nao acessivel, usando analise estatica"
   - If NO: skip, use static analysis only

4. Update checks: H1 (HSTS), H2 (X-Frame-Options), H3 (X-Content-Type-Options), H4 (CORS), H5 (Referrer-Policy)

## Step 5: Scan Project Code (Pattern-Based)

For each loaded vector module, execute this scanning process.
As you scan, track pass/fail for each applicable check in the registry.

### 5a. Read the vector module
Get its detection rules, patterns to search for, and severity criteria.

### 5b. Search project files
Use Grep and Read tools to find patterns described in the vector module.

**File priority order** (scan these first):
1. Route handlers and API endpoints
2. Authentication and middleware files
3. Database queries and models
4. Configuration files and environment handling
5. Client-side code handling user input
6. Other application code

### 5c. Evaluate each match
For each pattern match, determine if it is a true finding or false positive:
- A pattern in a test file is different from production code
- A pattern with mitigating code nearby may not be a finding
- Context matters — read surrounding lines before flagging

### 5d. Record true findings AND update checks
For each confirmed finding, record:
- File path and line number
- Vector category it belongs to
- Plain-language description (PT-BR, no jargon)
- Potential impact if exploited
- Current defense (if any exists)
- Recommended defense
- Severity per [modes/report-template.md](report-template.md) criteria

Also update the check registry:
- I1-I5 for injection findings
- A1-A5 for auth findings
- N1-N4 for network findings
- AI1-AI4 for AI findings (skip entire AI category if no AI libraries detected)

### 5e. Apply stack-specific rules
If stack rules were loaded in Step 3, apply them:
- May upgrade or downgrade severity based on stack context
- Add stack-specific fix suggestions and code examples

### Scanning discipline
- Complete one vector module entirely before moving to the next
- Keep findings organized by vector category
- Do NOT mix vectors during scanning

## Step 6: Run Kill-Chain Analysis

After all scanning is complete, load [modes/kill-chain.md](kill-chain.md).

For every **Critico** and **Alto** finding:
1. Identify all defense layers that exist for that risk
2. Apply the three-question test from kill-chain.md
3. Record the kill-chain results alongside the finding
4. Determine the defense depth verdict (palha/madeira/pedra/fortaleza)

Count how many critical risks have >=3 independent defense layers (for score bonus).

## Step 7: Calculate Deterministic Score

Using the check registry populated in Steps 4 and 5, calculate the final score
per the formula in [modes/report-template.md](report-template.md).

1. For each of the 35 checks, record: PASS / FAIL / N/A
2. Remove N/A checks from the total (not counted)
3. Apply category weights: Secrets 3x, Injection 2x, Auth 2x, Supply 1x, Headers 1x, Network 2x, AI 2x
4. Calculate score_base = (passed_weighted / applicable_weighted) x 10
5. Add kill-chain bonus: +0.5 per critical risk with >=3 defense layers (max +2.0)
6. Apply complexity threshold: if applicable_checks < 12, cap at 8.0
7. Final score = min(10, score_base + bonus)

## Step 8: Generate Report

Load [modes/report-template.md](report-template.md) and generate the final report.

Output the report directly to the user (do not write to a file unless asked).

Report structure:
1. **Header** — project info, detected stack, modules loaded, overall assessment
2. **Findings** — organized by vector category (NOT by file)
3. **Kill-chain analysis** — for each Critico/Alto finding
4. **Summary table** — counts per severity level
5. **Score Deterministico** — the full check registry table with weights and calculation
6. **Overall score** — X.X/10 with metaphor (palha/madeira/pedra/fortaleza)
7. **Proximos Passos** — top 3 priority fixes

## Step 9: Offer Follow-Up

After presenting the report, offer three options:

1. **"Quer que eu corrija algum finding?"** — Claude attempts to fix the issue
2. **"Quer um checklist de deploy baseado nestes findings?"** — Routes to checklist mode
3. **"Quer planejar defesas para uma feature nova?"** — Routes to preventive mode

## File Exclusions

ALWAYS skip these directories and files during scanning:
- `node_modules/`, `.git/`, `dist/`, `build/`, `.next/`
- `__pycache__/`, `venv/`, `.venv/`
- `*.min.js`, `*.map`, `package-lock.json`, `yarn.lock`
- `.env` — read for structure analysis ONLY, NEVER output contents

### Documentation False-Positive Filter

Findings in documentation files are NOT real vulnerabilities. When a Grep match
lands in any of these file types, DISCARD IT — do not report as a finding:

- `*.md` files (README, GABARITO, CHANGELOG, docs, planning artifacts)
- `*.txt` files (notes, changelogs)
- `*.example`, `*.sample`, `*.template` files
- Files inside `docs/`, `.planning/`, `references/`, `examples/` directories

**Why this matters:** Security skills, auditing tools, and testbed gabariots contain
example patterns (regex, vulnerable code snippets, severity tables) that trigger the
same scanners used to find real vulnerabilities. A reference to `eval(aiResponse)` in
a markdown table describing a vulnerability is NOT the same as `eval(aiOutput)` in
actual source code.

**Rule:** Only flag findings in files that are EXECUTED or DEPLOYED — source code
(`.ts`, `.tsx`, `.js`, `.jsx`, `.py`, `.sql`, `.html`, `.css`), configuration files
(`.json`, `.yaml`, `.toml`, `.env`), and shell scripts (`.sh`, `.ps1`).

Exception: `.env` files are flagged for structure/exposure analysis but their
VALUES are never included in the report.

## Edge Cases

### Very large projects (50+ source files)
Scan priority files first (Step 5 priority order). Ask the user:
> "O projeto tem [N] arquivos. Quer uma auditoria completa ou focada em diretorios especificos?"

### No source code files found
Report clearly:
> "Nenhum arquivo de codigo-fonte encontrado. Verifique se esta no diretorio correto do projeto."

### Mixed stacks (e.g., Next.js + Supabase)
Load ALL relevant vector modules and stack rules. Note the multi-stack nature in the report header. This is expected and common.
