# Audit Mode

Scans existing project code against security attack vectors and generates a severity-graded report in PT-BR.

## Step 1: Receive Stack Context

This mode receives the detected stack from SKILL.md Step 1. Available information:
- Detected frameworks (Next.js, React, Flask, Supabase, etc.)
- Detected infrastructure (Vercel, static HTML, etc.)
- Project root path

Before proceeding, confirm the stack detection with the user:

> "Detectei: [stacks]. Está correto? Posso prosseguir com a auditoria?"

If the user corrects the stack, update accordingly.

## Step 2: Load Vector Modules

Check which vector module files exist in the `vectors/` directory:

Expected files:
- [vectors/injection.md](../vectors/injection.md) — XSS, SQLi, CSRF, Prompt Injection
- [vectors/auth-access.md](../vectors/auth-access.md) — RLS Bypass, IDOR, JWT, Mass Assignment
- [vectors/secrets-exposure.md](../vectors/secrets-exposure.md) — Hardcoded keys, Headers, CORS
- [vectors/upload-network.md](../vectors/upload-network.md) — SSRF, File Upload, Open Redirect
- [vectors/supply-chain.md](../vectors/supply-chain.md) — Dependency vulnerabilities

Also check for any additional .md files in vectors/ (future modules).

**If NO vector modules exist** (only .gitkeep): skip to Step 6 and generate an empty report noting that no vector modules are available yet.

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

## Step 4: Scan Project Code

For each loaded vector module, execute this scanning process:

### 4a. Read the vector module
Get its detection rules, patterns to search for, and severity criteria.

### 4b. Search project files
Use Grep and Read tools to find patterns described in the vector module.

**File priority order** (scan these first):
1. Route handlers and API endpoints
2. Authentication and middleware files
3. Database queries and models
4. Configuration files and environment handling
5. Client-side code handling user input
6. Other application code

### 4c. Evaluate each match
For each pattern match, determine if it is a true finding or false positive:
- A pattern in a test file is different from production code
- A pattern with mitigating code nearby may not be a finding
- Context matters — read surrounding lines before flagging

### 4d. Record true findings
For each confirmed finding, record:
- File path and line number
- Vector category it belongs to
- Plain-language description (PT-BR, no jargon)
- Potential impact if exploited
- Current defense (if any exists)
- Recommended defense
- Severity per [modes/report-template.md](report-template.md) criteria

### 4e. Apply stack-specific rules
If stack rules were loaded in Step 3, apply them:
- May upgrade or downgrade severity based on stack context
- Add stack-specific fix suggestions and code examples

### Scanning discipline
- Complete one vector module entirely before moving to the next
- Keep findings organized by vector category
- Do NOT mix vectors during scanning

## Step 5: Run Kill-Chain Analysis

After all scanning is complete, load [modes/kill-chain.md](kill-chain.md).

For every **Crítico** and **Alto** finding:
1. Identify all defense layers that exist for that risk
2. Apply the three-question test from kill-chain.md
3. Record the kill-chain results alongside the finding
4. Determine the defense depth verdict (palha/madeira/pedra/fortaleza)

## Step 6: Generate Report

Load [modes/report-template.md](report-template.md) and generate the final report.

Output the report directly to the user (do not write to a file unless asked).

Report structure:
1. **Header** — project info, detected stack, modules loaded, overall assessment
2. **Findings** — organized by vector category (NOT by file)
3. **Kill-chain analysis** — for each Crítico/Alto finding
4. **Summary table** — counts per severity level
5. **Overall score** — 0-10 with metaphor (palha→fortaleza)
6. **Próximos Passos** — top 3 priority fixes

## Step 7: Offer Follow-Up

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

## Edge Cases

### Very large projects (50+ source files)
Scan priority files first (Step 4 priority order). Ask the user:
> "O projeto tem [N] arquivos. Quer uma auditoria completa ou focada em diretórios específicos?"

### No source code files found
Report clearly:
> "Nenhum arquivo de código-fonte encontrado. Verifique se está no diretório correto do projeto."

### Mixed stacks (e.g., Next.js + Supabase)
Load ALL relevant vector modules and stack rules. Note the multi-stack nature in the report header. This is expected and common.
