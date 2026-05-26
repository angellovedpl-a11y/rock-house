# Audit Mode

Scans existing project code against security attack vectors and generates a severity-graded report.

## What This Mode Does

1. Reads project files based on the detected stack
2. Applies vector detection rules for each relevant attack category
3. Runs kill-chain analysis — tests if each defense layer holds independently
4. Produces findings graded by severity: Critico / Alto / Medio / Baixo
5. Each finding includes: file:line, description, impact, current vs recommended defenses, fix suggestion
6. Report is in Portuguese (PT-BR)

## Vector Modules to Load

Based on the detected stack, load the relevant vector files:

- [vectors/injection.md](../vectors/injection.md) — XSS, SQLi, CSRF, Prompt Injection
- [vectors/auth-access.md](../vectors/auth-access.md) — RLS Bypass, IDOR, JWT, Mass Assignment
- [vectors/secrets-exposure.md](../vectors/secrets-exposure.md) — Hardcoded keys, Headers, CORS
- [vectors/upload-network.md](../vectors/upload-network.md) — SSRF, File Upload, Open Redirect
- [vectors/supply-chain.md](../vectors/supply-chain.md) — Dependency vulnerabilities

## Stack Rules to Load

Load the stack-specific rules file matching the detected stack from stacks/ directory.

## Status

Full implementation in Phase 2 (Audit Mode Foundation).
