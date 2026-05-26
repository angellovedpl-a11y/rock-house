# Roadmap: Rock House

## Overview

Rock House is a Claude Code security skill that audits web projects against attack vectors using a defense-in-depth approach. The build follows a vertical-slice strategy: SKILL.md router first, then audit mode with the highest-impact vectors, then remaining vectors grouped by domain, then checklist and preventive modes (which consume vectors), then stack-specific rules, references, scripts, and finally scoring and polish. Each phase delivers usable, testable capability.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Skill Router** - SKILL.md entry point with stack detection, mode routing, and progressive disclosure
- [ ] **Phase 2: Audit Mode Foundation** - Audit mode core that scans code and generates severity-graded reports
- [ ] **Phase 3: Secrets & Exposure Vectors** - First vector module covering secrets in code, security headers, and CORS
- [ ] **Phase 4: Auth & Access Vectors** - Vector module for RLS bypass, IDOR, JWT issues, and mass assignment
- [ ] **Phase 5: Injection Vectors** - Vector module for XSS, SQLi, CSRF, and prompt injection
- [ ] **Phase 6: Network & Supply Chain Vectors** - Vector module for SSRF, file upload, open redirect, and dependency vulns
- [ ] **Phase 7: Checklist Mode** - Pre-deploy checklist organized by risk with multi-layer validation
- [ ] **Phase 8: Preventive Mode** - Defense-in-depth tables generated before coding new features
- [ ] **Phase 9: Stack Rules** - Stack-specific detection rules for HTML/JS, Next.js, Supabase, Flask, and Infra
- [ ] **Phase 10: References & Scripts** - OWASP reference docs in PT-BR and optional automation scripts
- [ ] **Phase 11: Score & Polish** - Gamified security score and README for GitHub publication

## Phase Details

### Phase 1: Skill Router
**Goal**: Claude Code can load Rock House as a global skill and route to the correct security mode based on project context
**Depends on**: Nothing (first phase)
**Requirements**: CORE-01, CORE-02, CORE-03
**Success Criteria** (what must be TRUE):
  1. When a user opens a project with package.json, requirements.txt, or .html files, Rock House detects the stack automatically
  2. When a user says "audit this project" or "check security", Rock House routes to the correct mode
  3. Rock House loads only the modules relevant to the detected stack and requested mode (not all files at once)
  4. SKILL.md stays within 150 lines and uses progressive disclosure via file references
**Plans:** 1 plan

Plans:
- [ ] 01-01-PLAN.md — SKILL.md entry point with stack detection, mode routing, directory structure, and symlink setup

### Phase 2: Audit Mode Foundation
**Goal**: Users can run a security audit on existing code and receive a structured report with findings graded by severity
**Depends on**: Phase 1
**Requirements**: AUDIT-01, AUDIT-02, AUDIT-03, AUDIT-04
**Success Criteria** (what must be TRUE):
  1. Running audit on a project produces findings organized by attack vector with severity levels (critical/high/medium/low)
  2. Each finding includes file:line, description, impact, current vs recommended defenses, and a suggested fix
  3. Kill-chain analysis tests whether each defense layer holds independently (not just presence-checking)
  4. The audit report is in PT-BR with clear, non-jargon language
**Plans:** 1 plan

Plans:
- [ ] 02-01-PLAN.md — Audit engine, report template, and kill-chain analysis methodology

### Phase 3: Secrets & Exposure Vectors
**Goal**: The audit can detect secrets leaked in code, missing security headers, and CORS misconfigurations
**Depends on**: Phase 2
**Requirements**: VEC-SEC-01, VEC-SEC-02, VEC-SEC-03
**Success Criteria** (what must be TRUE):
  1. Audit detects hardcoded API keys, committed .env files, and NEXT_PUBLIC_ variables exposing service keys
  2. Audit flags missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
  3. Audit detects CORS misconfiguration (Access-Control-Allow-Origin: *)
  4. Each finding follows the standard format with severity, impact, and fix suggestion
**Plans**: TBD

### Phase 4: Auth & Access Vectors
**Goal**: The audit can detect authentication and access control vulnerabilities across common patterns
**Depends on**: Phase 2
**Requirements**: VEC-AUTH-01, VEC-AUTH-02, VEC-AUTH-03, VEC-AUTH-04
**Success Criteria** (what must be TRUE):
  1. Audit detects RLS bypass patterns: service key in client code, incomplete policies, SECURITY DEFINER misuse
  2. Audit detects IDOR: endpoints using IDs without ownership verification
  3. Audit detects JWT/Session issues: alg none, weak secrets, missing expiration, cookie flag omissions
  4. Audit detects mass assignment: request body passed directly to database without field whitelist
**Plans**: TBD

### Phase 5: Injection Vectors
**Goal**: The audit can detect injection attacks across web and AI contexts
**Depends on**: Phase 2
**Requirements**: VEC-INJ-01, VEC-INJ-02, VEC-INJ-03, VEC-INJ-04
**Success Criteria** (what must be TRUE):
  1. Audit detects XSS patterns: unsanitized inputs, innerHTML, dangerouslySetInnerHTML usage
  2. Audit detects SQL/NoSQL injection: string concatenation in queries instead of parameterized queries
  3. Audit detects CSRF: forms and API endpoints without protection tokens
  4. Audit detects prompt injection: chatbot/AI inputs without sanitization or system prompt blindagem
**Plans**: TBD

### Phase 6: Network & Supply Chain Vectors
**Goal**: The audit can detect network-layer attacks and vulnerable dependencies
**Depends on**: Phase 2
**Requirements**: VEC-NET-01, VEC-NET-02, VEC-NET-03, VEC-SUP-01
**Success Criteria** (what must be TRUE):
  1. Audit detects SSRF: external URLs accepted without whitelist validation
  2. Audit detects file upload attacks: missing magic byte validation, path traversal
  3. Audit detects open redirect: URL parameters used for redirection without validation
  4. Audit detects dependency vulnerabilities by referencing npm audit / pip audit results
**Plans**: TBD

### Phase 7: Checklist Mode
**Goal**: Users can run a pre-deploy checklist that validates defense-in-depth across all relevant risks
**Depends on**: Phase 1, Phases 3-6 (vectors must exist for checklist to reference)
**Requirements**: CHECK-01, CHECK-02, CHECK-03, CHECK-04
**Success Criteria** (what must be TRUE):
  1. Checklist presents items organized by risk category (not by technology)
  2. Each risk requires at least 2 independent defense layers to pass
  3. Checklist filters items to max ~30 relevant to the detected stack
  4. Each item is marked pass/fail/warning and a final summary report is generated
**Plans**: TBD

### Phase 8: Preventive Mode
**Goal**: Users get a defense-in-depth planning table BEFORE writing code for a new feature
**Depends on**: Phase 1, Phases 3-6 (vectors inform what risks to surface)
**Requirements**: PREV-01, PREV-02, PREV-03
**Success Criteria** (what must be TRUE):
  1. User describes a feature type (auth, form, api, payment, upload, etc.) and Rock House identifies applicable risks
  2. A defense table is generated showing at least 2 independent layers per risk with code examples
  3. Code examples use the project's detected stack (not generic pseudo-code)
**Plans**: TBD

### Phase 9: Stack Rules
**Goal**: All detection patterns are tuned to specific technology stacks with stack-aware examples and checks
**Depends on**: Phases 3-6 (vectors provide the detection patterns that stacks specialize)
**Requirements**: STK-01, STK-02, STK-03, STK-04, STK-05
**Success Criteria** (what must be TRUE):
  1. HTML/CSS/JS rules cover XSS via DOM, CSP, SRI, localStorage exposure
  2. Next.js/React rules cover NEXT_PUBLIC_ leaks, Server Actions, middleware auth, API route validation
  3. Supabase/PostgreSQL rules cover RLS policies, service vs anon key usage, JWT verification
  4. Flask/Python rules cover injection, session management, CORS configuration, file upload handling
  5. Infra/Deploy rules cover WAF, rate limiting, security headers, DNS, and TLS certificates
**Plans**: TBD

### Phase 10: References & Scripts
**Goal**: Users have OWASP reference material in PT-BR and optional automation scripts for common checks
**Depends on**: Phase 2 (references are consumed by audit reports; scripts augment manual checks)
**Requirements**: REF-01, REF-02, REF-03, REF-04, SCR-01, SCR-02, SCR-03
**Success Criteria** (what must be TRUE):
  1. OWASP Top 10 reference exists in PT-BR with examples relevant to vibe coding
  2. OWASP API Top 10 reference exists in PT-BR
  3. Defense in Depth reference explains theory, kill-chain analysis, and provides examples
  4. Operational Defense guide covers WAF, MFA, logs, and backups (what the skill does NOT do)
  5. Scripts for scan-secrets, audit-deps, and check-headers work on both PowerShell and Bash
**Plans**: TBD

### Phase 11: Score & Polish
**Goal**: Every audit produces a gamified security score and the project is ready for GitHub publication
**Depends on**: Phases 2-10 (score aggregates all vector findings; README documents everything)
**Requirements**: SCORE-01, DOC-01
**Success Criteria** (what must be TRUE):
  1. Audit report includes a 0-10 score with visual level indicators (palha/madeira/pedra/fortaleza)
  2. Score is calculated from vector findings weighted by severity
  3. README.md provides clear installation instructions, usage examples, and feature overview for GitHub visitors
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11

**Parallel note:** Phases 3, 4, 5, 6 can be executed in any order (all depend only on Phase 2). Phases 7 and 8 can also run in parallel once vectors are complete.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Skill Router | 0/1 | Planning complete | - |
| 2. Audit Mode Foundation | 0/1 | Planning complete | - |
| 3. Secrets & Exposure Vectors | 0/0 | Not started | - |
| 4. Auth & Access Vectors | 0/0 | Not started | - |
| 5. Injection Vectors | 0/0 | Not started | - |
| 6. Network & Supply Chain Vectors | 0/0 | Not started | - |
| 7. Checklist Mode | 0/0 | Not started | - |
| 8. Preventive Mode | 0/0 | Not started | - |
| 9. Stack Rules | 0/0 | Not started | - |
| 10. References & Scripts | 0/0 | Not started | - |
| 11. Score & Polish | 0/0 | Not started | - |
