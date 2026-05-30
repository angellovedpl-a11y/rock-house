# Evidence Pack

Standard evidence format for Rock House audit, checklist, and certify modes.
Use this whenever a result claims PASS, FAIL, UNKNOWN, N/A, or a certification level.

## Evidence Rules

- PASS requires concrete evidence.
- FAIL requires concrete evidence of unsafe or missing control.
- UNKNOWN means the control could not be verified.
- N/A means the control does not apply to the detected stack.
- A tool failure, timeout, missing file, missing git history, or unsupported package
  manager must be UNKNOWN unless another reliable evidence source exists.
- Never infer PASS from absence of a grep match alone when the control requires
  positive proof.

## Evidence Sources

| Source | Strong Evidence | Weak Evidence |
|--------|-----------------|---------------|
| Static source scan | Exact file:line and surrounding context | Pattern absent from limited scan |
| Tool output | Command, exit code, parsed result | Tool unavailable or unparsable output |
| Runtime URL check | Header/status result from staging/prod URL | Static config only |
| Git metadata | `git ls-files`, `.gitignore`, history scan | No `.git` directory |
| Dependency audit | npm/pip/pnpm/yarn audit or advisory DB result | Hardcoded denylist only |
| Stack config | Framework config and route/middleware files | Assumed framework defaults |

## Evidence Record

Use this structure for every check:

```markdown
| ID | Status | Evidence | Confidence | Notes |
|----|--------|----------|------------|-------|
| S1 | PASS/FAIL/UNKNOWN/N/A | [tool/file:line] | Alta/Media/Baixa | [short reason] |
```

Rules:

- Evidence must name the file, line, command, or tool.
- Secret values must never be copied.
- If a check is UNKNOWN, include the exact action that would make it verifiable.
- If a check is N/A, explain why it does not apply.

## Required Evidence Summary

At the end of certify mode, include:

```markdown
## Evidence Summary

| Area | PASS | FAIL | UNKNOWN | N/A | Confidence |
|------|------|------|---------|-----|------------|
| Secrets | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| Injection | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| Auth & Access | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| Supply Chain | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| Headers & CORS | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| Upload & Network | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
| AI | [n] | [n] | [n] | [n] | [Alta/Media/Baixa] |
```

## UNKNOWN Register

Every UNKNOWN must be listed:

```markdown
## UNKNOWN Register

| ID | Area | Why Unknown | How To Resolve | Blocks |
|----|------|-------------|----------------|--------|
| D2 | Supply Chain | `npm audit` timed out | Re-run audit or provide JSON output | Ouro |
```

## Blocking Evidence

A check is blocking when it proves one of these:

- live secret, service role key, private key, or committed `.env`
- exploitable Critico finding
- access-control bypass on private/user/financial data
- debug mode or stack trace exposure in production path
- critical dependency CVE
- upload path traversal or unrestricted server-side URL fetch
- open CORS with credentials on authenticated API
- confidence Baixa or UNKNOWN ratio above the certify threshold

## JSON Shape For CI

When the user asks for CI/GitHub Action output, use this shape. The
`scripts/rock-house-ci.js` scanner writes this format.

```json
{
  "tool": "rock-house",
  "result": "blocked",
  "certification": "Bloqueado",
  "score": 5.0,
  "confidence": "Baixa",
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "unknown": 5
  },
  "findings": [],
  "unknown": [],
  "gates": []
}
```

## SARIF Output For GitHub Code Scanning

The CI scanner can also write SARIF:

```bash
node scripts/rock-house-ci.js --path . --output rock-house-report.json --sarif rock-house.sarif
```

SARIF results should include:

- `ruleId`: Rock House check ID such as `S4`, `A1`, or `I3`
- `level`: `error` for Critico/Alto, `warning` for Medio, `note` for Baixo
- `locations`: file and line for each finding
- `properties`: severity, vector, impact, and recommendation
- rule metadata: OWASP category, CWE IDs, and help URL when available

## Markdown Summary For PRs

The CI scanner can write a human-readable Markdown summary:

```bash
node scripts/rock-house-ci.js --path . --output rock-house-report.json --markdown rock-house-summary.md
```

When running in GitHub Actions, the same summary is appended to
`GITHUB_STEP_SUMMARY` automatically. It should include:

- certification result, score, confidence, and target path
- severity counts
- top findings with file:line and recommendation
- UNKNOWN register excerpt
- next actions

## Rule Metadata

Every CI finding should include:

- `checkId`: Rock House check ID
- `rule.title`: short rule title
- `rule.owasp`: OWASP Top 10 or OWASP API category list
- `rule.cwe`: CWE ID list
- `rule.helpUri`: reference URL
- `fingerprint`: stable ID used for baseline matching

SARIF rules and Markdown tables should show the same OWASP/CWE mapping.

## CI Config

Projects may define `rock-house.config.json`:

```json
{
  "path": ".",
  "minLevel": "prata",
  "output": "rock-house-report.json",
  "sarif": "rock-house.sarif",
  "markdown": "rock-house-summary.md",
  "baseline": "rock-house-baseline.json",
  "failOnNewOnly": false,
  "exclude": ["docs", "examples", "coverage"],
  "allowCriticalSuppressions": false,
  "suppressions": [
    {
      "checkId": "D4",
      "path": "package.json",
      "reason": "Temporary false positive while migrating dependency policy.",
      "expires": "2026-12-31"
    }
  ]
}
```

CLI flags and GitHub Action inputs override config values. Config values override
scanner defaults.

Suppression rules:

- each suppression must include `reason`
- `checkId`, `path`, and `severity` are optional match filters
- `expires` is optional; expired suppressions are ignored
- Critico findings are not suppressible unless `allowCriticalSuppressions` is true
- suppressed findings must remain visible in JSON and Markdown reports

Config validation rules:

- unknown top-level config keys are rejected
- `minLevel` must be `bronze`, `prata`, or `ouro`
- `baseline`, when present, must be a string path to a previous JSON report
- `failOnNewOnly`, when present, must be a boolean
- `exclude` must be an array of strings
- `allowCriticalSuppressions` must be a boolean
- each suppression must include a non-empty string `reason`
- suppression `severity`, when present, must be `Critico`, `Alto`, `Medio`, or `Baixo`
- suppression `expires`, when present, must parse as a valid date

Baseline rules:

- baseline files are previous Rock House JSON reports
- findings are matched by stable fingerprint: check ID, normalized file path, and description
- baseline findings remain visible in JSON and Markdown
- `failOnNewOnly: true` makes the CI gate count only new findings
- baseline mode is for gradual adoption; it does not certify existing findings as safe
