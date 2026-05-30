# Rock House

> Build your code in a house of stone, not straw.

Security audit and defense-in-depth skill for [Claude Code](https://claude.ai/code). Analyzes web projects for vulnerabilities using independent defense layers — inspired by the Three Little Pigs.

Rock House is an internal security gate. It raises the assurance level of a project by collecting evidence, blocking unsafe deploys, and showing what is still unknown. It does not replace pentesting, production monitoring, or expert review for high-risk systems.

## What It Does

Rock House scans your code for attack vectors across 5 categories, tests if your defenses hold independently (kill-chain analysis), and generates a severity-graded report in Portuguese (PT-BR).

**4 modes:**
- `/rock-house certify` — strict evidence gate for deploy approval/blocking
- `/rock-house audit` — scan existing code for vulnerabilities
- `/rock-house checklist` — pre-deploy security gate
- `/rock-house preventive [feature]` — defense plan BEFORE coding

**Attack vectors:**

| Category | Vectors |
|----------|---------|
| Injection | XSS, SQLi, CSRF, Prompt Injection |
| Auth & Access | RLS Bypass, IDOR, JWT/Session, Mass Assignment |
| Secrets | Hardcoded keys, Security Headers, CORS |
| Network | SSRF, File Upload, Open Redirect |
| Supply Chain | Dependency vulnerabilities |

**5 stacks supported:**
HTML/JS, Next.js/React, Supabase/PostgreSQL, Flask/Python, Infrastructure

## Install

```bash
# Clone to a local directory
git clone https://github.com/angellovedpl-a11y/rock-house.git ~/Documents/rock-house

# Create junction/symlink so Claude Code discovers it
# Windows (no admin needed):
cmd /c mklink /J "%USERPROFILE%\.claude\skills\rock-house" "%USERPROFILE%\Documents\rock-house"

# Mac/Linux:
ln -s ~/Documents/rock-house ~/.claude/skills/rock-house
```

Restart Claude Code. Rock House will appear in your skills list.

## Usage

Open any project in Claude Code, then:

```
audit this project for security       → runs Audit mode
certify this project before deploy    → runs Certify mode
run security checklist before deploy  → runs Checklist mode
plan defenses for login feature       → runs Preventive mode
```

Or invoke directly: `/rock-house certify`

## Demo Target

The repository includes a deliberately vulnerable demo app:

```text
examples/vulnerable-next-supabase/
```

Run Rock House against that directory to verify the gate catches deploy-blocking
issues such as service-role exposure, IDOR, XSS, open CORS, missing lockfile, and
error disclosure.

## CI / GitHub Action

Use Rock House as a PR gate:

```yaml
name: Security

on:
  pull_request:

jobs:
  rock-house:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: angellovedpl-a11y/rock-house@v0
        with:
          path: .
          config: rock-house.config.json
          min-level: prata
          output: rock-house-report.json
          sarif: rock-house.sarif
          markdown: rock-house-summary.md
          dast-url: http://127.0.0.1:3000
          dast-paths: /,/api/health
          observability-evidence: rock-house-observability.json
          baseline: rock-house-baseline.json
          fail-on-new-only: 'false'
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: rock-house-report
          path: |
            rock-house-report.json
            rock-house.sarif
            rock-house-summary.md
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: rock-house.sarif
```

Local CI scanner:

```bash
node scripts/rock-house-ci.js \
  --path examples/vulnerable-next-supabase \
  --min-level prata \
  --output rock-house-report.json \
  --sarif rock-house.sarif \
  --markdown rock-house-summary.md
```

The CI scanner is dependency-free and intentionally conservative. It catches
high-signal deploy blockers, writes JSON/SARIF/Markdown reports, and adds a
GitHub Step Summary automatically when running inside Actions. The interactive
skill provides the deeper evidence review.

Each CI finding includes rule metadata:

- OWASP Top 10 / OWASP API category when applicable
- CWE IDs
- help URL
- stable fingerprint for baseline comparison

Optional project config:

```json
{
  "path": ".",
  "minLevel": "prata",
  "riskProfile": "standard",
  "dast": {
    "url": "http://127.0.0.1:3000",
    "paths": ["/", "/api/health"],
    "timeoutMs": 5000
  },
  "observability": {
    "evidence": "rock-house-observability.json"
  },
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

For high-risk systems, attach an assurance bundle:

```json
{
  "riskProfile": "high",
  "assurance": "rock-house.assurance.json"
}
```

Example assurance file:

```json
{
  "dynamicTesting": {
    "completed": true,
    "environment": "staging",
    "date": "2026-05-30"
  },
  "monitoring": {
    "errorTracking": true,
    "auditLogs": true,
    "alerts": true,
    "healthChecks": true
  },
  "review": {
    "completed": true,
    "reviewer": "security-team",
    "date": "2026-05-30"
  },
  "approval": {
    "humanApproved": true,
    "approver": "release-manager",
    "date": "2026-05-30"
  }
}
```

When `riskProfile` is `high`, Rock House blocks certification if dynamic testing,
runtime monitoring, specialized review, or human approval evidence is missing.

When `dast.url` or the Action input `dast-url` is configured, Rock House performs
live HTTP checks against localhost or staging and can report runtime findings such
as wildcard CORS, missing CSP, missing `nosniff`, server header disclosure, and
stack traces in 5xx responses.

When `observability.evidence` or the Action input `observability-evidence` is
configured, Rock House combines that operational evidence with code-level
detection for providers such as Sentry, Datadog, and OpenTelemetry. This lets
high-risk gates satisfy monitoring requirements with real integration evidence
instead of a manual boolean-only declaration.

Use it locally:

```bash
node scripts/rock-house-ci.js --config rock-house.config.json
```

Precedence: CLI flags and Action inputs override config values; config values
override defaults.

## Security Policy

Report suspected vulnerabilities through the private flow documented in
[.github/SECURITY.md](./.github/SECURITY.md). Do not open a public issue for a
security report.

Suppressions are audited in the JSON and Markdown reports. Each suppression must
include a `reason`. Critical findings cannot be suppressed unless
`allowCriticalSuppressions` is explicitly set to `true`.

Baseline mode lets existing repositories adopt Rock House gradually:

```bash
node scripts/rock-house-ci.js --path . --output rock-house-baseline.json
```

Then configure:

```json
{
  "baseline": "rock-house-baseline.json",
  "failOnNewOnly": true
}
```

Known findings remain visible and marked as baseline. `failOnNewOnly` only changes
the CI gate decision; it does not mean baseline findings are safe.

You can also use baseline without a config file:

```bash
node scripts/rock-house-ci.js \
  --path . \
  --baseline rock-house-baseline.json \
  --fail-on-new-only true
```

Invalid config blocks the scanner before analysis starts. Rock House rejects
unknown config keys, invalid `minLevel`, wrong value types, suppressions without
`reason`, invalid suppression severity, and invalid expiration dates.

Run the scanner tests:

```bash
node tests/rock-house-ci.test.js
```

## Score System

Every audit produces a 0-10 score:

| Score | Level | Meaning |
|-------|-------|---------|
| 0-3 | Straw House | No defense — the wolf blows it down |
| 4-6 | Wood House | Partial defense — holds for a bit |
| 7-8 | Stone House | Solid defense — wolf can't get in |
| 9-10 | Fortress | Defense in depth — not even with dynamite |

**Internal gate:** deploy decisions depend on score, open findings, and confidence:

| Level | Meaning |
|-------|---------|
| Bloqueado | Do not deploy: critical risk, low score, or too much unknown evidence |
| Bronze | Preview/staging only |
| Prata | Production allowed with monitoring |
| Ouro | Production gate passed with high confidence |

## Kill-Chain Analysis

Rock House doesn't just check if defenses exist — it tests if each layer holds **independently**. Three questions per defense:

1. If ONLY this defense existed, would the attack be blocked?
2. If this defense FAILS, what's the next layer?
3. Are there at least 2 independent layers for this risk?

## Project Structure

```
rock-house/
├── SKILL.md              # Entry point (101 lines)
├── action.yml            # GitHub Action entry point
├── .github/
│   └── workflows/
│       └── ci.yml        # Self-test workflow
├── modes/
│   ├── certify.md        # Strict evidence-based deploy gate
│   ├── audit.md           # 7-step audit engine
│   ├── checklist.md       # Pre-deploy gate (30 items)
│   ├── preventive.md      # Defense planning tables
│   ├── evidence-pack.md   # Evidence format and UNKNOWN rules
│   ├── report-template.md # Report format spec
│   └── kill-chain.md      # Independence testing methodology
├── vectors/
│   ├── injection.md       # XSS, SQLi, CSRF, Prompt Injection
│   ├── auth-access.md     # RLS, IDOR, JWT, Mass Assignment
│   ├── secrets-exposure.md # Keys, Headers, CORS
│   ├── upload-network.md  # SSRF, Upload, Redirect
│   └── supply-chain.md    # Dependencies
├── stacks/
│   ├── html-js.md         # Static sites
│   ├── nextjs.md          # Next.js / React
│   ├── supabase.md        # Supabase / PostgreSQL
│   ├── flask.md           # Flask / Python
│   └── infra.md           # Deployment / Hosting
├── references/
│   ├── owasp-top10.md     # OWASP Top 10 (PT-BR)
│   ├── owasp-api.md       # OWASP API Top 10 (PT-BR)
│   ├── defense-in-depth.md # Theory + examples
│   └── operational.md     # WAF, MFA, logs guide
├── scripts/
│   ├── rock-house-ci.js  # Dependency-free JSON security gate for CI
│   ├── lib/
│   │   ├── assurance.js  # High-risk assurance evidence validation
│   │   ├── config.js     # CLI/config parsing and validation
│   │   ├── dast.js       # Dynamic localhost/staging HTTP checks
│   │   ├── js-detection.js # JavaScript sink detection helpers
│   │   ├── observability.js # Runtime monitoring evidence adapters
│   │   ├── report-formatters.js # Markdown and SARIF output
│   │   ├── rules.js      # Rule metadata and severity impact
│   │   └── supply-chain-detection.js # Package manager evidence checks
│   ├── install-gitleaks.sh # Gitleaks installer (Bash)
│   ├── install-gitleaks.ps1 # Gitleaks installer (PowerShell)
│   ├── check-headers.sh   # Security headers checker
│   └── check-headers.ps1  # Security headers checker (PowerShell)
├── examples/
│   ├── rock-house.config.json # Example scanner config
│   └── vulnerable-next-supabase/ # Demo app with intentional vulnerabilities
├── tests/
│   └── rock-house-ci.test.js # Dependency-free scanner tests
└── README.md
```

## Requirements

- [Claude Code](https://claude.ai/code) CLI or Desktop app
- No external dependencies — Rock House is pure markdown + scripts

## License

MIT

## Author

Angelo Silva — [@angellovedpl-a11y](https://github.com/angellovedpl-a11y)
