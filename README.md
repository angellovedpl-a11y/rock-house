# Rock House

> Build your code in a house of stone, not straw.

Security audit and defense-in-depth skill for [Claude Code](https://claude.ai/code). Analyzes web projects for vulnerabilities using independent defense layers — inspired by the Three Little Pigs.

## What It Does

Rock House scans your code for 15 attack vectors across 5 categories, tests if your defenses hold independently (kill-chain analysis), and generates a severity-graded report in Portuguese (PT-BR).

**3 modes:**
- `/rock-house audit` — scan existing code for vulnerabilities
- `/rock-house checklist` — pre-deploy security gate
- `/rock-house preventive [feature]` — defense plan BEFORE coding

**15 attack vectors:**

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
git clone https://github.com/angellovedpl/rock-house.git ~/Documents/rock-house

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
run security checklist before deploy  → runs Checklist mode
plan defenses for login feature       → runs Preventive mode
```

Or invoke directly: `/rock-house audit`

## Score System

Every audit produces a 0-10 score:

| Score | Level | Meaning |
|-------|-------|---------|
| 0-3 | Straw House | No defense — the wolf blows it down |
| 4-6 | Wood House | Partial defense — holds for a bit |
| 7-8 | Stone House | Solid defense — wolf can't get in |
| 9-10 | Fortress | Defense in depth — not even with dynamite |

**Deploy safe: score >= 7 (stone house)**

## Kill-Chain Analysis

Rock House doesn't just check if defenses exist — it tests if each layer holds **independently**. Three questions per defense:

1. If ONLY this defense existed, would the attack be blocked?
2. If this defense FAILS, what's the next layer?
3. Are there at least 2 independent layers for this risk?

## Project Structure

```
rock-house/
├── SKILL.md              # Entry point (101 lines)
├── modes/
│   ├── audit.md           # 7-step audit engine
│   ├── checklist.md       # Pre-deploy gate (30 items)
│   ├── preventive.md      # Defense planning tables
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
│   ├── scan-secrets.sh    # Secret scanner (Bash)
│   ├── scan-secrets.ps1   # Secret scanner (PowerShell)
│   ├── audit-deps.sh      # Dependency auditor
│   └── check-headers.sh   # Security headers checker
└── README.md
```

## Requirements

- [Claude Code](https://claude.ai/code) CLI or Desktop app
- No external dependencies — Rock House is pure markdown + scripts

## License

MIT

## Author

Angelo Silva — [@angellovedpl](https://github.com/angellovedpl)
