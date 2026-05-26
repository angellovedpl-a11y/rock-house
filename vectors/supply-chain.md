# Vector Module: Supply Chain

Detects dependency vulnerabilities, typosquatting risks, and outdated packages.

## VEC-SUP-01: Dependency Vulnerabilities

### What to Look For

#### Node.js projects

Check if `package.json` exists. If yes:
1. Look for `package-lock.json` or `yarn.lock` — if missing, flag as medium risk (no lockfile = non-deterministic installs)
2. Reference `npm audit` results — instruct Claude to tell the user to run `npm audit` and share the output
3. Check `package.json` dependencies for known problematic packages:

```
# Packages known to have security issues or be abandoned
event-stream       # supply chain attack (2018)
ua-parser-js       # hijacked (2021)
colors             # maintainer sabotage (2022)
faker              # maintainer sabotage (2022)
node-ipc           # protestware (2022)
```

#### Python projects

Check if `requirements.txt` exists. If yes:
1. Look for pinned versions (`package==1.2.3`) vs unpinned (`package`) — unpinned is riskier
2. Reference `pip audit` — instruct user to run it
3. Check for `requirements.txt` without hashes

#### Lockfile committed

Check if lockfile is tracked by git:
```bash
git ls-files | grep -E '(package-lock|yarn\.lock|pnpm-lock|Pipfile\.lock|poetry\.lock)'
```

If lockfile is NOT committed, flag it — builds are non-reproducible.

#### Typosquatting indicators

Check for common typo variations of popular packages:
```
# These are examples — Claude should use judgment
lodahs (lodash)
axois (axios)
reqeusts (requests)
expresss (express)
reeact (react)
```

Look for packages with very low download counts or recent creation dates (if detectable from package.json metadata).

### Severity Assignment

| Finding | Severity |
|---------|----------|
| Known compromised package in dependencies | 🔴 Crítico |
| npm audit / pip audit reports critical CVE | 🔴 Crítico |
| npm audit / pip audit reports high CVE | 🟠 Alto |
| No lockfile committed | 🟡 Médio |
| Unpinned versions in requirements.txt | 🟡 Médio |
| Suspected typosquatting package name | 🟠 Alto |
| npm audit reports moderate CVE | 🟢 Baixo |

### Fix Suggestions

```bash
# Run audit
npm audit
pip audit

# Fix automatically (when possible)
npm audit fix

# Pin versions in requirements.txt
pip freeze > requirements.txt

# Commit lockfile
git add package-lock.json
git commit -m "chore: add lockfile for reproducible builds"
```

### What Claude Should Tell the User

Since Claude cannot run `npm audit` or `pip audit` directly during a skill scan (these require shell access), instruct the user:

> "Recomendo rodar `npm audit` (ou `pip audit`) no terminal e compartilhar o resultado comigo. Vou analisar as vulnerabilidades encontradas e incluir no relatório."

If the user shares audit output, parse it and include findings in the report with appropriate severity.
