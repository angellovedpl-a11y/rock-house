# Vector Module: Supply Chain

Detects dependency vulnerabilities, compromised packages, and typosquatting.

## VEC-SUP-01: Automated Dependency Audit

### Step 1: Detect Package Manager

Check which package manager the project uses:

```
Glob("package-lock.json")  → npm
Glob("yarn.lock")          → yarn (static analysis only)
Glob("pnpm-lock.yaml")     → pnpm (static analysis only)
Glob("requirements.txt")   → Python (pip)
Glob("Pipfile.lock")       → Python (pipenv)
Glob("poetry.lock")        → Python (poetry)
```

If NO lockfile found but `package.json` or `requirements.txt` exists:
- Finding: "Lockfile ausente — builds nao-reproduziveis"
- Severity: Medio
- Check D1: FAIL

If no `package.json` AND no `requirements.txt` AND no `Pipfile` AND no `pyproject.toml`:
- Skip this entire vector module (no dependencies to audit)

### Step 2: Run Audit (via Bash)

#### npm projects

If `package-lock.json` exists, run:

```bash
npm audit --json 2>/dev/null
```

Timeout: 30 seconds. If timeout or error, fall through to static analysis.

Parse the JSON output:

```
.vulnerabilities → for each entry:
  - name: package name
  - severity: critical | high | moderate | low
  - via: attack vector description
  - fixAvailable: boolean or object

Map to Rock House findings:
  critical → Critico
  high     → Alto
  moderate → Medio
  low      → Baixo
```

Track check D2: PASS if 0 critical vulnerabilities, FAIL otherwise.

#### Python projects

If `pip-audit` is available (check with `pip-audit --version`), run:

```bash
pip-audit --format=json 2>/dev/null
```

Timeout: 30 seconds.

Parse JSON: each entry has `name`, `version`, `vulns[]` with `id` (CVE) and `fix_versions`.

If `pip-audit` is NOT installed:
- Warning: "pip-audit nao instalado — usando apenas analise estatica. Instale com: pip install pip-audit"
- Proceed to static analysis only.

#### yarn / pnpm projects

Do NOT run `yarn audit` or `pnpm audit` — their JSON output formats are inconsistent across versions. Use static analysis only.

Warning: "Audit automatico nao suportado para yarn/pnpm — usando analise estatica."

### Step 3: Static Analysis (via Read)

Always run this step regardless of audit results. Uses Read and Grep only (no Bash needed).

#### 3a. Unpinned Versions

Read `package.json` and check `dependencies` + `devDependencies` for:

```
"*"       → any version (Medio)
"latest"  → always latest (Medio)
">="      → unbounded upper range (Medio)
```

Read `requirements.txt` and check for lines WITHOUT `==`:

```
package        → unpinned (Medio)
package>=1.0   → unbounded (Medio)
package~=1.0   → acceptable (PASS)
package==1.0.0 → pinned (PASS)
```

Track check D4: PASS if all production dependencies are pinned, FAIL otherwise.

#### 3b. Known Compromised Packages

Search `package.json` for these packages (hardcoded list):

```
event-stream        # supply chain attack — malicious code in flatmap-stream dep (2018)
ua-parser-js        # hijacked — crypto miner injected (2021)
colors@1.4.1+       # maintainer sabotage — infinite loop added (2022)
faker@6.6.6         # maintainer sabotage — lorem ipsum output (2022)
node-ipc@10.1.1+    # protestware — file deletion based on locale (2022)
flatmap-stream       # malicious dependency of event-stream
coa@2.0.3+          # hijacked — malware injected (2021)
rc@1.2.9+           # hijacked — malware injected (2021)
```

Any match → Critico finding.

Track check D3: PASS if 0 compromised packages found, FAIL otherwise.

#### 3c. Typosquatting Detection

Search `package.json` dependencies for these known typosquats (curated list, NOT Levenshtein):

```
lodahs       → should be lodash
axois        → should be axios
expresss     → should be express
reqeusts     → should be requests
reeact       → should be react
momnet       → should be moment
undersocre   → should be underscore
chak-ra      → should be chakra
angualr      → should be angular
babbel       → should be babel
wepback      → should be webpack
boostrap     → should be bootstrap
```

Any match → Alto finding: "Possivel typosquatting: [found] → voce quis dizer [correct]?"

#### 3d. Malicious Install Scripts

Check `package.json` of the project AND key dependencies for lifecycle scripts
that execute code during `npm install`:

```json
"scripts": {
  "preinstall": "...",
  "install": "...",
  "postinstall": "..."
}
```

These scripts run automatically with full system access during installation.
Compromised packages use them to exfiltrate env vars, install backdoors, or
download payloads.

**What to search for:**

In project `package.json`:
```
"preinstall"
"postinstall"
```

If found, read the script content. Flag if it:
- Downloads from external URLs (`curl`, `wget`, `fetch`, `http.get`)
- Reads environment variables (`process.env`, `$ENV`)
- Writes to directories outside the project (`/tmp`, `/etc`, `$HOME`)
- Executes obfuscated code (base64 decode, eval of hex strings)

In `node_modules/` — do NOT scan entire node_modules (too slow), but check the
project's DIRECT dependencies that are less-known (< 1 year old, single maintainer,
no README). Read their `package.json` for install scripts.

**Also check for:**

```
"scripts": {
  "prepare": "..."  // runs on install from git
}
```

### Severity Assignment

| Finding | Severity | Check |
|---------|----------|-------|
| Install script downloading external payload | Critico | — |
| Install script reading env vars | Alto | — |
| Install script with obfuscated code | Critico | — |
| npm audit critical CVE | Critico | D2 FAIL |
| Known compromised package | Critico | D3 FAIL |
| npm audit high CVE | Alto | — |
| Typosquatting detected | Alto | — |
| No lockfile committed | Medio | D1 FAIL |
| Unpinned versions ("*", "latest", ">=") | Medio | D4 FAIL |
| npm audit moderate CVE | Medio | — |
| npm audit low CVE | Baixo | — |
| pip-audit not installed (warning only) | Info | — |

### Fix Suggestions

For each finding type, suggest the specific fix:

```bash
# Critical CVE in npm
npm audit fix
# If fix not available: evaluate if package can be replaced

# Compromised package
npm uninstall <package>
# Replace with maintained alternative immediately

# Typosquatting
npm uninstall <typo-package>
npm install <correct-package>

# No lockfile
npm install   # generates package-lock.json
git add package-lock.json
git commit -m "chore: add lockfile for reproducible builds"

# Unpinned versions — replace in package.json
# "*"     → "^x.y.z" (specific range)
# "latest" → "^x.y.z"
# ">="    → "^x.y.z"

# Python — pin versions
pip freeze > requirements.txt
# Or use pip-compile (pip-tools) for better management
```

### Lockfile Verification

To check if lockfile is committed to git:

```bash
git ls-files | grep -E '(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|poetry\.lock)'
```

If no output → lockfile is NOT tracked → D1 FAIL.
If output exists → D1 PASS.
