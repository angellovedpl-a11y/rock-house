# Rock House v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all effectiveness gaps identified in the v1 self-audit, raising the skill from 6.5/10 to 8+/10.

**Architecture:** Markdown skill with Bash automation. Gitleaks for secret scanning (with regex fallback), automated npm/pip audit, cross-platform header checks, and a deterministic binary scoring system. Validated against a purpose-built vulnerable testbed.

**Tech Stack:** Markdown (skill files), Bash/PowerShell (scripts), Gitleaks (secret scanning), npm audit / pip audit (supply chain)

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `SKILL.md:5` | Add Bash to allowed-tools |
| Rewrite | `vectors/secrets-exposure.md` | Gitleaks integration + 30-pattern fallback |
| Create | `scripts/install-gitleaks.sh` | Linux/Mac installer with SHA256 verification |
| Create | `scripts/install-gitleaks.ps1` | Windows installer with SHA256 verification |
| Rewrite | `vectors/supply-chain.md` | Automated npm audit + static analysis |
| Rewrite | `scripts/check-headers.sh` | Functional header checker with timeout |
| Create | `scripts/check-headers.ps1` | Windows header checker |
| Rewrite | `modes/report-template.md` | Deterministic binary scoring system |
| Rewrite | `modes/audit.md` | Integrate all automated checks |
| Modify | `modes/checklist.md` | Reference automated checks instead of manual |
| Delete | `scripts/scan-secrets.sh` | Replaced by Gitleaks |
| Delete | `scripts/scan-secrets.ps1` | Replaced by Gitleaks |
| Delete | `scripts/audit-deps.sh` | Replaced by supply-chain.md automation |
| Create | `../rock-house-testbed/` (16 files) | Vulnerable testbed for validation |

---

### Task 1: Enable Bash and Update SKILL.md

**Files:**
- Modify: `SKILL.md:5` (allowed-tools line)

- [ ] **Step 1: Update allowed-tools**

In `SKILL.md`, change line 5:

```yaml
# Before
allowed-tools: "Read Glob Grep"

# After
allowed-tools: "Read Glob Grep Bash"
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add SKILL.md
git commit -m "feat: enable Bash in allowed-tools for automated scanning"
```

---

### Task 2: Gitleaks Installation Scripts

**Files:**
- Create: `scripts/install-gitleaks.sh`
- Create: `scripts/install-gitleaks.ps1`

- [ ] **Step 1: Create Linux/Mac installer**

Create `scripts/install-gitleaks.sh`:

```bash
#!/bin/bash
# Rock House — Gitleaks Installer (Linux/Mac)
# Downloads latest gitleaks binary with SHA256 verification
# Usage: bash install-gitleaks.sh

set -e

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

LATEST=$(curl -sL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
  echo "Failed to fetch latest version. Check your internet connection."
  exit 1
fi
VERSION="${LATEST#v}"

FILENAME="gitleaks_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/${FILENAME}"
CHECKSUM_URL="https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/gitleaks_${VERSION}_checksums.txt"

echo "Downloading gitleaks ${VERSION} for ${OS}/${ARCH}..."
curl -sL "$URL" -o "/tmp/$FILENAME"
curl -sL "$CHECKSUM_URL" -o "/tmp/checksums.txt"

EXPECTED=$(grep "$FILENAME" /tmp/checksums.txt | awk '{print $1}')
ACTUAL=$(sha256sum "/tmp/$FILENAME" | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "SHA256 mismatch! Expected: $EXPECTED Got: $ACTUAL"
  echo "Download may be corrupted or tampered with. Aborting."
  rm -f "/tmp/$FILENAME" "/tmp/checksums.txt"
  exit 1
fi

echo "SHA256 verified."
tar -xzf "/tmp/$FILENAME" -C "$INSTALL_DIR" gitleaks
chmod +x "$INSTALL_DIR/gitleaks"
rm -f "/tmp/$FILENAME" "/tmp/checksums.txt"

if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  echo "Add to your PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo "gitleaks ${VERSION} installed to $INSTALL_DIR/gitleaks"
"$INSTALL_DIR/gitleaks" version
```

- [ ] **Step 2: Create Windows installer**

Create `scripts/install-gitleaks.ps1`:

```powershell
# Rock House — Gitleaks Installer (Windows)
# Downloads latest gitleaks binary with SHA256 verification
# Usage: .\install-gitleaks.ps1

$ErrorActionPreference = "Stop"

$InstallDir = "$env:LOCALAPPDATA\Programs\gitleaks"
New-Item -ItemType Directory -Force $InstallDir | Out-Null

$release = Invoke-RestMethod "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
$version = $release.tag_name -replace '^v', ''
$tag = $release.tag_name

$filename = "gitleaks_${version}_windows_x64.zip"
$url = "https://github.com/gitleaks/gitleaks/releases/download/${tag}/${filename}"
$checksumUrl = "https://github.com/gitleaks/gitleaks/releases/download/${tag}/gitleaks_${version}_checksums.txt"

$tempZip = "$env:TEMP\$filename"
$tempChecksums = "$env:TEMP\gitleaks_checksums.txt"

Write-Host "Downloading gitleaks ${version} for Windows x64..."
Invoke-WebRequest -Uri $url -OutFile $tempZip
Invoke-WebRequest -Uri $checksumUrl -OutFile $tempChecksums

$expected = (Get-Content $tempChecksums | Where-Object { $_ -match $filename }) -split '\s+' | Select-Object -First 1
$actual = (Get-FileHash $tempZip -Algorithm SHA256).Hash.ToLower()

if ($expected -ne $actual) {
    Write-Host "SHA256 mismatch! Expected: $expected Got: $actual" -ForegroundColor Red
    Write-Host "Download may be corrupted or tampered with. Aborting." -ForegroundColor Red
    Remove-Item $tempZip, $tempChecksums -Force
    exit 1
}

Write-Host "SHA256 verified." -ForegroundColor Green
Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
Remove-Item $tempZip, $tempChecksums -Force

$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "Added $InstallDir to user PATH."
}

Write-Host "gitleaks ${version} installed to $InstallDir" -ForegroundColor Green
& "$InstallDir\gitleaks.exe" version
```

- [ ] **Step 3: Commit**

```bash
cd ~/Documents/rock-house
git add scripts/install-gitleaks.sh scripts/install-gitleaks.ps1
git commit -m "feat: add Gitleaks installer scripts with SHA256 verification"
```

---

### Task 3: Rewrite secrets-exposure.md with Gitleaks + Fallback

**Files:**
- Rewrite: `vectors/secrets-exposure.md`

- [ ] **Step 1: Replace entire file**

Replace `vectors/secrets-exposure.md` with the new content that implements the Gitleaks-first flow from the spec. The file must contain:

1. **Gitleaks detection flow** — check PATH, offer install, run with --report-format json
2. **Git history scan** — `--log-opts="--all"` with 60s timeout
3. **False positive filtering** — skip ANON/PUBLIC vars, respect .gitleaksignore
4. **Output safety** — NEVER copy the `match` field from Gitleaks JSON
5. **Fallback regex** — all 30 patterns from the spec (cloud, code platforms, payment, AI, communication, infrastructure, auth/crypto, client-side exposure)
6. **Fallback limitation notice** — "Scan de historico indisponivel sem Gitleaks"
7. **Severity mapping** — Gitleaks severity → Rock House severity
8. **Keep existing sections** — VEC-SEC-02 (Security Headers) and VEC-SEC-03 (CORS) stay unchanged

Write as a single Markdown file structured:

```markdown
# Vector Module: Secrets & Exposure

Detects leaked secrets, missing security headers, and CORS misconfigurations.

## VEC-SEC-01: Secrets in Code

### Primary: Gitleaks Scan

[Gitleaks detection flow — check PATH, install offer, run commands,
 history scan with timeout, false positive filtering, output safety rules,
 severity mapping table]

### Fallback: Regex Patterns (when Gitleaks unavailable)

[All 30 regex patterns organized by category, with limitation notice]

### NEXT_PUBLIC_ Exposure
[Existing section — keep as-is]

### .env Files in Git
[Existing section — keep as-is]

### Severity Assignment
[Updated table covering both Gitleaks and fallback findings]

### Fix Suggestions
[Existing section — keep as-is]

---

## VEC-SEC-02: Security Headers
[Keep entire existing section unchanged]

---

## VEC-SEC-03: CORS Misconfiguration
[Keep entire existing section unchanged]
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add vectors/secrets-exposure.md
git commit -m "feat: rewrite secrets detection with Gitleaks + 30-pattern fallback"
```

---

### Task 4: Rewrite supply-chain.md with Automated Scanning

**Files:**
- Rewrite: `vectors/supply-chain.md`

- [ ] **Step 1: Replace entire file**

Replace `vectors/supply-chain.md` with automated scanning flow. The file must contain:

1. **Package manager detection** — check for package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock
2. **Automated audit** — run `npm audit --json` (timeout 30s), parse JSON output extracting vulnerabilities object; `pip audit --format=json` with fallback notice
3. **Static analysis** — read package.json/requirements.txt for unpinned versions ("*", "latest", ">="), known compromised packages (event-stream, ua-parser-js, colors@1.4.1+, faker@6.6.6, node-ipc@10.1.1+, flatmap-stream, coa@2.0.3+, rc@1.2.9+), curated typosquatting list (lodahs, axois, expresss, reqeusts, reeact, momnet, undersocre, chak-ra, angualr, babbel, wepback, boostrap)
4. **Severity mapping** — npm critical→Critico, high→Alto, moderate→Medio, low→Baixo; compromised→Critico; typosquatting→Alto; lockfile absent→Medio; unpinned→Medio
5. **Fallbacks** — yarn/pnpm → static analysis only; pip-audit not installed → static analysis + warning
6. **Lockfile check** — `git ls-files | grep -E '(package-lock|yarn\.lock|pnpm-lock|Pipfile\.lock|poetry\.lock)'`

Structure:

```markdown
# Vector Module: Supply Chain

Detects dependency vulnerabilities, compromised packages, and typosquatting.

## VEC-SUP-01: Automated Dependency Audit

### Step 1: Detect Package Manager
[Detection logic with file checks]

### Step 2: Run Audit (via Bash)
[npm audit --json with parsing instructions, pip audit with fallback]

### Step 3: Static Analysis (via Read)
[Unpinned versions, compromised packages list, typosquatting list]

### Severity Assignment
[Mapping table]

### Fix Suggestions
[npm audit fix, pip freeze, lockfile commit, package removal]
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add vectors/supply-chain.md
git commit -m "feat: rewrite supply chain with automated npm/pip audit"
```

---

### Task 5: Rewrite Header Check Scripts

**Files:**
- Rewrite: `scripts/check-headers.sh`
- Create: `scripts/check-headers.ps1`

- [ ] **Step 1: Rewrite check-headers.sh with timeout**

Replace `scripts/check-headers.sh`:

```bash
#!/bin/bash
# Rock House — Security Headers Checker
# Tests security headers on a live URL
# Usage: bash check-headers.sh <url>

URL="$1"

if [ -z "$URL" ]; then
  echo "Usage: bash check-headers.sh https://your-site.com"
  exit 1
fi

echo "Rock House — Checking security headers for $URL"
echo "================================================"

HEADERS=$(curl -sI --max-time 10 "$URL" 2>/dev/null)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ] || [ -z "$HEADERS" ]; then
  echo "ERROR: Could not reach $URL (timeout or connection failed)"
  exit 1
fi

STATUS=$(echo "$HEADERS" | head -1 | tr -d '\r')
echo "Status: $STATUS"
echo ""

PASS=0
FAIL=0

check_header() {
  local name="$1"
  local display="$2"
  local value
  value=$(echo "$HEADERS" | grep -i "^$name:" | head -1 | sed "s/^[^:]*: //" | tr -d '\r')
  if [ -n "$value" ]; then
    echo "PASS $display: $value"
    PASS=$((PASS+1))
  else
    echo "FAIL $display: MISSING"
    FAIL=$((FAIL+1))
  fi
}

check_header "strict-transport-security" "HSTS"
check_header "x-frame-options" "X-Frame-Options"
check_header "x-content-type-options" "X-Content-Type-Options"
check_header "content-security-policy" "CSP"
check_header "referrer-policy" "Referrer-Policy"
check_header "permissions-policy" "Permissions-Policy"

echo ""
echo "================================================"
echo "Results: $PASS passed, $FAIL missing"
```

- [ ] **Step 2: Create check-headers.ps1**

Create `scripts/check-headers.ps1`:

```powershell
# Rock House — Security Headers Checker (Windows)
# Tests security headers on a live URL
# Usage: .\check-headers.ps1 -Url https://your-site.com

param([Parameter(Mandatory)][string]$Url)

Write-Host "Rock House — Checking security headers for $Url"
Write-Host "================================================"

try {
    $response = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec 10 -UseBasicParsing
} catch {
    $curlAvailable = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlAvailable) {
        $raw = & curl.exe -sI --max-time 10 $Url 2>$null
        if (-not $raw) {
            Write-Host "ERROR: Could not reach $Url" -ForegroundColor Red
            exit 1
        }
        $headers = @{}
        foreach ($line in $raw -split "`r?`n") {
            if ($line -match "^([^:]+):\s*(.+)$") {
                $headers[$matches[1].Trim().ToLower()] = $matches[2].Trim()
            }
        }
    } else {
        Write-Host "ERROR: Could not reach $Url" -ForegroundColor Red
        exit 1
    }
}

if ($response) {
    $headers = @{}
    foreach ($key in $response.Headers.Keys) {
        $headers[$key.ToLower()] = $response.Headers[$key]
    }
}

Write-Host "Status: $($response.StatusCode)" -ForegroundColor Cyan
Write-Host ""

$pass = 0; $fail = 0

$required = @(
    @{ Name = "strict-transport-security"; Display = "HSTS" },
    @{ Name = "x-frame-options"; Display = "X-Frame-Options" },
    @{ Name = "x-content-type-options"; Display = "X-Content-Type-Options" },
    @{ Name = "content-security-policy"; Display = "CSP" },
    @{ Name = "referrer-policy"; Display = "Referrer-Policy" },
    @{ Name = "permissions-policy"; Display = "Permissions-Policy" }
)

foreach ($h in $required) {
    $value = $headers[$h.Name]
    if ($value) {
        Write-Host "PASS $($h.Display): $value" -ForegroundColor Green
        $pass++
    } else {
        Write-Host "FAIL $($h.Display): MISSING" -ForegroundColor Red
        $fail++
    }
}

Write-Host ""
Write-Host "================================================"
Write-Host "Results: $pass passed, $fail missing"
```

- [ ] **Step 3: Commit**

```bash
cd ~/Documents/rock-house
git add scripts/check-headers.sh scripts/check-headers.ps1
git commit -m "feat: rewrite header checker with timeout and Windows support"
```

---

### Task 6: Rewrite report-template.md with Deterministic Score

**Files:**
- Rewrite: `modes/report-template.md`

- [ ] **Step 1: Replace entire file**

Replace `modes/report-template.md`. Keep the existing Report Header, Severity Definitions, Individual Finding Format, Kill-Chain Section, and Summary Table sections. Replace the Score Calculation section (lines 107-121) with the new deterministic system:

```markdown
## Score Calculation — Deterministic Binary Checks

The score is calculated from 35 binary checks (pass/fail). Checks not applicable
to the detected stack are REMOVED from the total (not counted as pass or fail).

### Check Registry

#### SECRETS (weight 3x — avg CVSS 9.1)

| ID | Check | Pass when |
|----|-------|-----------|
| S1 | No secrets in current code | Gitleaks / fallback regex finds 0 matches |
| S2 | No secrets in git history | Gitleaks --all finds 0 matches |
| S3 | .env in .gitignore | .gitignore contains .env* pattern |
| S4 | NEXT_PUBLIC_ safe only | No NEXT_PUBLIC_ with SERVICE/SECRET/PRIVATE/ADMIN |
| S5 | No private keys in repo | No -----BEGIN PRIVATE KEY patterns found |

#### INJECTION (weight 2x — avg CVSS 8.6)

| ID | Check | Pass when |
|----|-------|-----------|
| I1 | No SQL concatenation | No string-interpolated SQL queries found |
| I2 | No innerHTML with user input | No innerHTML assignments from external data |
| I3 | No dangerouslySetInnerHTML with user input | No unsanitized dangerouslySetInnerHTML |
| I4 | No eval with external input | No eval()/setTimeout()/setInterval() with user data |
| I5 | CSP header configured | Content-Security-Policy found in config or headers |

#### AUTH & ACCESS (weight 2x — avg CVSS 8.0)

| ID | Check | Pass when |
|----|-------|-----------|
| A1 | Service key server-only | No service_role/admin key in client-side files |
| A2 | RLS enabled on all tables | Every table in migrations has ENABLE ROW LEVEL SECURITY |
| A3 | Ownership check on ID endpoints | Endpoints with params.id include user_id/auth check |
| A4 | JWT with expiration | All jwt.sign() calls include expiresIn |
| A5 | Cookies with HttpOnly+Secure+SameSite | Cookie config includes all three flags |

#### SUPPLY CHAIN (weight 1x — avg CVSS 6.5)

| ID | Check | Pass when |
|----|-------|-----------|
| D1 | Lockfile committed | git ls-files shows lockfile |
| D2 | No critical audit CVEs | npm audit --json reports 0 critical |
| D3 | No compromised packages | No packages from compromised list found |
| D4 | Versions pinned | No "*", "latest", or ">=" in dependencies |

#### HEADERS (weight 1x — avg CVSS 5.3)

| ID | Check | Pass when |
|----|-------|-----------|
| H1 | HSTS configured | Strict-Transport-Security in config/headers |
| H2 | X-Frame-Options configured | X-Frame-Options in config/headers |
| H3 | X-Content-Type-Options configured | nosniff in config/headers |
| H4 | CORS restrictive | No origin: '*' or origin: true |
| H5 | Referrer-Policy configured | Referrer-Policy in config/headers |

#### NETWORK (weight 2x — avg CVSS 8.0)

| ID | Check | Pass when |
|----|-------|-----------|
| N1 | SSRF protected | URL fetch endpoints validate/blocklist URLs |
| N2 | Upload validates type | File type checked by magic bytes, not extension |
| N3 | Filenames sanitized | Uploaded files renamed to UUID |
| N4 | No open redirect | Redirect endpoints validate destination is relative |

#### AI (weight 2x — avg CVSS 8.0, skip if no AI detected)

| ID | Check | Pass when |
|----|-------|-----------|
| AI1 | System prompt hardened | System prompt includes boundary instructions |
| AI2 | AI output not executed as code | No eval/db.query on AI response |
| AI3 | AI has no admin DB access | AI context uses anon/user key, not service key |
| AI4 | Rate limit on AI endpoints | Rate limiting middleware on AI routes |

### Score Formula

```
passed_weighted = sum(passed_checks × category_weight)
applicable_weighted = sum(applicable_checks × category_weight)

score_base = (passed_weighted / applicable_weighted) × 10

# Kill-chain depth bonus
bonus = +0.5 for each critical risk with ≥3 independent defense layers
bonus = min(bonus, 2.0)

score_final = min(10, score_base + bonus)

# Complexity threshold
if applicable_checks < 12:
    score_final = min(8.0, score_final)
    # Note: "Projeto simples — menos superficie de ataque testada"
```

### Score Scale

| Score | Level | Metaphor |
|-------|-------|----------|
| 0 – 3.0 | Casa de palha | O lobo derruba com um sopro |
| 3.1 – 6.0 | Casa de madeira | Aguenta um pouco, mas cai |
| 6.1 – 8.0 | Casa de pedra | O lobo nao derruba |
| 8.1 – 10 | Fortaleza | Nem com dinamite |

### Presenting the Score

After all findings, present the score table:

```markdown
## Score Deterministico

| Categoria | Checks | Passaram | Peso | Pontos |
|-----------|--------|----------|------|--------|
| Secrets | [N/5] | [n] | 3x | [n×3] / [N×3] |
| Injection | [N/5] | [n] | 2x | [n×2] / [N×2] |
| Auth | [N/5] | [n] | 2x | [n×2] / [N×2] |
| Supply | [N/4] | [n] | 1x | [n×1] / [N×1] |
| Headers | [N/5] | [n] | 1x | [n×1] / [N×1] |
| Network | [N/4] | [n] | 2x | [n×2] / [N×2] |
| AI | [N/4] | [n] | 2x | [n×2] / [N×2] |
| **Total** | **[T]** | **[P]** | | **[Pw] / [Aw]** |

**Score base:** [X.X] / 10
**Bonus kill-chain:** +[X.X]
**Score final:** [X.X] / 10 — [metaphor emoji + name]
```
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add modes/report-template.md
git commit -m "feat: deterministic binary score system with CVSS-weighted categories"
```

---

### Task 7: Rewrite audit.md to Integrate All Automated Checks

**Files:**
- Rewrite: `modes/audit.md`

- [ ] **Step 1: Replace entire file**

Rewrite `modes/audit.md` to integrate the new automated flows. The new audit mode has these steps:

**Step 1:** Receive stack context (unchanged from v1)
**Step 2:** Load vector modules (unchanged from v1)
**Step 3:** Load stack rules (unchanged from v1)
**Step 4:** Run automated scans (NEW)
  - 4a. Secrets scan — Gitleaks or fallback regex (per vectors/secrets-exposure.md)
  - 4b. Supply chain audit — npm audit --json / static analysis (per vectors/supply-chain.md)
  - 4c. Headers check — static analysis of config files + optional dynamic curl (per spec section 4)
    - Detect managed platforms (Vercel/Netlify) → downgrade "absent in config" from Alto to Baixo
**Step 5:** Scan project code for pattern-based vectors (same as v1 Step 4 — injection, auth, network)
**Step 6:** Run kill-chain analysis (unchanged from v1)
**Step 7:** Calculate deterministic score (NEW — per modes/report-template.md check registry)
  - Track each of the 35 checks as pass/fail
  - Mark non-applicable checks as N/A (excluded from total)
  - Apply formula from report-template.md
**Step 8:** Generate report (updated — include score table)
**Step 9:** Offer follow-up (unchanged from v1)

Key changes from v1:
- Steps 4a-4c are NEW automated scans via Bash
- Step 7 is NEW score calculation
- Step 5 (code scanning) now ALSO records pass/fail for the 35 checks as it scans
- The report includes the deterministic score table

File exclusions section: unchanged from v1.
Edge cases section: unchanged from v1.

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add modes/audit.md
git commit -m "feat: integrate automated scans and deterministic scoring into audit mode"
```

---

### Task 8: Update checklist.md to Reference Automated Checks

**Files:**
- Modify: `modes/checklist.md`

- [ ] **Step 1: Add automation notes to each risk category**

In `modes/checklist.md`, add a line after each risk category table indicating which checks are now automated:

For "RISCO: Vazamento de Secrets" (after line 36):
```markdown
**Automacao:** Items 1, 3, 4 are verified automatically via Gitleaks/regex scan and Grep.
```

For "RISCO: Injection" (after line 48):
```markdown
**Automacao:** Item 8 (CSP) is verified automatically via headers check.
Items 6, 7, 9 are verified via code pattern scanning.
```

For "RISCO: Dependencias" (after line 97):
```markdown
**Automacao:** Items 24, 25 are verified automatically via npm audit / pip audit.
Item 26 is verified via lockfile check.
```

For "RISCO: Headers e Infraestrutura" (after line 86):
```markdown
**Automacao:** Items 19-22 are verified automatically via static config analysis.
Note: For Vercel/Netlify projects, some headers are added by the platform.
Use dynamic check (with URL) for accurate results.
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/rock-house
git add modes/checklist.md
git commit -m "feat: add automation references to checklist mode"
```

---

### Task 9: Remove Obsolete Scripts

**Files:**
- Delete: `scripts/scan-secrets.sh`
- Delete: `scripts/scan-secrets.ps1`
- Delete: `scripts/audit-deps.sh`

- [ ] **Step 1: Remove files**

```bash
cd ~/Documents/rock-house
git rm scripts/scan-secrets.sh scripts/scan-secrets.ps1 scripts/audit-deps.sh
```

- [ ] **Step 2: Commit**

```bash
git commit -m "chore: remove obsolete scripts replaced by Gitleaks and automated supply chain"
```

---

### Task 10: Create Testbed — Project Structure

**Files:**
- Create: `../rock-house-testbed/package.json`
- Create: `../rock-house-testbed/.env`
- Create: `../rock-house-testbed/.gitignore`
- Create: `../rock-house-testbed/next.config.js`

- [ ] **Step 1: Initialize testbed repo**

```bash
cd ~/Documents
mkdir rock-house-testbed && cd rock-house-testbed
git init
```

- [ ] **Step 2: Create package.json with planted vulnerabilities**

Create `package.json`:

```json
{
  "name": "rock-house-testbed",
  "version": "0.0.1",
  "private": true,
  "description": "Intentionally vulnerable project for Rock House validation",
  "dependencies": {
    "next": "15.3.0",
    "react": "19.1.0",
    "react-dom": "19.1.0",
    "@supabase/supabase-js": "^2.49.0",
    "jsonwebtoken": "*",
    "multer": ">=1.0.0",
    "openai": "latest",
    "event-stream": "4.0.1",
    "axois": "1.0.0",
    "cors": "^2.8.5",
    "express": "^4.21.0"
  }
}
```

Planted vulnerabilities:
- `event-stream` — known compromised package (gabarito #13)
- `axois` — typosquatting of axios (gabarito #14)
- No lockfile will be created (gabarito #15)
- `"*"`, `"latest"`, `">="` unpinned versions

- [ ] **Step 3: Create .env committed to git (intentional)**

Create `.env`:

```
DATABASE_URL=postgres://admin:supersecret@db.example.com:5432/mydb
NEXT_PUBLIC_SUPABASE_URL=https://abc123.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYzEyMyIsInJvbGUiOiJhbm9uIn0.fake
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYzEyMyIsInJvbGUiOiJzZXJ2aWNlX3JvbGUifQ.fake
OPENAI_API_KEY=sk-fake1234567890abcdefghijklmnopqrstuvwxyz1234567890
```

Planted vulnerabilities:
- NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY exposed (gabarito #4)
- .env will be committed to git (gabarito #3)

- [ ] **Step 4: Create .gitignore WITHOUT .env (intentional)**

Create `.gitignore`:

```
node_modules/
.next/
dist/
build/
```

Planted vulnerability: .env NOT in .gitignore (gabarito #3)

- [ ] **Step 5: Create next.config.js with zero headers**

Create `next.config.js`:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {};

module.exports = nextConfig;
```

Planted vulnerability: no security headers configured (gabarito #16)

- [ ] **Step 6: Commit**

```bash
cd ~/Documents/rock-house-testbed
git add -A
git commit -m "init: testbed project structure with planted vulnerabilities"
```

---

### Task 11: Create Testbed — Source Files (Secrets + Injection)

**Files:**
- Create: `../rock-house-testbed/src/config/secrets.ts`
- Create: `../rock-house-testbed/src/lib/db.ts`
- Create: `../rock-house-testbed/src/app/page.tsx`

- [ ] **Step 1: Create secrets.ts with hardcoded keys**

Create `src/config/secrets.ts`:

```typescript
export const AWS_KEY = "AKIA1234567890ABCDEF";
export const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
export const STRIPE_KEY = "sk_live_FAKE_EXAMPLE_KEY_HERE";
export const INTERNAL_PASSWORD = "admin123secure";
```

Planted vulnerabilities:
- AWS key AKIA pattern (gabarito #1)
- Stripe sk_live_ key (gabarito #2)

- [ ] **Step 2: Create db.ts with SQL injection**

Create `src/lib/db.ts`:

```typescript
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function getUserById(id: string) {
  const result = await pool.query(
    `SELECT * FROM users WHERE id = ${id}`
  );
  return result.rows[0];
}

export async function searchUsers(name: string) {
  const result = await pool.query(
    "SELECT * FROM users WHERE name = '" + name + "'"
  );
  return result.rows;
}
```

Planted vulnerability: SQL concatenation (gabarito #6)

- [ ] **Step 3: Create page.tsx with XSS**

Create `src/app/page.tsx`:

```tsx
'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';

export default function HomePage() {
  const searchParams = useSearchParams();
  const [comment, setComment] = useState('');

  useEffect(() => {
    const q = searchParams.get('q');
    if (q) {
      document.getElementById('search-results')!.innerHTML = q;
    }
  }, [searchParams]);

  return (
    <div>
      <div id="search-results"></div>
      <div dangerouslySetInnerHTML={{ __html: comment }} />
      <textarea onChange={(e) => setComment(e.target.value)} />
    </div>
  );
}
```

Planted vulnerabilities:
- innerHTML with user input from URL params (gabarito #5)
- dangerouslySetInnerHTML with user input (gabarito #5 — bonus detection)

- [ ] **Step 4: Commit**

```bash
cd ~/Documents/rock-house-testbed
git add src/config/secrets.ts src/lib/db.ts src/app/page.tsx
git commit -m "feat: add secrets, db, and page with planted vulnerabilities"
```

---

### Task 12: Create Testbed — Source Files (Auth + AI + Network)

**Files:**
- Create: `../rock-house-testbed/src/lib/supabase.ts`
- Create: `../rock-house-testbed/src/lib/ai.ts`
- Create: `../rock-house-testbed/src/app/api/users/route.ts`
- Create: `../rock-house-testbed/src/app/api/login/route.ts`
- Create: `../rock-house-testbed/src/app/api/upload/route.ts`
- Create: `../rock-house-testbed/cors-server.js`
- Create: `../rock-house-testbed/supabase/migrations/001_tables.sql`

- [ ] **Step 1: Create supabase.ts with service key on client**

Create `src/lib/supabase.ts`:

```typescript
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseServiceKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!;

export const supabase = createClient(supabaseUrl, supabaseServiceKey);
```

Planted vulnerability: service role key in client code (gabarito #8)

- [ ] **Step 2: Create ai.ts with prompt injection + eval**

Create `src/lib/ai.ts`:

```typescript
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function chat(userMessage: string) {
  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'user', content: userMessage },
    ],
  });

  const aiOutput = response.choices[0].message.content!;
  const result = eval(aiOutput);
  return result;
}
```

Planted vulnerabilities:
- No system prompt / no hardening (gabarito #21)
- eval(aiResponse) — code execution (gabarito #7, #22)

- [ ] **Step 3: Create users/route.ts with IDOR**

Create `src/app/api/users/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get('id');

  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();

  return NextResponse.json(data);
}
```

Planted vulnerability: no ownership check — any user can read any profile (gabarito #9)

- [ ] **Step 4: Create login/route.ts with JWT issues**

Create `src/app/api/login/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

export async function POST(req: NextRequest) {
  const { email, password } = await req.json();

  const user = { id: '123', email };
  const token = jwt.sign({ userId: user.id }, 'mysecretkey');

  const response = NextResponse.json({ token });
  response.cookies.set('session', token, {
    path: '/',
  });

  return response;
}
```

Planted vulnerabilities:
- JWT without expiresIn (gabarito #10)
- Cookies without HttpOnly, Secure, SameSite (gabarito #11)
- Weak JWT secret 'mysecretkey'

- [ ] **Step 5: Create upload/route.ts with file upload vulnerabilities**

Create `src/app/api/upload/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { writeFile } from 'fs/promises';
import path from 'path';

export async function POST(req: NextRequest) {
  const formData = await req.formData();
  const file = formData.get('file') as File;
  const url = formData.get('url') as string;

  if (url) {
    const response = await fetch(url);
    const data = await response.text();
    return NextResponse.json({ data });
  }

  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);

  const uploadPath = path.join(process.cwd(), 'public/uploads', file.name);
  await writeFile(uploadPath, buffer);

  return NextResponse.json({ path: `/uploads/${file.name}` });
}
```

Planted vulnerabilities:
- No file type validation (gabarito #18)
- User filename used directly — path traversal (gabarito #19)
- fetch(url) without validation — SSRF (gabarito #20)

- [ ] **Step 6: Create cors-server.js with CORS misconfiguration**

Create `cors-server.js`:

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
  origin: '*',
  credentials: true,
}));

app.get('/api/data', (req, res) => {
  res.json({ sensitive: 'data' });
});

app.listen(3001);
```

Planted vulnerability: CORS origin: * with credentials: true (gabarito #17)

- [ ] **Step 7: Create migration without RLS**

Create `supabase/migrations/001_tables.sql`:

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  role TEXT DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  title TEXT NOT NULL,
  content TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- No RLS enabled on either table
```

Planted vulnerability: tables without RLS (gabarito #12)

- [ ] **Step 8: Create gabarito file**

Create `GABARITO.md`:

```markdown
# Rock House Testbed — Gabarito

22 planted vulnerabilities. Rock House v2 must detect >= 20 (90%).

| # | Category | File | Vulnerability | Expected |
|---|----------|------|--------------|----------|
| 1 | Secrets | src/config/secrets.ts:1 | AWS key AKIA pattern | Critico |
| 2 | Secrets | src/config/secrets.ts:3 | Stripe sk_live_ key | Critico |
| 3 | Secrets | .env (git tracked) | .env committed to git | Critico |
| 4 | Secrets | .env:4 | NEXT_PUBLIC_SERVICE_ROLE | Critico |
| 5 | Injection | src/app/page.tsx:11 | innerHTML = user input | Critico |
| 6 | Injection | src/lib/db.ts:7 | SQL concatenation | Critico |
| 7 | Injection | src/lib/ai.ts:13 | eval(aiResponse) | Critico |
| 8 | Auth | src/lib/supabase.ts:4 | Service key in client | Critico |
| 9 | Auth | src/app/api/users/route.ts | IDOR no ownership | Alto |
| 10 | Auth | src/app/api/login/route.ts:7 | JWT no expiration | Alto |
| 11 | Auth | src/app/api/login/route.ts:9 | Cookies no flags | Alto |
| 12 | Auth | supabase/migrations/001.sql | Tables without RLS | Critico |
| 13 | Supply | package.json | event-stream compromised | Critico |
| 14 | Supply | package.json | axois typosquatting | Alto |
| 15 | Supply | (missing) | No lockfile | Medio |
| 16 | Headers | next.config.js | Zero security headers | Alto |
| 17 | Headers | cors-server.js:6 | CORS * + credentials | Critico |
| 18 | Network | src/app/api/upload/route.ts | No file type validation | Alto |
| 19 | Network | src/app/api/upload/route.ts:17 | User filename direct | Critico |
| 20 | Network | src/app/api/upload/route.ts:8 | SSRF fetch(url) | Critico |
| 21 | AI | src/lib/ai.ts:8 | No system prompt | Alto |
| 22 | AI | src/lib/ai.ts:13 | eval(AI output) | Critico |

## Pass Criteria

- Detection rate >= 90% (>= 20/22)
- Zero false positive criticals
- Score reproducible (2 runs = same number)
- Every category has >= 1 hit
```

- [ ] **Step 9: Commit testbed**

```bash
cd ~/Documents/rock-house-testbed
git add -A
git commit -m "feat: complete testbed with 22 planted vulnerabilities and gabarito"
```

---

### Task 13: Run Validation

This task is manual — run after all previous tasks are complete.

- [ ] **Step 1: Run Rock House v2 audit on testbed**

Open the testbed in Claude Code and invoke:
```
rock house audit
```

- [ ] **Step 2: Compare findings against GABARITO.md**

For each of the 22 planted vulnerabilities, check if Rock House found it:
- Mark as HIT if found
- Mark as MISS if not found
- Note any EXTRA findings (false positives or bonus detections)

- [ ] **Step 3: Calculate detection rate**

```
rate = hits / 22
```

Target: >= 90% (>= 20/22)

- [ ] **Step 4: Verify score reproducibility**

Run the audit a second time. Compare score_final from both runs. They must be identical.

- [ ] **Step 5: If rate < 90%, fix and re-test**

For each MISS:
1. Identify which vector module should have caught it
2. Check if the pattern is defined in the module
3. If missing, add the pattern
4. Re-run audit on testbed
5. Repeat until >= 90%

- [ ] **Step 6: Commit any fixes**

```bash
cd ~/Documents/rock-house
git add -A
git commit -m "fix: patch detection gaps found during testbed validation"
```
