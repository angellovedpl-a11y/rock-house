# Scanner Rule Registry & Coverage-Aware Confidence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Plan-review correction pass — 2026-06-01.** Codex reviewed this plan and flagged 4 corrections, now folded in before resuming from Task 2:
> 1. **Coverage** must not call a repo "audited" when `supported` is empty → Task 4 (`evaluateCoverage`, `calculateConfidence`).
> 2. **Blind-spot detection** must be repo-wide (monorepo), not root-only → Task 4 (`detectStacks` recursive walk).
> 3. **Fingerprint** needs a stronger discriminator (`line`) so duplicate-`checkId` rules don't collapse → Task 3 (Step 5b).
> 4. **`/g` regex hardening** must live in engine code, not just a written convention → Task 1 (already implemented in commit `e87d49b`; plan code below now matches).

**Goal:** Replace the inline-regex detection core of the Rock House CI scanner with a declarative rule registry, add coverage-aware confidence, in-engine secret detection, Python/Flask rules, and rich fix packs — without breaking the 28 passing tests or the dependency-free constraint.

**Architecture:** Detection rules become declarative objects in `scripts/lib/rules/`, run by a generic engine. A coverage map downgrades confidence to `Baixa` when a project's stack has no matching rule family (killing the "approve what we didn't audit" failure mode). Findings gain a `fixPack` (before → after + command) rendered in JSON/Markdown/SARIF.

**Tech Stack:** Node.js (v20+ in CI, no external dependencies). Tests are integration-style: spawn `scripts/rock-house-ci.js` against a temp fixture and assert on the JSON report. Test runner: `node tests/rock-house-ci.test.js`.

**Spec:** `docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md`

---

## File Structure

**Create:**
- `scripts/lib/rules/engine.js` — generic rule runner: language detection, per-line matching, windowed flow confirmation, allowlist, gate-vs-finding dispatch.
- `scripts/lib/rules/coverage.js` — stack detection + coverage evaluation (supported vs blind-spot stacks).
- `scripts/lib/rules/index.js` — aggregates rule families, exposes `DETECTION_RULES`, `ruleFor`, `impactFor`, metadata `META`.
- `scripts/lib/rules/injection.js` — XSS/eval/SQLi/command-injection/SSRF/path-traversal rules.
- `scripts/lib/rules/secrets.js` — provider secret patterns + entropy heuristic.
- `scripts/lib/rules/python-flask.js` — Python/Flask rules.
- `scripts/lib/rules/headers-cors.js` — static CORS + open-redirect rules.
- `scripts/lib/rules/auth-access.js` — privileged-key + ownership rules.

**Modify:**
- `scripts/rock-house-ci.js` — `scanFiles` delegates to the engine; `addFinding` carries `fixPack`; `main` builds the coverage map; `calculateConfidence` takes coverage; report includes `coverage`.
- `scripts/lib/rules.js` — becomes a thin shim re-exporting `scripts/lib/rules/index.js` (keeps `require('./lib/rules')` callers working).
- `scripts/lib/report-formatters.js` — Cobertura section, fix-pack rendering in Markdown, fix-pack fields in SARIF.
- `tests/rock-house-ci.test.js` — new test functions registered in `run()`.
- `CLAUDE.md` — correct the "gitleaks patterns" claim.

**Reuse unchanged:** `scripts/lib/js-detection.js` (`shouldFlagInnerHtml`) is imported by the injection family.

---

## Task 1: Generic rule engine

**Files:**
- Create: `scripts/lib/rules/engine.js`
- Test: `tests/rock-house-ci.test.js` (new `testEngineMatching`)

- [ ] **Step 1: Write the failing test**

Add this function to `tests/rock-house-ci.test.js` and call `testEngineMatching();` as the first line inside `run()`:

```js
function testEngineMatching() {
  const { languageFor, runRules } = require('../scripts/lib/rules/engine');
  assert.strictEqual(languageFor('.tsx'), 'js');
  assert.strictEqual(languageFor('.py'), 'py');
  assert.strictEqual(languageFor('.go'), 'other');

  const findings = [];
  const gates = [];
  const addFinding = (severity, id, vector, file, line, desc, fix, fixPack) =>
    findings.push({ severity, id, vector, file, line, desc, fix, fixPack });

  const rules = [
    { id: 'T1', severity: 'Alto', vector: 'Test', languages: ['py'],
      pattern: /danger\(/, message: 'danger', recommendation: 'stop', fixPack: { why: 'x' } },
    { id: 'T2', severity: 'Critico', vector: 'Test', languages: ['js'],
      pattern: /never/, message: 'never', recommendation: 'no' },
    { id: 'T3', severity: 'Medio', vector: 'Test', languages: ['*'],
      pattern: /flagged/, flow: { window: 3, negate: /safe/ }, message: 'flow', recommendation: 'fix' }
  ];

  // py file: T1 fires, T2 (js only) does not
  runRules({ rules, language: 'py', rel: 'a.py', lines: ['ok', 'danger()', 'never'], addFinding, gates });
  assert.strictEqual(findings.filter((f) => f.id === 'T1').length, 1);
  assert.strictEqual(findings.filter((f) => f.id === 'T2').length, 0);
  assert.strictEqual(findings.find((f) => f.id === 'T1').line, 2, 'line is 1-based');
  assert.deepStrictEqual(findings.find((f) => f.id === 'T1').fixPack, { why: 'x' });

  // flow negate: "flagged" near "safe" is suppressed
  findings.length = 0;
  runRules({ rules, language: 'js', rel: 'b.js', lines: ['flagged', 'safe'], addFinding, gates });
  assert.strictEqual(findings.filter((f) => f.id === 'T3').length, 0, 'negate suppresses');
  findings.length = 0;
  runRules({ rules, language: 'js', rel: 'c.js', lines: ['flagged', 'plain'], addFinding, gates });
  assert.strictEqual(findings.filter((f) => f.id === 'T3').length, 1, 'no negate -> fires');

  // gate rule pushes to gates, not findings
  findings.length = 0;
  gates.length = 0;
  const gateRule = [{ id: 'T4', languages: ['*'], pattern: /warn/, gate: { id: 'H4', status: 'WARN', note: 'n' } }];
  runRules({ rules: gateRule, language: 'js', rel: 'd.js', lines: ['warn'], addFinding, gates });
  assert.strictEqual(findings.length, 0);
  assert.strictEqual(gates.length, 1);
  assert.strictEqual(gates[0].status, 'WARN');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `Cannot find module '../scripts/lib/rules/engine'`.

- [ ] **Step 3: Write minimal implementation**

Create `scripts/lib/rules/engine.js`:

```js
const LANGUAGE_BY_EXT = {
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.ts': 'js', '.tsx': 'js',
  '.py': 'py',
  '.sql': 'sql',
  '.html': 'html', '.css': 'css',
  '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml'
};

// Codex correction #4: hardening lives in code, not in a rule-authoring convention.
// `.test()` is stateful when a regex has the /g or /y flag — reset lastIndex so a
// stray flag in any rule can never cause an intermittent false negative.
function test(regex, str) {
  if (regex.global) regex.lastIndex = 0;
  return regex.test(str);
}

function languageFor(ext) {
  return LANGUAGE_BY_EXT[ext] || 'other';
}

function ruleAppliesToFile(rule, language, rel) {
  const langs = rule.languages || ['*'];
  if (!langs.includes('*') && !langs.includes(language)) return false;
  if (rule.pathTest && !rule.pathTest(rel)) return false;
  if (rule.allowlist && rule.allowlist.some((re) => test(re, rel))) return false;
  return true;
}

function flowConfirms(rule, lines, index) {
  const flow = rule.flow;
  if (!flow) return true;
  const text = flow.context
    ? lines.slice(Math.max(0, index - flow.context), Math.min(lines.length, index + flow.context + 1)).join('\n')
    : lines.slice(index, Math.min(lines.length, index + (flow.window || 25))).join('\n');
  if (flow.negate && test(flow.negate, text)) return false;
  if (flow.confirm && !test(flow.confirm, text)) return false;
  return true;
}

function runRules({ rules, language, rel, lines, addFinding, gates }) {
  for (const rule of rules) {
    if (!ruleAppliesToFile(rule, language, rel)) continue;
    lines.forEach((line, index) => {
      if (rule.lineAllowlist && rule.lineAllowlist.some((re) => test(re, line))) return;
      const hit = rule.customMatch
        ? rule.customMatch(lines, index, rel)
        : test(rule.pattern, line);
      if (!hit) return;
      if (!flowConfirms(rule, lines, index)) return;
      if (rule.gate) {
        gates.push({
          id: rule.gate.id,
          status: rule.gate.status,
          evidence: `${rel}:${index + 1}`,
          note: rule.gate.note
        });
        return;
      }
      addFinding(rule.severity, rule.id, rule.vector, rel, index + 1, rule.message, rule.recommendation, rule.fixPack);
    });
  }
}

module.exports = { languageFor, runRules };
```

> **Hardening (in code, not convention) — Codex correction #4:** every regex test goes
> through the `test(regex, str)` helper, which resets `lastIndex` when a regex has the
> `/g`/`/y` flag. A stray global flag in any rule can therefore never cause an
> intermittent false negative. `flow` is also honored for `customMatch` rules (the old
> `!rule.customMatch &&` guard is gone). This matches the engine already committed in
> `e87d49b`; the block above is the source of truth if the engine is ever rebuilt.

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — ends with `rock-house-ci tests passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/rules/engine.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): add generic declarative rule engine"
```

---

## Task 2: Rule registry index + metadata, repoint rules.js shim

**Files:**
- Create: `scripts/lib/rules/index.js`
- Modify: `scripts/lib/rules.js` (becomes a shim)
- Test: `tests/rock-house-ci.test.js` (existing suite must stay green)

- [ ] **Step 1: Create the registry index**

Create `scripts/lib/rules/index.js`. `META` starts as the current contents of `rules.js` plus new ids; families are required and concatenated (families are added in later tasks — start with empty requires that exist after Task 3, so for now `DETECTION_RULES` is `[]`):

```js
const META = {
  S2: { title: 'Git history secrets scan unavailable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S4: { title: 'Sensitive public environment variable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S7: { title: 'Stack trace disclosure', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-209'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A1: { title: 'Privileged key in client-side code', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-798', 'CWE-200'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A3: { title: 'Missing ownership check', owasp: ['A01:2021 Broken Access Control', 'API1:2023 Broken Object Level Authorization'], cwe: ['CWE-639', 'CWE-862'], helpUri: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/' },
  A4: { title: 'Protected route accessible without authentication', owasp: ['A01:2021 Broken Access Control', 'API2:2023 Broken Authentication'], cwe: ['CWE-306', 'CWE-862'], helpUri: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/' },
  I2: { title: 'DOM XSS sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I3: { title: 'React HTML injection sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I4: { title: 'External input reaches code execution', owasp: ['A03:2021 Injection'], cwe: ['CWE-95'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  H1: { title: 'Missing Content-Security-Policy header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H2: { title: 'Missing Strict-Transport-Security header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-319'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H3: { title: 'Missing X-Content-Type-Options header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-16'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H4: { title: 'Permissive CORS', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-942'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H5: { title: 'Server header disclosure', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-200'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H6: { title: 'Dynamic target unreachable', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-770'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H7: { title: 'Open redirect in dynamic response', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-601'], helpUri: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' },
  D1: { title: 'Missing lockfile', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D2: { title: 'Dependency audit unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D3: { title: 'Advisory database unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D4: { title: 'Loose dependency version', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  R0: { title: 'Missing high-risk assurance bundle', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R1: { title: 'Missing dynamic security testing evidence', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R2: { title: 'Missing runtime monitoring evidence', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-778'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R3: { title: 'Missing specialized security review evidence', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-656'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R4: { title: 'Missing human deployment approval evidence', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-285'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R5: { title: 'Invalid assurance integrity digest', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-353'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R6: { title: 'Invalid assurance signature', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R7: { title: 'Approval environment violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-284'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R8: { title: 'Approval reference violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-285'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R9: { title: 'Approval validity violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-613'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R10: { title: 'Assurance signed with revoked key', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R11: { title: 'Assurance signed with non-allowed key', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  // --- new ids (detection metadata; rule objects added in later tasks) ---
  'SEC-GENERIC': { title: 'Hardcoded secret', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-AWS': { title: 'Hardcoded AWS access key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-STRIPE': { title: 'Hardcoded Stripe live key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-GOOGLE': { title: 'Hardcoded Google API key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-GITHUB': { title: 'Hardcoded GitHub token', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-PEM': { title: 'Hardcoded private key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-ENTROPY': { title: 'High-entropy secret-like literal', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'PY-DEBUG': { title: 'Flask debug mode enabled', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-489'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  'PY-SHELL': { title: 'Shell command injection risk', owasp: ['A03:2021 Injection'], cwe: ['CWE-78'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'PY-PICKLE': { title: 'Unsafe deserialization (pickle)', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-502'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'PY-YAML': { title: 'Unsafe YAML load', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-502'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'PY-SQL': { title: 'SQL built from string formatting', owasp: ['A03:2021 Injection'], cwe: ['CWE-89'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'PY-TEMPLATE': { title: 'Server-side template injection risk', owasp: ['A03:2021 Injection'], cwe: ['CWE-94'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'I5': { title: 'OS command injection', owasp: ['A03:2021 Injection'], cwe: ['CWE-78'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'I6': { title: 'Path traversal', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-22'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  'I7': { title: 'Server-side request forgery', owasp: ['A10:2021 Server-Side Request Forgery'], cwe: ['CWE-918'], helpUri: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
  'C1': { title: 'Weak cryptographic hash', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-327'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'C2': { title: 'Insecure randomness for secret', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-338'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' }
};

// Families are added in later tasks. Each exports an array of detection rules.
const families = [];
try { families.push(require('./injection')); } catch (e) { /* added in Task 3/7 */ }
try { families.push(require('./secrets')); } catch (e) { /* added in Task 5 */ }
try { families.push(require('./python-flask')); } catch (e) { /* added in Task 6 */ }
try { families.push(require('./headers-cors')); } catch (e) { /* added in Task 3 */ }
try { families.push(require('./auth-access')); } catch (e) { /* added in Task 3 */ }

const DETECTION_RULES = families.flat();

function ruleFor(checkId) {
  return META[checkId] || { title: checkId, owasp: [], cwe: [], helpUri: 'https://owasp.org/www-project-top-ten/' };
}

function impactFor(severity) {
  if (severity === 'Critico') return 'May allow data exposure, account takeover, or full system compromise.';
  if (severity === 'Alto') return 'May significantly weaken confidentiality, integrity, or access control.';
  if (severity === 'Medio') return 'May increase risk under specific conditions.';
  return 'Hardening improvement.';
}

module.exports = { META, DETECTION_RULES, ruleFor, impactFor };
```

> The `try/require` guards let the index load before the family files exist. They are removed in Task 8 once all families are present.

- [ ] **Step 2: Repoint the old rules.js to the registry**

Replace the entire contents of `scripts/lib/rules.js` with:

```js
const { ruleFor, impactFor } = require('./rules/index');

module.exports = { impactFor, ruleFor };
```

- [ ] **Step 3: Run the full suite to verify no regression**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `rock-house-ci tests passed`. (Behavior unchanged: `ruleFor`/`impactFor` resolve identically; `DETECTION_RULES` is not wired into the scanner yet.)

- [ ] **Step 4: Commit**

```bash
git add scripts/lib/rules/index.js scripts/lib/rules.js
git commit -m "refactor(scanner): move rule metadata into registry index, shim rules.js"
```

---

## Task 3: Port existing inline checks into rule families and wire the engine

**Files:**
- Create: `scripts/lib/rules/injection.js`, `scripts/lib/rules/headers-cors.js`, `scripts/lib/rules/auth-access.js`
- Modify: `scripts/rock-house-ci.js` (`scanFiles`, `addFinding`)
- Test: existing suite must stay green (no new findings, identical ids/lines)

- [ ] **Step 1: Create the injection family (ports I3, I2, I4)**

Create `scripts/lib/rules/injection.js`:

```js
const { shouldFlagInnerHtml } = require('../js-detection');

module.exports = [
  {
    id: 'I3', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /dangerouslySetInnerHTML/,
    message: 'React dangerouslySetInnerHTML can create XSS if content is user-controlled.',
    recommendation: 'Render text normally or sanitize HTML with a reviewed sanitizer.',
    fixPack: {
      why: 'HTML controlado pelo usuário vira execução de script no navegador da vítima.',
      before: '<div dangerouslySetInnerHTML={{ __html: comment }} />',
      after: '<div>{comment}</div>  // ou DOMPurify.sanitize(comment)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I2', severity: 'Alto', vector: 'Injection', languages: ['js', 'html'],
    customMatch: (lines, index) => shouldFlagInnerHtml(lines, index),
    message: 'innerHTML assignment can create DOM XSS.',
    recommendation: 'Use textContent or sanitize trusted HTML before inserting it.',
    fixPack: {
      why: 'innerHTML com dado dinâmico executa <script>/onerror injetado.',
      before: 'el.innerHTML = `<b>${user.name}</b>`;',
      after: 'el.textContent = user.name;  // ou DOMPurify.sanitize(...)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I4', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /\beval\s*\(|setTimeout\s*\([^,)]*(req|query|body|input|message)/,
    message: 'External input appears to reach code execution.',
    recommendation: 'Remove eval-like execution and validate input with a schema.',
    fixPack: {
      why: 'Entrada externa chegando em eval = execução remota de código.',
      before: 'eval(req.query.expr)',
      after: 'const value = schema.parse(req.query.expr);  // sem eval',
      refs: ['OWASP A03', 'CWE-95']
    }
  }
];
```

- [ ] **Step 2: Create the headers-cors family (ports H4 finding + H4 credentials gate)**

Create `scripts/lib/rules/headers-cors.js`:

```js
module.exports = [
  {
    id: 'H4', severity: 'Alto', vector: 'Headers & CORS', languages: ['*'],
    pattern: /Access-Control-Allow-Origin['"]?\s*,?\s*value:\s*['"]\*/,
    message: 'CORS allows every origin.',
    recommendation: 'Use an explicit origin allowlist.',
    fixPack: {
      why: 'CORS * deixa qualquer site ler respostas autenticadas do seu domínio.',
      before: "Access-Control-Allow-Origin: '*'",
      after: "origin: ['https://app.seudominio.com']",
      refs: ['OWASP A05', 'CWE-942']
    }
  },
  {
    id: 'H4', severity: 'Alto', vector: 'Headers & CORS', languages: ['*'],
    pattern: /origin\s*:\s*['"]\*/,
    message: 'CORS allows every origin.',
    recommendation: 'Use an explicit origin allowlist.',
    fixPack: {
      why: 'CORS * deixa qualquer site ler respostas autenticadas do seu domínio.',
      before: "cors({ origin: '*' })",
      after: "cors({ origin: ['https://app.seudominio.com'] })",
      refs: ['OWASP A05', 'CWE-942']
    }
  },
  {
    id: 'H4', languages: ['*'],
    pattern: /Access-Control-Allow-Credentials['"]?\s*,?\s*value:\s*['"]true/,
    gate: { id: 'H4', status: 'WARN', note: 'Credentials are enabled; open CORS becomes critical if paired with wildcard origin.' }
  },
  {
    id: 'H4', languages: ['*'],
    pattern: /credentials\s*:\s*true/,
    gate: { id: 'H4', status: 'WARN', note: 'Credentials are enabled; open CORS becomes critical if paired with wildcard origin.' }
  }
];
```

- [ ] **Step 3: Create the auth-access family (ports S4, A1, S7, A3)**

Create `scripts/lib/rules/auth-access.js`:

```js
function isClientPath(rel) {
  return /(^|\/)(app|pages|components|hooks)\//.test(rel) && !/\/api\//.test(rel) && !/server/.test(rel);
}

module.exports = [
  {
    id: 'S4', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    pattern: /NEXT_PUBLIC_.*(SERVICE|SECRET|PRIVATE|ADMIN|PASSWORD)/i,
    message: 'Sensitive-looking NEXT_PUBLIC variable exposed to client bundle.',
    recommendation: 'Move the value to a server-only environment variable.',
    fixPack: {
      why: 'Tudo com prefixo NEXT_PUBLIC_ vai pro bundle do cliente — qualquer um lê.',
      before: 'NEXT_PUBLIC_SERVICE_KEY=...',
      after: 'SERVICE_KEY=...   // sem NEXT_PUBLIC_, só no servidor',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'A1', severity: 'Critico', vector: 'Auth & Access', languages: ['*'],
    pathTest: isClientPath,
    pattern: /SUPABASE_SERVICE_ROLE|service_role/i,
    message: 'Supabase service role reference appears in client-side code.',
    recommendation: 'Use service role only in server routes or server actions.',
    fixPack: {
      why: 'A service_role ignora RLS; no cliente, é acesso total ao banco pra qualquer visitante.',
      before: "createClient(url, SUPABASE_SERVICE_ROLE)  // em components/",
      after: "// service_role só em route handlers / server actions",
      refs: ['OWASP A01', 'CWE-200']
    }
  },
  {
    id: 'S7', severity: 'Alto', vector: 'Secrets', languages: ['*'],
    pattern: /error\.stack|err\.stack/,
    message: 'Stack trace appears in client-visible error response.',
    recommendation: 'Log internal details server-side and return a generic error.',
    fixPack: {
      why: 'Stack trace revela caminhos, libs e versões que ajudam o atacante.',
      before: 'res.status(500).json({ error: err.stack })',
      after: 'console.error(err); res.status(500).json({ error: "Erro interno" })',
      refs: ['OWASP A05', 'CWE-209']
    }
  },
  {
    id: 'A3', severity: 'Alto', vector: 'Auth & Access', languages: ['js'],
    pattern: /\.eq\(['"]id['"],\s*params\.id\)/,
    flow: { context: 8, negate: /user_id|owner|auth\.|getServerSession|getUser|session/ },
    message: 'ID lookup does not show an ownership/auth check nearby.',
    recommendation: 'Add ownership filtering such as user_id = authenticated user id.',
    fixPack: {
      why: 'Buscar por id sem checar dono = IDOR: troco o id na URL e leio dados alheios.',
      before: ".eq('id', params.id)",
      after: ".eq('id', params.id).eq('user_id', session.user.id)",
      refs: ['OWASP A01 / API1:2023', 'CWE-639']
    }
  }
];
```

> Note: `S4` keeps `vector: 'Secrets'` and `A1` keeps `vector: 'Auth & Access'` exactly as the current inline calls, so report grouping is unchanged.

- [ ] **Step 4: Rewire `scanFiles` to the engine**

In `scripts/rock-house-ci.js`:

Add to the require block near the top (after the existing `js-detection` require):

```js
const { languageFor, runRules } = require('./lib/rules/engine');
const { DETECTION_RULES } = require('./lib/rules/index');
```

Replace the entire `scanFiles` function (currently lines ~241-295) with:

```js
function scanFiles(files) {
  for (const file of files) {
    const rel = path.relative(targetRoot, file).replace(/\\/g, '/');
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split(/\r?\n/);
    const language = languageFor(path.extname(file));
    runRules({ rules: DETECTION_RULES, language, rel, lines, addFinding, gates });
  }
}
```

- [ ] **Step 5: Extend `addFinding` to carry `fixPack`**

In `scripts/rock-house-ci.js`, change the `addFinding` signature and finding object (currently lines ~330-364):

```js
function addFinding(severity, checkId, vector, file, line, description, fix, fixPack) {
  const rule = ruleFor(checkId);
  const finding = {
    severity,
    checkId,
    rule: {
      title: rule.title,
      owasp: rule.owasp,
      cwe: rule.cwe,
      helpUri: rule.helpUri
    },
    vector,
    file,
    line,
    description,
    impact: impactFor(severity),
    recommendation: fix,
    fixPack: fixPack || null
  };
  finding.fingerprint = fingerprintFor(finding);
  finding.baseline = baselineFingerprints.has(finding.fingerprint);

  const suppression = findSuppression(finding);
  if (suppression) {
    suppressed.push({
      ...finding,
      suppression: {
        reason: suppression.reason,
        expires: suppression.expires || null
      }
    });
    return;
  }

  findings.push(finding);
}
```

> `scanPnpmWorkspace` and `scanPackageJson`/`scanLockfile` call `addFinding` with 7 args; `fixPack` is simply `undefined` → stored as `null`. No change needed there.

- [ ] **Step 5b: Strengthen the dedup fingerprint with `line` (Codex correction #3)**

`fingerprintFor` currently keys on `checkId + file + description`. This task and Task 6
add families that **reuse a `checkId`** across multiple rules and lines (`H4` ×4,
`PY-SQL` ×2). Two genuinely distinct occurrences that share the same `checkId` and
description can collapse into one fingerprint — silently hiding a finding from the
report and from baseline/suppression accounting. Add `line` as a discriminator.

In `scripts/rock-house-ci.js`, replace `fingerprintFor`:

```js
function fingerprintFor(finding) {
  if (!finding || !finding.checkId || !finding.file || !finding.description) return '';
  return [
    finding.checkId,
    normalizePath(finding.file),
    String(finding.line || ''),
    String(finding.description).trim().toLowerCase()
  ].join('|');
}
```

> **Migration impact:** adding `line` changes every fingerprint, so any **existing
> baseline file is invalidated once** (all findings read as "new" until regenerated).
> This is a documented one-time reset — note it in the release/changelog and regenerate
> baselines. `testBaselineFailOnNewOnly` stays green: it generates and reads the baseline
> with the same `fingerprintFor`, and a finding's line is stable run-to-run.

- [ ] **Step 6: Remove the now-dead `js-detection` direct require from the scanner (optional cleanup)**

In `scripts/rock-house-ci.js`, delete the line `const { shouldFlagInnerHtml } = require('./lib/js-detection');` — it is now used only inside the injection family. Leave `scripts/lib/js-detection.js` itself untouched.

- [ ] **Step 7: Run the full suite — behavior must be identical**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS. Specifically `testVulnerableDemoBlocks` (S4 + I3), `testEscapedInnerHtmlDoesNotCreateFinding` (exactly one I2 at line 6), `testBaselineFailOnNewOnly` (I3 fingerprint stable), and `testCleanFixturePasses` all still pass.

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/rules/injection.js scripts/lib/rules/headers-cors.js scripts/lib/rules/auth-access.js scripts/rock-house-ci.js
git commit -m "refactor(scanner): port inline checks to rule families, run via engine"
```

---

## Task 4: Coverage-aware confidence + Cobertura report section

**Files:**
- Create: `scripts/lib/rules/coverage.js`
- Modify: `scripts/rock-house-ci.js` (`main`, `calculateConfidence`, report object), `scripts/lib/report-formatters.js` (Cobertura section)
- Test: `tests/rock-house-ci.test.js` (new `testUnsupportedStackLowersConfidence`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `testUnsupportedStackLowersConfidence();`, `testNoRecognizedStackLowersConfidence();`, and `testMonorepoBlindSpotDetected();` in `run()`:

```js
function testUnsupportedStackLowersConfidence() {
  const fixture = makeTempProject('rock-house-coverage-gap-');
  // A Go project: recognized stack, but Rock House has no Go rule family.
  writeFile(fixture, 'go.mod', 'module example.com/app\n\ngo 1.22\n');
  writeFile(fixture, 'main.go', 'package main\nfunc main() {}\n');

  const output = path.join(os.tmpdir(), `rock-house-coverage-gap-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'unsupported stack must not earn a passing gate');
  const report = readJson(output);
  assert.strictEqual(report.confidence, 'Baixa', 'coverage gap forces Baixa confidence');
  assert.strictEqual(report.certification, 'Bloqueado', 'Baixa confidence blocks');
  assert(Array.isArray(report.coverage.gaps), 'report exposes coverage.gaps');
  assert(report.coverage.gaps.includes('go'), 'go is reported as a blind spot');
}

function testNoRecognizedStackLowersConfidence() {
  // Codex correction #1: a repo with no recognized stack AND no blind-spot manifest
  // was never really audited — it must not pass with high confidence.
  const fixture = makeTempProject('rock-house-no-stack-');
  writeFile(fixture, 'NOTES.txt', 'just notes — nothing the scanner recognizes');

  const output = path.join(os.tmpdir(), `rock-house-no-stack-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  const report = readJson(output);
  assert.strictEqual(report.confidence, 'Baixa', 'no recognized stack forces Baixa');
  assert.strictEqual(report.coverage.audited, false, 'nothing recognized is not "audited"');
  assert.strictEqual(report.coverage.gaps.length, 0, 'no blind-spot manifest, yet still blocked');
  assert.notStrictEqual(result.status, 0, 'an unaudited repo must not earn a passing gate');
}

function testMonorepoBlindSpotDetected() {
  // Codex correction #2: blind spots in subdirectories (monorepo) must be found,
  // not only at the repo root.
  const fixture = makeTempProject('rock-house-monorepo-');
  writeFile(fixture, 'package.json', JSON.stringify({ dependencies: { next: '14.0.0', react: '18.0.0' } }));
  writeFile(fixture, 'services/api/Cargo.toml', '[package]\nname = "api"');

  const output = path.join(os.tmpdir(), `rock-house-monorepo-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  const report = readJson(output);
  assert(report.coverage.gaps.includes('rust'), 'rust blind spot found in services/api/');
  assert.strictEqual(report.confidence, 'Baixa', 'a nested blind spot forces Baixa');
  assert.notStrictEqual(result.status, 0, 'monorepo blind spot blocks');
}
```

> `go.mod` and `main.go` are not in `SOURCE_EXTENSIONS`, so no findings are produced — the block comes purely from coverage, proving the P0 mechanism works in isolation. `testNoRecognizedStackLowersConfidence` covers the empty-`supported` case (correction #1); `testMonorepoBlindSpotDetected` covers repo-wide detection (correction #2).

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `report.coverage` is undefined / confidence is `Alta`.

- [ ] **Step 3: Create the coverage module**

Create `scripts/lib/rules/coverage.js`:

```js
const fs = require('fs');
const path = require('path');

// Stacks Rock House has NO rule family for → detecting one is a blind spot.
const UNSUPPORTED = [
  { id: 'php', file: 'composer.json' },
  { id: 'go', file: 'go.mod' },
  { id: 'ruby', file: 'Gemfile' },
  { id: 'rust', file: 'Cargo.toml' },
  { id: 'java', file: 'pom.xml' },
  { id: 'java', file: 'build.gradle' }
];
const ID_BY_FILE = Object.fromEntries(UNSUPPORTED.map((u) => [u.file, u.id]));

// Never descend into these while detecting stacks (perf + noise).
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage',
  'vendor', 'venv', '.venv', '__pycache__', '.turbo', '.cache'
]);

// Codex correction #2: detection is repo-wide (monorepo-aware), not root-only.
// One bounded walk collects both supported signals and blind-spot gaps anywhere in
// the tree (e.g. services/api/Cargo.toml, apps/web/package.json).
function detectStacks(root, maxDepth = 6) {
  const supported = new Set();
  const gaps = new Set();
  const pyManifests = [];
  let sawPackageJson = false;

  (function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const entry of entries) {
      const name = entry.name;
      const full = path.join(dir, name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(full, depth + 1);
        continue;
      }
      if (ID_BY_FILE[name]) { gaps.add(ID_BY_FILE[name]); continue; }
      if (name === 'package.json') {
        sawPackageJson = true;
        let pkg = {};
        try { pkg = JSON.parse(fs.readFileSync(full, 'utf8')); } catch (e) { pkg = {}; }
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        if (deps.next) supported.add('nextjs');
        if (deps.react) supported.add('react');
        if (deps.express) supported.add('express');
        if (deps['@supabase/supabase-js']) supported.add('supabase');
        continue;
      }
      if (/^next\.config\.(js|mjs|ts)$/.test(name)) supported.add('nextjs');
      if (name === 'manage.py') supported.add('django');
      if (name === 'requirements.txt' || name === 'pyproject.toml' || name === 'Pipfile') {
        try { pyManifests.push(fs.readFileSync(full, 'utf8')); } catch (e) { /* ignore */ }
      }
      if (name === 'index.html') supported.add('static');
    }
  })(root, 0);

  const py = pyManifests.join('\n');
  if (/(^|\n)\s*flask\b/i.test(py)) supported.add('flask');
  if (/(^|\n)\s*django\b/i.test(py)) supported.add('django');
  if (/(^|\n)\s*fastapi\b/i.test(py)) supported.add('fastapi');
  if (supported.size === 0 && sawPackageJson) supported.add('node');

  return { supported: [...supported], gaps: [...gaps] };
}

// Codex correction #1: an empty gap list is NOT enough to call a repo "audited".
// If no supported stack was recognized at all, we inspected nothing of substance →
// `audited` requires gaps.length === 0 AND supported.length > 0.
function evaluateCoverage(root) {
  const { supported, gaps } = detectStacks(root);
  const audited = gaps.length === 0 && supported.length > 0;
  let note;
  if (gaps.length > 0) {
    note = `Ponto cego: detectei ${gaps.join(', ')} mas não tenho regras específicas. Não confie no score.`;
  } else if (supported.length === 0) {
    note = 'Nenhum stack reconhecido foi auditado de verdade — confiança rebaixada (não aprovo o que não inspecionei).';
  } else {
    note = `Auditado: ${supported.join(', ')}.`;
  }
  return { supported, gaps, audited, note };
}

module.exports = { detectStacks, evaluateCoverage };
```

- [ ] **Step 4: Wire coverage into the scanner**

In `scripts/rock-house-ci.js`:

Add to the require block:

```js
const { evaluateCoverage } = require('./lib/rules/coverage');
```

In `main()`, after the line `const certification = decideCertification(...)` is computed, the order matters — coverage must be computed before confidence. Replace the block that computes `summary`/`score`/`confidence`/`certification` (currently ~lines 131-134) with:

```js
  const summary = summarize(gateFindings, unknown);
  const score = calculateScore(summary);
  const coverage = evaluateCoverage(targetRoot);
  const confidence = calculateConfidence(summary, coverage);
  const certification = decideCertification(summary, score, confidence);
```

Add `coverage` to the `report` object (after the `confidence,` line, ~line 153):

```js
    confidence,
    coverage,
    summary,
```

- [ ] **Step 5: Update `calculateConfidence` to honor coverage**

Replace `calculateConfidence` (currently ~lines 434-438) with:

```js
function calculateConfidence(summary, coverage) {
  // Codex correction #1: a blind spot OR nothing-recognized both force low confidence.
  if (coverage && coverage.gaps && coverage.gaps.length > 0) return 'Baixa';
  if (coverage && (!coverage.supported || coverage.supported.length === 0)) return 'Baixa';
  if (summary.unknown > 4) return 'Baixa';
  if (summary.unknown > 1) return 'Media';
  return 'Alta';
}
```

- [ ] **Step 6: Render the Cobertura section in Markdown**

In `scripts/lib/report-formatters.js`, inside `toMarkdown`, add a Cobertura block. Insert these array entries immediately after the `'## Resumo'` table rows (after the summary table line and its trailing `''`):

```js
    '## Cobertura',
    '',
    report.coverage
      ? `${report.coverage.audited ? '✅' : '⚠️'} ${report.coverage.note}`
      : 'Cobertura não avaliada.',
    report.coverage && report.coverage.gaps && report.coverage.gaps.length
      ? `**Pontos cegos:** ${report.coverage.gaps.join(', ')}`
      : '',
    '',
```

- [ ] **Step 7: Run tests**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — including the new `testUnsupportedStackLowersConfidence`, and `testCleanFixturePasses` (Next.js fixture has no unsupported manifest → no gap → confidence unchanged → still Prata/passed).

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/rules/coverage.js scripts/rock-house-ci.js scripts/lib/report-formatters.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): coverage-aware confidence + Cobertura report section"
```

---

## Task 5: In-engine secret detection (P0)

**Files:**
- Create: `scripts/lib/rules/secrets.js`
- Modify: `scripts/lib/rules/index.js` (remove the `try/require` guard for secrets — done in Task 8; the guard already loads it)
- Test: `tests/rock-house-ci.test.js` (new `testSecretDetection`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `testSecretDetection();` in `run()`:

```js
function testSecretDetection() {
  const fixture = makeTempProject('rock-house-secrets-');
  // Real-looking hardcoded secrets in source.
  writeFile(fixture, 'config.py', [
    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    'STRIPE = "STRIPE_TEST_FIXTURE_REDACTED"'
  ].join('\n'));
  // Allowlisted: example file with placeholder must NOT flag.
  writeFile(fixture, '.env.example', 'AWS_KEY=your-key-here\nSTRIPE=sk_live_xxxxxxxxxxxx\n');

  const output = path.join(os.tmpdir(), `rock-house-secrets-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'hardcoded secrets must block');
  const report = readJson(output);
  assert(report.findings.some((f) => f.checkId === 'SEC-AWS' && f.file === 'config.py'), 'AWS key detected');
  assert(report.findings.some((f) => f.checkId === 'SEC-STRIPE' && f.file === 'config.py'), 'Stripe key detected');
  assert.strictEqual(report.findings.some((f) => f.file === '.env.example'), false, 'allowlisted example file must not flag');
  const aws = report.findings.find((f) => f.checkId === 'SEC-AWS');
  assert(aws.fixPack && aws.fixPack.before && aws.fixPack.after, 'secret finding carries a fix pack');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — no `SEC-AWS`/`SEC-STRIPE` findings (`secrets.js` missing).

- [ ] **Step 3: Create the secrets family**

Create `scripts/lib/rules/secrets.js`:

```js
// Shared allowlist: never scan these files for secrets (placeholders/fixtures).
const FILE_ALLOWLIST = [
  /\.env\.example$/i, /example/i, /test/i, /fixture/i, /\.md$/i, /\.lock$/i
];
// Lines that are obviously not real secrets.
const LINE_ALLOWLIST = [
  /your[-_].*[-_](key|secret|token)|here|changeme|placeholder|xxx{2,}|<[^>]+>/i,
  /process\.env|os\.environ|import\.meta\.env/
];

function entropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const ENTROPY_ASSIGN = /\b(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key)\b\s*[:=]\s*['"]([A-Za-z0-9+/_=-]{20,})['"]/i;

module.exports = [
  {
    id: 'SEC-AWS', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: 'Hardcoded AWS access key id found in source.',
    recommendation: 'Move the key to an environment variable and rotate it immediately.',
    fixPack: {
      why: 'Chave AWS no código = quem clonar o repo controla sua conta AWS.',
      before: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
      after: 'AWS_KEY = os.environ["AWS_KEY"]',
      command: 'git rm --cached config.py  # depois ROTACIONE a chave no IAM',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-STRIPE', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/,
    message: 'Hardcoded Stripe live secret key found in source.',
    recommendation: 'Move it to an environment variable and roll the key in the Stripe dashboard.',
    fixPack: {
      why: 'Chave sk_live_ move dinheiro real: quem tiver ela cobra e estorna na sua conta.',
      before: 'STRIPE = "sk_live_4eC39Hq..."',
      after: 'STRIPE = process.env.STRIPE_SECRET_KEY',
      command: 'Roll a chave no painel Stripe e atualize a env var',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-GOOGLE', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    message: 'Hardcoded Google API key found in source.',
    recommendation: 'Restrict and rotate the key; load it from an environment variable.',
    fixPack: {
      why: 'Chave Google exposta pode gerar cobrança e abuso de API na sua conta.',
      before: 'const KEY = "AIza...";',
      after: 'const KEY = process.env.GOOGLE_API_KEY;',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-GITHUB', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bgh[opsu]_[0-9A-Za-z]{36}\b/,
    message: 'Hardcoded GitHub token found in source.',
    recommendation: 'Revoke the token on GitHub and load it from an environment variable.',
    fixPack: {
      why: 'Token GitHub dá acesso aos seus repositórios e Actions.',
      before: 'token = "ghp_xxxxxxxx..."',
      after: 'token = os.environ["GITHUB_TOKEN"]',
      command: 'Revogue em github.com/settings/tokens',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-PEM', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    message: 'Hardcoded private key block found in source.',
    recommendation: 'Remove the key from the repo, rotate it, and store it in a secret manager.',
    fixPack: {
      why: 'Chave privada no repo permite personificar seu servidor/serviço.',
      before: '-----BEGIN RSA PRIVATE KEY-----\\n...',
      after: '// carregue de um arquivo fora do repo / secret manager',
      command: 'git rm --cached <arquivo>  # e gere um novo par de chaves',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-ENTROPY', severity: 'Alto', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    customMatch: (lines, index) => {
      const m = ENTROPY_ASSIGN.exec(lines[index]);
      if (!m) return false;
      return entropy(m[1]) >= 3.5;
    },
    message: 'High-entropy value assigned to a secret-looking variable.',
    recommendation: 'If this is a real secret, move it to an environment variable and rotate it.',
    fixPack: {
      why: 'String longa e aleatória colada num campo "secret/token/password" costuma ser credencial real.',
      before: 'API_TOKEN = "f3Q9...32 chars aleatórios..."',
      after: 'API_TOKEN = os.environ["API_TOKEN"]',
      refs: ['OWASP A02', 'CWE-798']
    }
  }
];
```

> The entropy rule uses `customMatch` so it can extract the literal and measure Shannon entropy (≥3.5 bits/char) — this avoids flagging long-but-structured strings like URLs.

- [ ] **Step 4: Run tests**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `testSecretDetection` green, and `testCleanFixturePasses` still green (no secret patterns, allowlist intact).

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/rules/secrets.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): in-engine secret detection with entropy + allowlist"
```

---

## Task 6: Python/Flask rule family (P1)

**Files:**
- Create: `scripts/lib/rules/python-flask.js`
- Test: `tests/rock-house-ci.test.js` (new `testPythonFlaskRules`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `testPythonFlaskRules();` in `run()`:

```js
function testPythonFlaskRules() {
  const fixture = makeTempProject('rock-house-python-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'app.py', [
    'import subprocess, pickle, yaml',
    'app.run(debug=True)',
    'subprocess.call(cmd, shell=True)',
    'data = pickle.loads(payload)',
    'cfg = yaml.load(stream)',
    'query = f"SELECT * FROM users WHERE id = {user_id}"'
  ].join('\n'));
  // Clean Python file must not be flagged.
  writeFile(fixture, 'safe.py', [
    'import subprocess, yaml',
    'subprocess.run(["ls", "-la"])',
    'cfg = yaml.safe_load(stream)'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-python-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'insecure python must block');
  const report = readJson(output);
  const ids = report.findings.filter((f) => f.file === 'app.py').map((f) => f.checkId);
  for (const id of ['PY-DEBUG', 'PY-SHELL', 'PY-PICKLE', 'PY-YAML', 'PY-SQL']) {
    assert(ids.includes(id), `expected ${id} in app.py findings`);
  }
  assert.strictEqual(report.findings.some((f) => f.file === 'safe.py'), false, 'safe python must not flag');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — none of the `PY-*` ids present.

- [ ] **Step 3: Create the family**

Create `scripts/lib/rules/python-flask.js`:

```js
module.exports = [
  {
    id: 'PY-DEBUG', severity: 'Alto', vector: 'Headers & CORS', languages: ['py'],
    pattern: /\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/,
    message: 'Flask debug mode enabled — exposes the Werkzeug console (RCE) in production.',
    recommendation: 'Set debug=False in production and gate it behind an env var.',
    fixPack: {
      why: 'debug=True liga um console que executa Python remoto se alguém alcançar a página de erro.',
      before: 'app.run(debug=True)',
      after: 'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
      refs: ['OWASP A05', 'CWE-489']
    }
  },
  {
    id: 'PY-SHELL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /subprocess\.[a-z_]+\([^)]*shell\s*=\s*True|\bos\.system\(|\bos\.popen\(/,
    message: 'Shell execution with shell=True / os.system can lead to command injection.',
    recommendation: 'Pass an argument list without shell=True and never interpolate user input.',
    fixPack: {
      why: 'shell=True com qualquer parte vinda do usuário vira injeção de comando no servidor.',
      before: 'subprocess.call(cmd, shell=True)',
      after: 'subprocess.run(["git", "clone", repo_url])  # lista, sem shell',
      refs: ['OWASP A03', 'CWE-78']
    }
  },
  {
    id: 'PY-PICKLE', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /\bpickle\.loads?\(/,
    message: 'pickle deserialization of untrusted data allows arbitrary code execution.',
    recommendation: 'Use json for data interchange; never unpickle untrusted bytes.',
    fixPack: {
      why: 'pickle.loads executa código embutido no payload — RCE se o dado não for confiável.',
      before: 'data = pickle.loads(payload)',
      after: 'data = json.loads(payload)',
      refs: ['OWASP A08', 'CWE-502']
    }
  },
  {
    id: 'PY-YAML', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/,
    message: 'yaml.load without SafeLoader can instantiate arbitrary Python objects.',
    recommendation: 'Use yaml.safe_load() for untrusted input.',
    fixPack: {
      why: 'yaml.load constrói objetos Python arbitrários a partir do texto — execução de código.',
      before: 'cfg = yaml.load(stream)',
      after: 'cfg = yaml.safe_load(stream)',
      refs: ['OWASP A08', 'CWE-502']
    }
  },
  {
    id: 'PY-SQL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /(execute|executemany)\s*\(\s*f?["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*(\{|%s?\s*%|"\s*\+|'\s*\+|\.format\()/i,
    message: 'SQL query appears to be built with string formatting — SQL injection risk.',
    recommendation: 'Use parameterized queries (placeholders), never f-strings or concatenation.',
    fixPack: {
      why: 'Montar SQL com f-string/format deixa o usuário reescrever a consulta (SQLi).',
      before: 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
      after: 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))',
      refs: ['OWASP A03', 'CWE-89']
    }
  },
  {
    id: 'PY-SQL', severity: 'Critico', vector: 'Injection', languages: ['py'],
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*=\s*f["']|f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/i,
    message: 'SQL string built with an f-string — SQL injection risk.',
    recommendation: 'Build queries with parameter placeholders, not f-strings.',
    fixPack: {
      why: 'f-string em SQL interpola entrada direta na consulta (SQLi).',
      before: 'query = f"SELECT * FROM users WHERE id = {user_id}"',
      after: 'query = "SELECT * FROM users WHERE id = %s"  # e passe (user_id,)',
      refs: ['OWASP A03', 'CWE-89']
    }
  },
  {
    id: 'PY-TEMPLATE', severity: 'Alto', vector: 'Injection', languages: ['py'],
    pattern: /render_template_string\s*\(\s*[^)'"]*(request|input|user|f["'])/,
    message: 'render_template_string with dynamic input enables server-side template injection.',
    recommendation: 'Render static templates; pass user data as context variables, not into the template string.',
    fixPack: {
      why: 'Jinja avaliando string controlada pelo usuário = execução de código no servidor (SSTI).',
      before: 'render_template_string("Hi " + request.args["name"])',
      after: 'render_template("hi.html", name=request.args["name"])',
      refs: ['OWASP A03', 'CWE-94']
    }
  }
];
```

> Two `PY-SQL` rule objects cover the `execute(f"...")` and the `query = f"..."` shapes; both map to the same `checkId`, so a finding from either is labeled `PY-SQL`. The test asserts presence of the id, not the count.

- [ ] **Step 4: Run tests**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `testPythonFlaskRules` green; `safe.py` produces no findings (uses `subprocess.run([...])` and `yaml.safe_load`).

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/rules/python-flask.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): Python/Flask rule family (debug, shell, pickle, yaml, SQLi, SSTI)"
```

---

## Task 7: Generic/JS gap rules (P2)

**Files:**
- Modify: `scripts/lib/rules/injection.js` (append I5/I6/I7/C1/C2), `scripts/lib/rules/headers-cors.js` (append static H7)
- Test: `tests/rock-house-ci.test.js` (new `testGenericGapRules`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `testGenericGapRules();` in `run()`:

```js
function testGenericGapRules() {
  const fixture = makeTempProject('rock-house-generic-');
  writeFile(fixture, 'server.js', [
    'const cp = require("child_process");',
    'cp.exec("ping " + req.query.host);',
    'const h = crypto.createHash("md5");',
    'const token = Math.random().toString(36);',
    'fetch(req.query.url);',
    'res.redirect(req.query.next);'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-generic-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'generic vulns must block');
  const report = readJson(output);
  const ids = report.findings.map((f) => f.checkId);
  for (const id of ['I5', 'C1', 'C2', 'I7', 'H7']) {
    assert(ids.includes(id), `expected ${id} in findings`);
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `I5/C1/C2/I7/H7` not present.

- [ ] **Step 3: Append generic rules to the injection family**

Append these objects to the array in `scripts/lib/rules/injection.js` (before the closing `];`):

```js
  ,{
    id: 'I5', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /\b(?:child_process\.)?exec(?:Sync)?\s*\([^)]*(\+|`[^`]*\$\{|req\.|request\.|params\.|input)/,
    message: 'Shell command built with external input (command injection).',
    recommendation: 'Use execFile with an argument array; never concatenate user input into a shell string.',
    fixPack: {
      why: 'Concatenar entrada do usuário num comando de shell deixa rodar comando arbitrário.',
      before: 'exec("ping " + req.query.host)',
      after: 'execFile("ping", ["-c", "1", host])  // valide host antes',
      refs: ['OWASP A03', 'CWE-78']
    }
  },
  {
    id: 'I6', severity: 'Alto', vector: 'Injection', languages: ['js'],
    pattern: /\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|unlink)\s*\([^)]*(req\.|request\.|params\.|query\.|body\.)/,
    message: 'Filesystem path built from user input (path traversal).',
    recommendation: 'Resolve against a base dir and reject paths that escape it.',
    fixPack: {
      why: '../../ na entrada permite ler/escrever fora da pasta pretendida.',
      before: 'fs.readFile(req.query.file)',
      after: 'const p = path.resolve(BASE, name); if (!p.startsWith(BASE)) throw Error();',
      refs: ['OWASP A01', 'CWE-22']
    }
  },
  {
    id: 'I7', severity: 'Alto', vector: 'Injection', languages: ['js'],
    pattern: /\b(?:fetch|axios(?:\.get|\.post)?)\s*\([^)]*(req\.|request\.|params\.|query\.|body\.)/,
    message: 'Outbound request target built from user input (SSRF).',
    recommendation: 'Allowlist destination hosts; block internal/metadata addresses.',
    fixPack: {
      why: 'URL controlada pelo usuário deixa o servidor bater em 169.254.169.254 e na rede interna.',
      before: 'fetch(req.query.url)',
      after: 'if (!ALLOWED_HOSTS.includes(new URL(url).host)) throw Error();',
      refs: ['OWASP A10', 'CWE-918']
    }
  },
  {
    id: 'C1', severity: 'Medio', vector: 'Secrets', languages: ['js'],
    pattern: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)/,
    message: 'Weak hash (md5/sha1) used.',
    recommendation: 'Use SHA-256+ for integrity and bcrypt/argon2 for passwords.',
    fixPack: {
      why: 'md5/sha1 são quebráveis — ruins para senha ou integridade.',
      before: "crypto.createHash('md5')",
      after: "crypto.createHash('sha256')  // senha: use bcrypt/argon2",
      refs: ['OWASP A02', 'CWE-327']
    }
  },
  {
    id: 'C2', severity: 'Medio', vector: 'Secrets', languages: ['js'],
    pattern: /\b(?:token|secret|password|otp|nonce|salt)\b[^\n;]*Math\.random\(\)|Math\.random\(\)[^\n;]*\b(?:token|secret|password|otp|nonce|salt)\b/i,
    message: 'Math.random() used to generate a secret/token (predictable).',
    recommendation: 'Use crypto.randomBytes / crypto.randomUUID for security tokens.',
    fixPack: {
      why: 'Math.random() é previsível: tokens viram adivinháveis.',
      before: 'const token = Math.random().toString(36)',
      after: 'const token = crypto.randomBytes(32).toString("hex")',
      refs: ['OWASP A02', 'CWE-338']
    }
  }
```

- [ ] **Step 4: Append the static open-redirect rule to headers-cors**

Append to the array in `scripts/lib/rules/headers-cors.js` (before the closing `];`):

```js
  ,{
    id: 'H7', severity: 'Alto', vector: 'Headers & CORS', languages: ['js', 'py'],
    pattern: /\bredirect\s*\(\s*(?:req\.|request\.)?(?:query|args|params|body|GET)[.\[]/,
    message: 'Redirect target taken directly from user input (open redirect).',
    recommendation: 'Map redirect targets through a reviewed allowlist of relative paths.',
    fixPack: {
      why: 'Redirecionar pro destino que o usuário mandar facilita phishing com seu domínio.',
      before: 'res.redirect(req.query.next)',
      after: 'const dest = ALLOWED[req.query.next] || "/"; res.redirect(dest);',
      refs: ['OWASP A01', 'CWE-601']
    }
  }
```

- [ ] **Step 5: Run tests**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `testGenericGapRules` green; `testCleanFixturePasses` still green (clean fixture has none of these patterns).

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/rules/injection.js scripts/lib/rules/headers-cors.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): generic rules (command injection, path traversal, SSRF, weak crypto, insecure random, open redirect)"
```

---

## Task 8: Fix-pack rendering in Markdown + SARIF, remove require guards

**Files:**
- Modify: `scripts/lib/report-formatters.js` (Markdown fix-pack section + SARIF fields)
- Modify: `scripts/lib/rules/index.js` (drop the `try/catch` require guards now that all families exist)
- Test: `tests/rock-house-ci.test.js` (new `testFixPackRendering`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `testFixPackRendering();` in `run()`:

```js
function testFixPackRendering() {
  const fixture = makeTempProject('rock-house-fixpack-');
  writeFile(fixture, 'config.py', 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n');

  const output = path.join(fixture, 'report.json');
  const sarifOutput = path.join(fixture, 'report.sarif');
  const markdownOutput = path.join(fixture, 'summary.md');
  const result = runScanner(fixture, output, 'bronze', { sarifOutput, markdownOutput });

  assert.notStrictEqual(result.status, 0);
  const report = readJson(output);
  const aws = report.findings.find((f) => f.checkId === 'SEC-AWS');
  assert(aws.fixPack && aws.fixPack.after, 'JSON finding carries fixPack');

  const md = fs.readFileSync(markdownOutput, 'utf8');
  assert(md.includes('## Pacotes de Correcao'), 'Markdown has fix-pack section');
  assert(md.includes('AWS_KEY = os.environ'), 'Markdown shows the after snippet');

  const sarif = readJson(sarifOutput);
  const awsResult = sarif.runs[0].results.find((r) => r.ruleId === 'SEC-AWS');
  assert(awsResult.properties.fixAfter, 'SARIF result carries fixAfter property');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `## Pacotes de Correcao` not in Markdown; `fixAfter` missing in SARIF.

- [ ] **Step 3: Add the Markdown fix-pack section**

In `scripts/lib/report-formatters.js`, add a helper near `findingsTable`:

```js
function fixPacksSection(items) {
  const blocks = [];
  for (const f of items) {
    if (!f.fixPack) continue;
    const fp = f.fixPack;
    const lines = [
      `### [${f.severity}] ${f.checkId} — ${escapeMd(f.rule?.title || f.description)}  (\`${f.file}:${f.line}\`)`,
      fp.why ? `**Por que:** ${escapeMd(fp.why)}` : '',
      fp.before ? `**Antes:** \`${escapeMd(fp.before)}\`` : '',
      fp.after ? `**Depois:** \`${escapeMd(fp.after)}\`` : '',
      fp.command ? `**Comando:** \`${escapeMd(fp.command)}\`` : '',
      Array.isArray(fp.refs) && fp.refs.length ? `**Ref:** ${escapeMd(fp.refs.join(' / '))}` : ''
    ].filter((l) => l !== '');
    blocks.push(lines.join('\n'));
  }
  return blocks.length ? blocks.join('\n\n') : 'Nenhum pacote de correcao disponivel.';
}
```

In `toMarkdown`, insert these entries immediately after the `'## Bloqueios / Findings'` block (after the `_Mostrando 10 de N findings._` line and its trailing `''`):

```js
    '## Pacotes de Correcao',
    '',
    fixPacksSection(topFindings),
    '',
```

- [ ] **Step 4: Add SARIF fix-pack properties**

In `scripts/lib/report-formatters.js`, inside `toSarif`, extend the per-result `properties` object (in the `results: report.findings.map(...)` block) to include:

```js
          properties: {
            severity: finding.severity,
            vector: finding.vector,
            owasp: finding.rule?.owasp || [],
            cwe: finding.rule?.cwe || [],
            impact: finding.impact,
            recommendation: finding.recommendation,
            fixBefore: finding.fixPack?.before || '',
            fixAfter: finding.fixPack?.after || '',
            fixCommand: finding.fixPack?.command || ''
          }
```

- [ ] **Step 5: Remove the require guards in the registry index**

Now that all family files exist, replace the guarded family loading in `scripts/lib/rules/index.js` with direct requires:

```js
const DETECTION_RULES = [
  ...require('./auth-access'),
  ...require('./injection'),
  ...require('./headers-cors'),
  ...require('./secrets'),
  ...require('./python-flask')
];
```

(Delete the `const families = []; try {...} ... const DETECTION_RULES = families.flat();` block.)

- [ ] **Step 6: Run the full suite**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `testFixPackRendering` green and all prior tests green, including `testVulnerableDemoBlocks` (its Markdown/SARIF assertions are unaffected by the added section/properties).

- [ ] **Step 7: Commit**

```bash
git add scripts/lib/report-formatters.js scripts/lib/rules/index.js tests/rock-house-ci.test.js
git commit -m "feat(scanner): render fix packs in Markdown and SARIF; finalize registry wiring"
```

---

## Task 9: Docs sync + full verification

**Files:**
- Modify: `CLAUDE.md` (correct the gitleaks claim)
- Test: full suite + vulnerable-demo CI check

- [ ] **Step 1: Correct the gitleaks claim in CLAUDE.md**

In `CLAUDE.md`, find the row in the Recommended Stack table:

```
| **Secret scanning** | `gitleaks` patterns (regex in script) | Best regex patterns, MIT license, no binary dependency |
```

Replace it with:

```
| **Secret scanning** | Built-in provider patterns + entropy in the scanner; `gitleaks` optional for git history | In-engine detection needs zero install; gitleaks adds deep history scanning |
```

- [ ] **Step 2: Run the full test suite**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — `rock-house-ci tests passed`.

- [ ] **Step 3: Run the vulnerable-demo gate check (mirrors CI)**

Run:
```bash
node scripts/rock-house-ci.js --path examples/vulnerable-next-supabase --min-level prata --output "$TMPDIR/rh-vuln.json"; echo "exit=$?"
```
Expected: `exit=1` (blocked). Confirm with:
```bash
node -e "const r=require(process.env.TMPDIR + '/rh-vuln.json'); console.log(r.result, r.certification, 'coverage:', JSON.stringify(r.coverage))"
```
Expected: `blocked Bloqueado coverage: {"supported":[...],"gaps":[],...}` — the demo is a supported stack (no blind-spot gaps), and the new secret/generic rules may add findings without changing the blocked verdict.

- [ ] **Step 4: Self-scan the scanner repo (smoke test for false positives)**

Run:
```bash
node scripts/rock-house-ci.js --path . --min-level bronze --output "$TMPDIR/rh-self.json" --config examples/rock-house.config.json; echo "exit=$?"
node -e "const r=require(process.env.TMPDIR + '/rh-self.json'); console.log('C/H/M:', r.summary.critical, r.summary.high, r.summary.medium); console.log(r.findings.map(f=>f.checkId+' '+f.file).slice(0,20))"
```
Expected: review the output. The repo's own source and the `examples/` tree are excluded by `examples/rock-house.config.json`. If any **false positive** appears in `scripts/`, tighten that rule's `allowlist`/`pattern` and re-run Task's relevant test. (This step is a judgment check, not a hard assert.)

- [ ] **Step 5: Final commit**

```bash
git add CLAUDE.md
git commit -m "docs: correct secret-scanning description to reflect in-engine detection"
```

---

## Self-Review (completed during planning)

**Spec coverage:**
- Declarative rule registry → Tasks 1–3, 8. ✅
- Coverage-aware confidence (P0) → Task 4. ✅
- In-engine secret detection (P0) → Task 5. ✅
- Python/Flask parity (P1) → Task 6. ✅
- Rich fix packs (P1) → fixPack fields throughout + rendering in Task 8. ✅
- Light source→sink flow → engine `flow` window (Task 1), used by A3 (Task 3). ✅
- Generic/JS gap rules + dormant H7 static (P2) → Task 7. ✅
- Non-goals (no auto-fix, no deps, no plumbing rewrite) → respected; only additive changes. ✅
- Migration keeps 28 tests green → every task ends by running the full suite. ✅
- Future Approach C → documented in spec; not in plan scope (correct). ✅

**Placeholder scan:** No TBD/TODO; every code step shows complete code. ✅

**Type/name consistency:** `runRules`/`languageFor` (engine) used identically in Tasks 1 and 3; `addFinding(..., fixPack)` 8-arg signature defined in Task 3 and consumed by all families; `evaluateCoverage` defined in Task 4 and called once; `fixPack` shape (`why/before/after/command/refs`) consistent across all rules and the renderer; `DETECTION_RULES` exported in Task 2, consumed in Task 3, finalized in Task 8. ✅

**Note on duplicate `checkId`s:** `H4` (×4) and `PY-SQL` (×2) intentionally share ids across multiple rule objects (different patterns, same classification). Findings are de-duplicated downstream by `fingerprintFor`, which now keys on **checkId + file + line + description** (Task 3 Step 5b, Codex correction #3) — so two distinct occurrences sharing a `checkId` and description but at different lines are preserved instead of collapsing into one.

**Plan-review corrections applied (2026-06-01, Codex):**
- **#1 — coverage-not-audited-when-empty:** Task 4 `evaluateCoverage` (`audited` requires `supported.length > 0`) + `calculateConfidence` (empty `supported` → `Baixa`). Test: `testNoRecognizedStackLowersConfidence`. ✅
- **#2 — repo-wide blind-spot detection:** Task 4 `detectStacks` is a single recursive walk (skips heavy dirs), finding manifests in monorepo sub-packages. Test: `testMonorepoBlindSpotDetected`. ✅
- **#3 — stronger fingerprint:** Task 3 Step 5b adds `line` to `fingerprintFor` (migration: one-time baseline reset, documented). ✅
- **#4 — `/g` hardening in code:** Task 1 engine `test()` wrapper resets `lastIndex`; already shipped in `e87d49b`, plan code now matches. ✅
