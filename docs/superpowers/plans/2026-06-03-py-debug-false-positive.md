# PY-DEBUG False Positive Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the PY-DEBUG rule from flagging `DEBUG = True` inside a `DevConfig` class as **Alto** when the same file defines a production config with `DEBUG = False` — without weakening the genuine `app.run(debug=True)` runtime case.

**Architecture:** Split the single PY-DEBUG regex into two rules: (1) `app.run(debug=True)` stays a pure-regex always-Alto runtime finding; (2) the config-style `DEBUG = True` becomes a `customMatch` rule that suppresses the match only when it sits inside a Dev/Test/Local/Debug-named class AND the file also defines a prod-style config class with `DEBUG = False`. The rule engine already supports `customMatch(lines, index, rel)` (full-file access) — no engine change needed.

**Tech Stack:** Node (dependency-free), the existing `runRules` engine in `scripts/lib/rules/engine.js`, `tests/rock-house-ci.test.js` harness.

**Branch:** new `fix/py-debug-config-context` off `master` (a separate PR, parallel to PR #1 — this does NOT touch the taint engine).

**Files in play:**
- `scripts/lib/rules/python-flask.js` — the PY-DEBUG rule definition (lines 2-13).
- `tests/rock-house-ci.test.js` — new rule-level tests via `runRules`.

> **Why `master`, not the taint branch:** keeps PR #1 focused on the taint engine. Create the branch fresh from `master` so the two reviews stay independent.

---

### Task 0: Branch from master

- [ ] **Step 1: Create the branch**

```bash
git checkout master
git pull --ff-only
git checkout -b fix/py-debug-config-context
```

Expected: on a clean `fix/py-debug-config-context` branched from `master`.

---

### Task 1: Split PY-DEBUG into runtime (regex) + config (customMatch)

**Files:**
- Modify: `scripts/lib/rules/python-flask.js`
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing tests**

Add `testPyDebugConfigContext()` and register it (call it from the runner block alongside the other rule tests, e.g. near `testEngineMatching();`). It drives the rules directly through `runRules` so it is fast and deterministic:

```javascript
function testPyDebugConfigContext() {
  const { runRules } = require('../scripts/lib/rules/engine');
  const flaskRules = require('../scripts/lib/rules/python-flask');

  function run(lines) {
    const findings = [];
    const gates = [];
    runRules({
      rules: flaskRules, language: 'py', rel: 'config.py', lines,
      addFinding: (severity, id, vector, file, line, desc) => findings.push({ severity, id, line }),
      gates
    });
    return findings.filter((f) => f.id === 'PY-DEBUG');
  }

  // 1) Dev config WITH a prod config in the same file → suppressed (the false positive we are killing)
  const devWithProd = [
    'class DevConfig:',
    '    DEBUG = True',
    '',
    'class ProdConfig:',
    '    DEBUG = False'
  ];
  assert.strictEqual(run(devWithProd).length, 0, 'Dev DEBUG=True with a Prod DEBUG=False is suppressed');

  // 2) Lone DEBUG=True with NO prod counterpart → still flagged (genuinely risky)
  const loneDebug = [
    'class Config:',
    '    DEBUG = True'
  ];
  assert.strictEqual(run(loneDebug).length, 1, 'DEBUG=True without a prod config still flagged');

  // 3) Runtime app.run(debug=True) → always flagged, regardless of config classes
  const runtime = [
    'class ProdConfig:',
    '    DEBUG = False',
    '',
    'if __name__ == "__main__":',
    '    app.run(debug=True)'
  ];
  const runtimeHits = run(runtime);
  assert.strictEqual(runtimeHits.length, 1, 'app.run(debug=True) is always flagged');
  assert.strictEqual(runtimeHits[0].line, 5, 'runtime finding points at the app.run line');

  // 4) DEBUG=False exists but NOT inside a prod-style class (module-level) → NOT a valid
  //    prod-config signal → Dev DEBUG=True is still flagged (Codex Ressalva: tighter heuristic).
  const devWithModuleLevelFalse = [
    'DEBUG = False',
    '',
    'class DevConfig:',
    '    DEBUG = True'
  ];
  assert.strictEqual(run(devWithModuleLevelFalse).length, 1,
    'a module-level DEBUG=False is not a prod-config class → no suppression');
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — case 1 currently returns 1 (false positive), and the single combined rule may also mis-handle the split expectations.

- [ ] **Step 3: Rewrite the PY-DEBUG rule as two rules**

In `scripts/lib/rules/python-flask.js`, replace the single PY-DEBUG object (lines 2-13) with two objects. The first is the runtime regex (unchanged severity/message). The second is config-style with a `customMatch` that suppresses the Dev+Prod case.

```javascript
  {
    id: 'PY-DEBUG', severity: 'Alto', vector: 'Headers & CORS', languages: ['py'],
    pattern: /\.run\([^)]*debug\s*=\s*True/,
    message: 'Flask debug mode enabled at runtime — exposes the Werkzeug console (RCE) in production.',
    recommendation: 'Set debug=False in production and gate it behind an env var.',
    fixPack: {
      why: 'debug=True liga um console que executa Python remoto se alguém alcançar a página de erro.',
      before: 'app.run(debug=True)',
      after: 'app.run(debug=os.environ.get("FLASK_DEBUG") == "1")',
      refs: ['OWASP A05', 'CWE-489']
    }
  },
  {
    id: 'PY-DEBUG', severity: 'Alto', vector: 'Headers & CORS', languages: ['py'],
    // Config-style DEBUG=True. Suppressed when it sits inside a Dev/Test/Local/Debug-named
    // class AND the file also defines a config class with DEBUG=False (a real prod config) —
    // that pattern is intentional environment separation, not a production misconfig.
    customMatch: (lines, index) => {
      if (!/^\s*DEBUG\s*=\s*True\b/.test(lines[index])) return false;
      // Nearest enclosing class header for a given line index.
      const classOf = (idx) => {
        for (let i = idx; i >= 0; i--) {
          const m = /^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(lines[i]);
          if (m) return m[1];
        }
        return null;
      };
      const enclosingClass = classOf(index);
      const inDevClass = enclosingClass && /Dev|Test|Local|Debug/i.test(enclosingClass);
      // Codex Ressalva: require DEBUG=False to live inside a PROD-STYLE config class
      // (Prod/Production/Live/Base/Default), not just anywhere in the file. That is the
      // real "intentional environment separation" signal.
      const hasProdConfigFalse = lines.some((l, i) => {
        if (!/^\s*DEBUG\s*=\s*False\b/.test(l)) return false;
        const cls = classOf(i);
        return cls && /Prod|Production|Live|Base|Default/i.test(cls);
      });
      if (inDevClass && hasProdConfigFalse) return false; // intentional env separation → suppress
      return true;
    },
    message: 'Flask debug mode enabled in config — exposes the Werkzeug console (RCE) if this config reaches production.',
    recommendation: 'Keep DEBUG=True only in a clearly-scoped dev config, and ensure production loads a config with DEBUG=False.',
    fixPack: {
      why: 'DEBUG=True num config carregado em produção liga o console que executa Python remoto.',
      before: 'DEBUG = True',
      after: 'DEBUG = os.environ.get("FLASK_DEBUG") == "1"',
      refs: ['OWASP A05', 'CWE-489']
    }
  },
```

> The `customMatch` returns `true` to mean "this line IS a finding" (the engine then calls `addFinding`). Returning `false` suppresses. The runtime rule keeps using `pattern`. Both carry `id: 'PY-DEBUG'`, so reports and the `META['PY-DEBUG']` entry are unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — the three cases plus the full suite green.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/rules/python-flask.js tests/rock-house-ci.test.js
git commit -m "fix(py-debug): suppress config DEBUG=True when a prod config exists; keep runtime always-flagged"
```

---

### Task 2: Confirm against the real Bot Radar pattern (integration sanity)

The false positive surfaced on `radar/config.py:51` of Bot Radar AC1 (`DEBUG=True` in `DevConfig`, prod uses `ProdConfig`). Prove the scanner-level path (not just `runRules`) no longer flags it.

**Files:**
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing/standing test**

Add and register `await testPyDebugScannerIntegration();`:

```javascript
async function testPyDebugScannerIntegration() {
  const fixture = makeTempProject('rock-house-pydebug-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'config.py', [
    'class DevConfig:',
    '    DEBUG = True',
    '',
    'class ProdConfig:',
    '    DEBUG = False',
    '    SECRET_KEY = os.environ["SECRET_KEY"]'
  ].join('\n'));
  const output = path.join(os.tmpdir(), `rock-house-pydebug-${Date.now()}.json`);
  runScanner(fixture, output, 'bronze');
  const report = readJson(output);
  const pyDebug = (report.findings || []).filter((f) => f.checkId === 'PY-DEBUG');
  assert.strictEqual(pyDebug.length, 0, 'Dev/Prod config split is not a PY-DEBUG finding');
}
```

- [ ] **Step 2: Run test**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS (Task 1 already implements the suppression; this asserts it end-to-end through `runScanner`).

- [ ] **Step 3: Commit**

```bash
git add tests/rock-house-ci.test.js
git commit -m "test(py-debug): scanner-level proof of Dev/Prod config suppression"
```

---

## Final verification

- [ ] `node tests/rock-house-ci.test.js` → `rock-house-ci tests passed`.
- [ ] Self-scan still Ouro 10/10 (the change only narrows one rule; no new findings on the repo itself).
- [ ] Optional real-world check: re-run the Rock House scan against `C:\Users\ANGELO SILVA\Documents\projetos\bot-radar-ac` and confirm `PY-DEBUG` no longer appears for `radar/config.py` (command in `10-Projects/DEV/bot-radar-ac/HANDOFF-2026-06-03-rock-house.md`).

## Self-review notes

- **Spec coverage:** Part C (PY-DEBUG) of the design → Tasks 1-2. C-pref heuristic (Dev/Test class + existing prod `DEBUG=False`) implemented exactly.
- **No engine change:** uses the existing `customMatch` hook in `scripts/lib/rules/engine.js:43-45`. The runtime case stays a `pattern` rule.
- **No silent weakening:** a lone `DEBUG=True` with no prod counterpart still fires (case 2); `app.run(debug=True)` always fires (case 3). Suppression is narrow and evidence-based.
