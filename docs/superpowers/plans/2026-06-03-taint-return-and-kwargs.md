# Taint Engine — Return-Taint + Keyword-Args Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two silent/imprecise holes in the Python taint engine so a helper that returns user input (`def get_q(): return request.args['x']`) and a sink called by keyword (`cur.execute(query=user_input)`) are caught, not silently clean.

**Architecture:** Add a return-taint summary (`returnIsSource` + the already-collected `paramTaintsReturn`) computed per function and composed to a bounded fixpoint. Thread an optional resolver context (`ctx`) through `exprIsTainted` / `analyzeFunctionIntra` so a call whose resolved callee returns taint is itself treated as a source — and, for resolved repo calls, treated as *clean* when it provably does not return taint (precision). Separately, stop dropping `keyword_argument` nodes in the IR and map them to callee params by name.

**Tech Stack:** Node (dependency-free), tree-sitter WASM (vendored), the existing `tests/rock-house-ci.test.js` harness (plain `assert`, async functions registered in the runner at the top of the file).

**Branch:** `feat/python-taint-engine` (these are the pre-merge fixes for PR #1).

**Files in play:**
- `scripts/lib/taint/engine.js` — `exprIsTainted`, `analyzeFunctionIntra`, `analyzeProjectTaint`, new `buildReturnTaint`.
- `scripts/lib/taint/ir.js` — `describeExpr` keyword-arg handling.
- `scripts/lib/taint/index.js` — orchestration: build return-taint before same-function emission, pass `ctx`.
- `scripts/lib/taint/callgraph.js` — `resolveCall` (read-only; reused by the resolver shim).
- `tests/rock-house-ci.test.js` — new fixtures + runner registration.

> **Convention reminder (from 2026-06-02 handoff):** never `git add -A` — `node -e` on Git Bash leaves junk files in the repo root. Stage only the exact files each step names. To run a JS check, write a temp `.js` and `node tempfile.js` — never `node -e`.

---

### Task 1: `returnIsSource` summary in `analyzeFunctionIntra`

A function whose return is tainted by a **source** (params NOT seeded) must advertise it. `paramTaintsReturn` already exists; add `returnIsSource` computed from a parallel source-only taint set.

**Files:**
- Modify: `scripts/lib/taint/engine.js` (`analyzeFunctionIntra`, ~lines 28-80)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing test**

Add this function and register it (call `await testTaintReturnSummary();` in the runner block near line 30, after `await testTaintInterprocedural();`):

```javascript
async function testTaintReturnSummary() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { analyzeFunctionIntra } = require('../scripts/lib/taint/engine');

  // returns a source directly → returnIsSource true, no param needed
  let ir = buildFileIR(await parse('def get_q():\n    return request.args["x"]\n'), 'h.py');
  let res = analyzeFunctionIntra(ir.functions[0], 'h.py');
  assert.strictEqual(res.summary.returnIsSource, true, 'source-returning helper flagged');

  // returns its param → paramTaintsReturn has it, returnIsSource false
  ir = buildFileIR(await parse('def wrap(x):\n    return x\n'), 'h.py');
  res = analyzeFunctionIntra(ir.functions[0], 'h.py', ['x']);
  assert.strictEqual(res.summary.returnIsSource, false, 'param passthrough is not a source');
  assert(res.summary.paramTaintsReturn.has('x'), 'param flow to return tracked');

  // returns a constant → neither
  ir = buildFileIR(await parse('def c():\n    return 42\n'), 'h.py');
  res = analyzeFunctionIntra(ir.functions[0], 'h.py');
  assert.strictEqual(res.summary.returnIsSource, false, 'constant return is clean');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `res.summary.returnIsSource` is `undefined` (not `true`).

- [ ] **Step 3: Implement in `analyzeFunctionIntra`**

In `scripts/lib/taint/engine.js`, add a source-only taint set alongside `tainted`, update it in the assign branch, compute `returnIsSource`, and add it to the returned summary.

After the existing `const tainted = new Set(seedParams);` (line 29) add:

```javascript
  const sourceTainted = new Set(); // tainted IGNORING params (source-driven only) → returnIsSource
```

In the assign branch (currently lines 53-55), after the existing `tainted` update, add the parallel update:

```javascript
      const ts = exprIsTainted(ev.a.value, sourceTainted);
      for (const tgt of ev.a.targets) { if (ts) sourceTainted.add(tgt); else sourceTainted.delete(tgt); }
```

Replace the returns loop (lines 73-77) with:

```javascript
  let returnIsSource = false;
  for (const r of fn.returns) {
    if (!r.value) continue;
    if (exprIsTainted(r.value, tainted)) {
      for (const p of seedParams) if ((r.value.reads || []).includes(p)) paramTaintsReturn.add(p);
    }
    if (exprIsTainted(r.value, sourceTainted)) returnIsSource = true;
  }
```

Update the return statement (line 79) to include `returnIsSource`:

```javascript
  return { sinkHits, summary: { paramReachesSink, paramTaintsReturn, paramReachesBlind, returnIsSource } };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — full suite ends with `rock-house-ci tests passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "feat(taint): compute returnIsSource summary in intra pass"
```

---

### Task 2: `buildReturnTaint` — per-function return-taint with bounded fixpoint

A function returns taint if `returnIsSource`, OR it returns the value of a call to another repo function that returns taint. Compose to a fixpoint so `def a(): return get_q()` inherits `get_q`'s return-taint.

**Files:**
- Modify: `scripts/lib/taint/engine.js` (new exported `buildReturnTaint`)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing test**

Add and register `await testBuildReturnTaint();` in the runner:

```javascript
async function testBuildReturnTaint() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { buildSymbolTable } = require('../scripts/lib/taint/symbols');
  const { buildReturnTaint } = require('../scripts/lib/taint/engine');

  const hIr = buildFileIR(await parse('def get_q():\n    return request.args["x"]\n'), 'h.py');
  const vIr = buildFileIR(await parse('from h import get_q\ndef a():\n    return get_q()\n'), 'v.py');
  const symbols = buildSymbolTable([hIr, vIr]);
  const rt = buildReturnTaint([hIr, vIr], symbols);

  assert.strictEqual(rt.get('h.get_q').returnIsSource, true, 'direct source return');
  assert.strictEqual(rt.get('v.a').returnIsSource, true, 'inherited through resolved call (fixpoint)');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `buildReturnTaint is not a function`.

- [ ] **Step 3: Implement `buildReturnTaint`**

In `scripts/lib/taint/engine.js`, after `analyzeProjectTaint` (before `buildHops`), add. It reuses `resolveCall` (already required at line 82) and `MAX_DEPTH`.

```javascript
// Per-function return-taint: returnIsSource (source-driven, unconditional) and the
// param indices whose taint reaches the return. Composed to a bounded fixpoint so a
// function that returns the value of a resolved call to a return-tainted function is
// itself return-tainted. Unresolved/external return-producers do NOT set returnIsSource
// here — exprIsTainted falls back to its conservative arg-flow for those.
function buildReturnTaint(fileIRs, symbols) {
  const irOfFn = new Map();   // qualname -> FileIR
  const fnByQual = new Map(); // qualname -> FunctionIR
  const summary = new Map();  // qualname -> { returnIsSource, paramReturnIdx:Set<int> }

  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      irOfFn.set(fn.qualname, ir);
      fnByQual.set(fn.qualname, fn);
      const base = analyzeFunctionIntra(fn, ir.path, fn.params || []);
      const paramReturnIdx = new Set();
      (fn.params || []).forEach((p, i) => { if (base.summary.paramTaintsReturn.has(p)) paramReturnIdx.add(i); });
      summary.set(fn.qualname, { returnIsSource: base.summary.returnIsSource, paramReturnIdx });
    }
  }

  // Fixpoint: a()'s return inherits return-taint from a resolved callee it returns.
  for (let iter = 0; iter < MAX_DEPTH; iter++) {
    let changed = false;
    for (const ir of fileIRs) {
      for (const fn of ir.functions) {
        const s = summary.get(fn.qualname);
        if (s.returnIsSource) continue;
        for (const r of fn.returns) {
          if (!r.value || !r.value.isCall) continue;
          const shim = { calleeDotted: r.value.callee || '', calleeLast: (r.value.callee || '').split('.').pop(), args: r.value.args || [] };
          const res = resolveCall(shim, ir, symbols);
          if (res.kind !== 'function') continue;
          if (summary.get(res.fn.qualname) && summary.get(res.fn.qualname).returnIsSource) {
            s.returnIsSource = true; changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }
  return summary;
}
```

Add `buildReturnTaint` to the `module.exports` (line 388):

```javascript
module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource, analyzeProjectTaint, computeParamCallFlows, buildReturnTaint };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "feat(taint): buildReturnTaint summary with bounded fixpoint"
```

---

### Task 3: Thread return-taint `ctx` through `exprIsTainted` (source + precision)

A call to a return-tainted repo function becomes a source. A resolved repo call that provably does NOT return taint is treated as clean (kills the `def first(a,b): return a` over-taint when only `b` is tainted). Unresolved/external calls keep the current conservative arg-flow. All changes are backward-compatible: with no `ctx`, behavior is identical to today.

**Files:**
- Modify: `scripts/lib/taint/engine.js` (`exprIsTainted`, and pass `ctx` through `analyzeFunctionIntra`)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing test**

Add and register `await testReturnTaintCtx();`:

```javascript
async function testReturnTaintCtx() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { buildSymbolTable } = require('../scripts/lib/taint/symbols');
  const { analyzeFunctionIntra, buildReturnTaint, makeReturnTaintCtx } = require('../scripts/lib/taint/engine');

  // get_q() returns a source; profile assigns it and sinks it — must be a hit WITH ctx.
  const hIr = buildFileIR(await parse('def get_q():\n    return request.args["x"]\n'), 'h.py');
  const vIr = buildFileIR(await parse('from h import get_q\ndef profile():\n    q = get_q()\n    cur.execute(q)\n'), 'v.py');
  const symbols = buildSymbolTable([hIr, vIr]);
  const rt = buildReturnTaint([hIr, vIr], symbols);
  const ctx = makeReturnTaintCtx(rt, symbols, vIr);

  const profile = vIr.functions.find((f) => f.name === 'profile');
  const withCtx = analyzeFunctionIntra(profile, 'v.py', [], ctx);
  assert.strictEqual(withCtx.sinkHits.length, 1, 'return-source helper makes the sink a hit');
  assert.strictEqual(withCtx.sinkHits[0].sinkId, 'TAINT-SQLI');

  // Without ctx, today's behavior: the no-arg call is not a source → no hit (proves we did not regress the default).
  const noCtx = analyzeFunctionIntra(profile, 'v.py', []);
  assert.strictEqual(noCtx.sinkHits.length, 0, 'no ctx = unchanged conservative default');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `makeReturnTaintCtx is not a function`.

- [ ] **Step 3: Implement ctx + thread it**

In `scripts/lib/taint/engine.js`, change `exprIsTainted` (lines 10-19) to accept and use an optional `ctx`:

```javascript
function exprIsTainted(expr, taintedVars, ctx) {
  if (!expr) return false;
  if (exprIsSource(expr)) return true;
  if (expr.isCall) {
    const last = (expr.callee || '').split('.').pop();
    if (isSanitizer(last)) return false;                 // sanitized — check BEFORE reads
    if (ctx && ctx.callReturn) {
      const verdict = ctx.callReturn(expr, taintedVars, ctx);
      if (verdict === true) return true;                 // resolved callee returns taint
      if (verdict === 'clean') return false;             // resolved & provably not return-tainting
      // 'unknown' (unresolved/external) → fall through to conservative arg-flow
    }
    return (expr.args || []).some((a) => exprIsTainted(a, taintedVars, ctx)); // taint flows through calls
  }
  return (expr.reads || []).some((id) => taintedVars.has(id));
}
```

Make `analyzeFunctionIntra` accept and forward `ctx`. Change its signature (line 28) to:

```javascript
function analyzeFunctionIntra(fn, file, seedParams = [], ctx = null) {
```

and pass `ctx` to every `exprIsTainted(...)` call inside it (the assign-taint line, the `sourceTainted` line from Task 1, the sink-hit `some(...)` line, `sqlIsParameterized` is fine to leave, and the returns-loop `exprIsTainted` calls). Concretely, each `exprIsTainted(X, Y)` in this function becomes `exprIsTainted(X, Y, ctx)`.

Add `makeReturnTaintCtx` near `buildReturnTaint`:

```javascript
// Build the resolver context exprIsTainted uses to ask "does this call return taint?".
// `ir` is the file the expression being analyzed lives in (needed to resolve the call).
function makeReturnTaintCtx(returnSummary, symbols, ir) {
  return {
    ir, symbols, returnSummary,
    callReturn(expr, taintedVars, ctx) {
      const shim = { calleeDotted: expr.callee || '', calleeLast: (expr.callee || '').split('.').pop(), args: expr.args || [] };
      const res = resolveCall(shim, ctx.ir, ctx.symbols);
      if (res.kind !== 'function') return 'unknown';      // external/unresolved → conservative arg-flow
      const s = ctx.returnSummary.get(res.fn.qualname);
      if (!s) return 'unknown';
      if (s.returnIsSource) return true;
      // Resolved: return is tainted iff a tainted arg is bound to a param that flows to the return.
      for (const i of s.paramReturnIdx) {
        if (expr.args[i] && exprIsTainted(expr.args[i], taintedVars, ctx)) return true;
      }
      return 'clean';                                     // resolved & precisely not return-tainting
    }
  };
}
```

Export `makeReturnTaintCtx` (extend the `module.exports` from Task 2):

```javascript
module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource, analyzeProjectTaint, computeParamCallFlows, buildReturnTaint, makeReturnTaintCtx };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — including the existing `testTaintIntraprocedural` and `testTaintScannerIntegration` (backward-compatible default path).

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "feat(taint): return-taint resolver ctx for exprIsTainted (source + precision)"
```

---

### Task 4: Wire return-taint into `analyzeProject` (the headline fix)

Build symbols + return-taint once, then pass a per-file `ctx` into the same-function intra emission **and** into the cross-function pass. This is where `get_q()` → `cur.execute(q)` finally becomes a finding end-to-end.

**Files:**
- Modify: `scripts/lib/taint/index.js`
- Modify: `scripts/lib/taint/engine.js` (`analyzeProjectTaint` accepts `returnSummary`, builds per-file ctx for its internal `analyzeFunctionIntra`/`exprIsTainted` calls)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing integration test**

Add and register `await testTaintReturnSourceHelperIsFound();`:

```javascript
async function testTaintReturnSourceHelperIsFound() {
  const fixture = makeTempProject('rock-house-taint-retsrc-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'helpers.py', [
    'from flask import request',
    'def get_q():',
    '    return request.args["q"]'
  ].join('\n'));
  writeFile(fixture, 'views.py', [
    'from helpers import get_q',
    'def profile():',
    '    q = get_q()',
    '    cur.execute(q)'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-taint-retsrc-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');
  assert.notStrictEqual(result.status, 0, 'return-source helper SQLi must block');
  const report = readJson(output);
  const t = report.findings.find((f) => f.checkId === 'TAINT-SQLI');
  assert(t, 'TAINT-SQLI from a source-returning helper is found');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — no `TAINT-SQLI` finding (the silent-safe hole).

- [ ] **Step 3a: `analyzeProjectTaint` accepts `returnSummary`**

In `scripts/lib/taint/engine.js`, change the signature (line 205) to:

```javascript
function analyzeProjectTaint(fileIRs, symbols, returnSummary = null) {
```

Inside, where it builds initial summaries (line 220) and walks the emit pass, construct a per-file ctx and pass it to `analyzeFunctionIntra` and `exprIsTainted`. At the top of the per-file loops, add:

```javascript
      const ctx = returnSummary ? makeReturnTaintCtx(returnSummary, symbols, ir) : null;
```

- line 220 becomes: `const res = analyzeFunctionIntra(fn, ir.path, fn.params, ctx);`
- in the emit pass, the assignment taint check (line 289) becomes: `const t = exprIsTainted(ev.a.value, tainted, ctx);`
- the emit pass tainted-arg find (line 297) becomes: `const taintedArgIdx = (call.args || []).findIndex((arg) => exprIsTainted(arg, tainted, ctx));`
- `computeParamCallFlows(fn, ir, symbols)` (line 222): leave as-is for this task (provenance/flow precision is not return-taint); its internal `exprIsTainted` calls keep the conservative default. (Out of scope; honest because over-taint, never silent.)

> Note: `makeReturnTaintCtx` and `buildReturnTaint` are defined later in the file than `analyzeProjectTaint`. Function declarations are hoisted in Node, so calling `makeReturnTaintCtx` from inside `analyzeProjectTaint` is fine.

- [ ] **Step 3b: Orchestrate in `index.js`**

In `scripts/lib/taint/index.js`, import the new helpers (line 7):

```javascript
const { analyzeFunctionIntra, analyzeProjectTaint, buildReturnTaint, makeReturnTaintCtx } = require('./engine');
```

Move symbol-table construction up and build return-taint BEFORE the same-function emission loop. Replace lines 44-69 with:

```javascript
  coverage.ran = true;
  const symbols = buildSymbolTable(fileIRs);
  const returnSummary = buildReturnTaint(fileIRs, symbols);

  for (const ir of fileIRs) {
    const ctx = makeReturnTaintCtx(returnSummary, symbols, ir);
    for (const fn of ir.functions) {
      let res;
      try { res = analyzeFunctionIntra(fn, ir.path, [], ctx); }
      catch (e) { coverage.blindEdges += 1; continue; }
      for (const hit of res.sinkHits) {
        emitTaintFinding({
          sinkId: hit.sinkId,
          severity: hit.severity,
          hops: [
            { file: hit.file, line: fn.startLine, text: `entrada não confiável em ${fn.name}()`, role: 'source' },
            { file: hit.file, line: hit.line, text: hit.calleeDotted + '(...)', role: 'sink' }
          ]
        }, addFinding);
      }
    }
  }

  // Inter-procedural: source and sink in different functions/files.
  let inter;
  try { inter = analyzeProjectTaint(fileIRs, symbols, returnSummary); }
  catch (e) { inter = { paths: [], blindEdges: 1 }; }
  coverage.blindEdges += inter.blindEdges;
  for (const p of inter.paths) emitTaintFinding(p, addFinding);
```

(The `buildSymbolTable` require at line 9 stays; it is no longer used at the old line 64 since we moved it up — verify there is exactly one `buildSymbolTable(...)` call after this edit.)

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — the new test plus the whole suite green.

- [ ] **Step 5: Guard against double-emission (regression)**

Add and register `await testReturnTaintNoDoubleEmit();` to prove the existing direct-source case still emits exactly one finding (the intra pass owns it; the cross-function pass must not also emit it):

```javascript
async function testReturnTaintNoDoubleEmit() {
  const fixture = makeTempProject('rock-house-taint-nodupe-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'views.py', [
    'from flask import request',
    'def profile():',
    '    q = request.args["id"]',
    '    cur.execute(q)'
  ].join('\n'));
  const output = path.join(os.tmpdir(), `rock-house-taint-nodupe-${Date.now()}.json`);
  runScanner(fixture, output, 'bronze');
  const report = readJson(output);
  const hits = (report.findings || []).filter((f) => f.checkId === 'TAINT-SQLI');
  assert.strictEqual(hits.length, 1, 'direct-source sink emits exactly one finding, no duplicate');
}
```

Run: `node tests/rock-house-ci.test.js` — Expected: PASS. If it reports 2, the emit pass is double-counting external sinks; ensure `analyzeProjectTaint`'s emit pass still `continue`s on `resolution.kind !== 'function'` (external sinks remain owned by the intra pass).

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/taint/engine.js scripts/lib/taint/index.js tests/rock-house-ci.test.js
git commit -m "feat(taint): propagate return-taint end-to-end (source-returning helper SQLi)"
```

---

### Task 5: Keyword-argument support

Stop dropping `keyword_argument` nodes. Each becomes an arg describing its **value** expression, tagged with the keyword name. Sinks fire on a tainted keyword value; resolved repo calls map a keyword arg to the param of the same name.

**Files:**
- Modify: `scripts/lib/taint/ir.js` (`describeExpr` arg mapping, ~lines 44-49)
- Modify: `scripts/lib/taint/engine.js` (`computeParamCallFlows` param mapping ~line 187; emit pass param mapping ~line 306)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing tests**

Add and register `await testTaintKeywordArgIR();` and `await testTaintKeywordSink();`:

```javascript
async function testTaintKeywordArgIR() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const ir = buildFileIR(await parse('def v():\n    cur.execute(query=request.args["id"])\n'), 'v.py');
  const call = ir.functions[0].calls.find((c) => c.calleeDotted.endsWith('execute'));
  assert.strictEqual(call.args.length, 1, 'keyword arg is kept as an arg');
  assert.strictEqual(call.args[0].keyword, 'query', 'keyword name captured');
  assert.strictEqual(call.args[0].dotted, 'request.args', 'value expression described, not the kw name');
}

async function testTaintKeywordSink() {
  const fixture = makeTempProject('rock-house-taint-kwarg-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'views.py', [
    'from flask import request',
    'def profile():',
    '    cur.execute(query=request.args["id"])'
  ].join('\n'));
  const output = path.join(os.tmpdir(), `rock-house-taint-kwarg-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');
  assert.notStrictEqual(result.status, 0, 'tainted keyword arg into a sink must block');
  const report = readJson(output);
  assert(report.findings.find((f) => f.checkId === 'TAINT-SQLI'), 'kwarg sink TAINT-SQLI found');
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `call.args.length` is `0` (kwarg dropped); no kwarg finding.

- [ ] **Step 3: Keep keyword args in the IR**

In `scripts/lib/taint/ir.js`, replace the arg mapping in `describeExpr` (lines 45-49) with:

```javascript
    if (argList) {
      args = argList.namedChildren.map((a) => {
        if (a.type === 'keyword_argument') {
          const nameNode = a.childForFieldName('name');
          const valueNode = a.childForFieldName('value');
          const desc = describeExpr(valueNode, src);
          desc.keyword = nameNode ? textOf(nameNode, src) : null;
          return desc;
        }
        return describeExpr(a, src);
      });
    }
```

- [ ] **Step 4: Map keyword args to params by name (resolved calls)**

In `scripts/lib/taint/engine.js`, both places that map an arg index to a callee param by position must prefer name when the arg is a keyword.

In `computeParamCallFlows`, replace the positional lookup (line 187) `const calleeParam = (callee.params || [])[i];` with:

```javascript
        const calleeParam = argExpr.keyword
          ? (callee.params || []).find((p) => p === argExpr.keyword)
          : (callee.params || [])[i];
```

In the `analyzeProjectTaint` emit pass, replace the param lookup (line 306) `const param = callee.params[taintedArgIdx];` with:

```javascript
          const taintedArg = call.args[taintedArgIdx];
          const param = taintedArg && taintedArg.keyword
            ? (callee.params || []).find((p) => p === taintedArg.keyword)
            : callee.params[taintedArgIdx];
```

(Leave the existing `if (!summary || !param)` blind-edge guard immediately after — a kwarg naming a param the callee lacks now falls into that honest blind edge, not a silent drop.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — both new tests plus the full suite. Confirm `sqlIsParameterized` still behaves: `execute(sql, params)` positional safe-case tests stay green (kwargs don't change positional arg[0]/arg[1] handling).

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/taint/ir.js scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "feat(taint): support keyword arguments (IR + name-based param mapping)"
```

---

### Task 6: Repo hygiene (unblock `git diff --check` and clean status)

**Files:**
- Delete: `MAX_DEPTH` (junk file in repo root)
- Modify: `.gitignore`? No — **track** `.planning/phases/01-skill-router/01-RESEARCH.md`
- Modify: `scripts/vendor/README.md` (trailing whitespace), `docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md` (blank line at EOF)

- [ ] **Step 1: Verify the current offenders**

Run:
```bash
git status --short
git diff --check master...HEAD
```
Expected: shows untracked `MAX_DEPTH` and `.planning/phases/01-skill-router/01-RESEARCH.md`, and two whitespace warnings (`scripts/vendor/README.md:13` trailing whitespace, `docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md:281` blank line at EOF).

- [ ] **Step 2: Delete the junk file**

```bash
git rm --cached MAX_DEPTH 2>/dev/null; rm -f MAX_DEPTH
```
(It is untracked, so `rm -f MAX_DEPTH` alone suffices; the `git rm --cached` is a no-op safety net.)

- [ ] **Step 3: Fix the whitespace offenders**

Open `scripts/vendor/README.md`, remove the trailing whitespace on line 13. Open `docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md`, remove the trailing blank line at EOF (file must end with a single newline after the last content line).

- [ ] **Step 4: Verify clean**

Run:
```bash
git add scripts/vendor/README.md docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md .planning/phases/01-skill-router/01-RESEARCH.md
git diff --check master...HEAD
git status --short
```
Expected: `git diff --check` prints nothing; `git status --short` shows no `MAX_DEPTH` and the RESEARCH.md staged (no longer `??`).

- [ ] **Step 5: Commit**

```bash
git commit -m "chore: track skill-router research, drop junk file, fix whitespace"
```

---

### Task 7: `returnReachesBlind` — unknown return is a blind edge, not clean (Codex Ressalva 1)

A function whose return is the value of an **unresolved/external (non-sanitizer) call** has an
UNKNOWN return-taint. Today `callReturn` would answer `'clean'` for it (resolved callee, no
source, no param-return), so `def h(): return unknown(); q = h(); cur.execute(q)` is silently
clean. Honest behavior: that sink becomes a **blind edge** (lowers confidence), never a clean.

Depends on Tasks 2-4 (must be done after `buildReturnTaint`, `makeReturnTaintCtx`, and the
`index.js` wiring exist).

**Files:**
- Modify: `scripts/lib/taint/engine.js` (`buildReturnTaint`, `makeReturnTaintCtx`, `analyzeFunctionIntra`)
- Modify: `scripts/lib/taint/index.js` (consume the new `blindEdges` from the intra pass)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing test**

Add and register `await testReturnReachesBlindIsBlindEdge();`:

```javascript
async function testReturnReachesBlindIsBlindEdge() {
  const fixture = makeTempProject('rock-house-taint-retblind-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'helpers.py', [
    'def h():',
    '    return external_lib.fetch()'   // unresolved/external return — taint UNKNOWN
  ].join('\n'));
  writeFile(fixture, 'views.py', [
    'from helpers import h',
    'def profile():',
    '    q = h()',
    '    cur.execute(q)'
  ].join('\n'));
  const output = path.join(os.tmpdir(), `rock-house-taint-retblind-${Date.now()}.json`);
  runScanner(fixture, output, 'bronze');
  const report = readJson(output);
  assert(report.coverage.taint.ran === true, 'taint ran');
  assert(report.coverage.taint.blindEdges >= 1, 'unknown return reaching a sink is a blind edge');
  assert.notStrictEqual(report.confidence, 'Alta', 'unknown-return sink means confidence is not Alta');
  const hard = (report.findings || []).some((f) => f.checkId === 'TAINT-SQLI');
  assert.strictEqual(hard, false, 'unknown return is NOT a hard finding — it is a blind edge, honestly');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `blindEdges` is `0` (the silent-clean hole Codex flagged).

- [ ] **Step 3: Compute `returnReachesBlind` in `buildReturnTaint`**

In `scripts/lib/taint/engine.js`, inside `buildReturnTaint`, extend the per-function summary
and the fixpoint. In the base summary loop, after computing `paramReturnIdx`, add:

```javascript
      // returnReachesBlind: a return value that is a NON-sanitizer call resolving to
      // unresolved/external — we cannot know if its result is tainted.
      let returnReachesBlind = false;
      for (const r of fn.returns) {
        const v = r.value;
        if (!v || !v.isCall) continue;
        const last = (v.callee || '').split('.').pop();
        if (isSanitizer(last)) continue; // laundered → not blind
        const shim = { calleeDotted: v.callee || '', calleeLast: last, args: v.args || [] };
        const res = resolveCall(shim, ir, symbols);
        if (res.kind === 'unresolved' || res.kind === 'external') { returnReachesBlind = true; break; }
      }
      summary.set(fn.qualname, { returnIsSource: base.summary.returnIsSource, paramReturnIdx, returnReachesBlind });
```

(Replace the existing `summary.set(...)` line from Task 2 with the one above. Add
`const { isSourceExpr, sinkFor, isSanitizer } = require('./catalogs');` already exists at the
top of engine.js — `isSanitizer` is in scope.)

In the fixpoint loop, also propagate `returnReachesBlind` when a function returns a resolved
callee that itself reaches blind. Inside the fixpoint's `for (const r of fn.returns)` block,
after the `returnIsSource` propagation, add:

```javascript
          if (summary.get(res.fn.qualname) && summary.get(res.fn.qualname).returnReachesBlind && !s.returnReachesBlind) {
            s.returnReachesBlind = true; changed = true;
          }
```

- [ ] **Step 4: Add the `'blind'` verdict to `callReturn`**

In `makeReturnTaintCtx.callReturn` (Task 3), insert the blind check BEFORE the final `'clean'`:

```javascript
      if (s.returnIsSource) return true;
      for (const i of s.paramReturnIdx) {
        if (expr.args[i] && exprIsTainted(expr.args[i], taintedVars, ctx)) return true;
      }
      if (s.returnReachesBlind) return 'blind';   // resolved, but its own return is UNKNOWN
      return 'clean';
```

`exprIsTainted` must treat `'blind'` as NOT confirmed taint (so it does not become a hard
finding). In `exprIsTainted`, the existing `if (verdict === true) return true;` and
`if (verdict === 'clean') return false;` already leave `'blind'` to fall through to the
conservative arg-flow — for a no-arg call that yields `false`, which is what we want
(no hard finding). The blind-edge accounting happens in `analyzeFunctionIntra` (next step),
not in `exprIsTainted`.

- [ ] **Step 5: Track blind edges in `analyzeFunctionIntra`**

In `analyzeFunctionIntra`, add blind tracking. After `const tainted = new Set(seedParams);`
add:

```javascript
  let blindEdges = 0;
  const blindTainted = new Set(); // vars assigned from a call whose return-taint is UNKNOWN
```

In the assign branch, after the existing `tainted`/`sourceTainted` updates, add:

```javascript
      if (ctx && ctx.callReturn && ev.a.value && ev.a.value.isCall) {
        const verdict = ctx.callReturn(ev.a.value, tainted, ctx);
        for (const tgt of ev.a.targets) { if (verdict === 'blind') blindTainted.add(tgt); else blindTainted.delete(tgt); }
      }
```

In the sink branch, after the existing `if (!hit) continue;` is evaluated — replace that line
so a blind-tainted arg into a sink counts as a blind edge instead of being silently dropped:

```javascript
      if (!hit) {
        if ((call.args || []).some((arg) => (arg.reads || []).some((r) => blindTainted.has(r)))) blindEdges += 1;
        continue;
      }
```

Update the return statement to include `blindEdges`:

```javascript
  return { sinkHits, blindEdges, summary: { paramReachesSink, paramTaintsReturn, paramReachesBlind, returnIsSource } };
```

- [ ] **Step 6: Consume the intra blind edges in `index.js`**

In `scripts/lib/taint/index.js`, in the same-function emission loop (the one wired in Task 4),
after the `for (const hit of res.sinkHits) { ... }` block, add:

```javascript
      coverage.blindEdges += res.blindEdges || 0;
```

- [ ] **Step 7: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — the new test plus the whole suite green. Confirm `testTaintReturnSourceHelperIsFound`
(Task 4) still passes: a return-**source** is still a hard finding; only return-**unknown** is a blind edge.

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/taint/engine.js scripts/lib/taint/index.js tests/rock-house-ci.test.js
git commit -m "feat(taint): unknown return reaching a sink is a blind edge, not silent clean (Codex review)"
```

---

### Task 8: Keyword-aware `sqlIsParameterized` (Codex Ressalva 2)

`sqlIsParameterized` is positional (`engine.js:22`): it assumes `execute(sql, params)`. With
keyword args — especially out of order, `execute(params=(uid,), sql="... %s")` — the positional
`args[0]` is the params tuple, so a SAFE parameterized query is mis-flagged. Make it resolve the
SQL-string arg and the params arg by keyword when present. Do this AFTER Task 5 (kwargs in IR).

**Files:**
- Modify: `scripts/lib/taint/engine.js` (`sqlIsParameterized` and its call sites)
- Test: `tests/rock-house-ci.test.js`

- [ ] **Step 1: Write the failing tests**

Add and register `await testSqlParameterizedKwargs();`:

```javascript
async function testSqlParameterizedKwargs() {
  // SAFE: parameterized query with kwargs OUT OF ORDER → must NOT be flagged.
  let fixture = makeTempProject('rock-house-kwsql-safe-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'views.py', [
    'from flask import request',
    'def profile():',
    '    uid = request.args["id"]',
    '    cur.execute(params=(uid,), sql="SELECT * FROM u WHERE id = %s")'
  ].join('\n'));
  let output = path.join(os.tmpdir(), `rock-house-kwsql-safe-${Date.now()}.json`);
  runScanner(fixture, output, 'bronze');
  let report = readJson(output);
  assert(!(report.findings || []).some((f) => f.checkId === 'TAINT-SQLI'),
    'parameterized query with out-of-order kwargs is safe, not a finding');

  // VULN: the SQL string itself is tainted via a kwarg → must be flagged.
  fixture = makeTempProject('rock-house-kwsql-vuln-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'views.py', [
    'from flask import request',
    'def profile():',
    '    uid = request.args["id"]',
    '    cur.execute(sql=uid)'
  ].join('\n'));
  output = path.join(os.tmpdir(), `rock-house-kwsql-vuln-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');
  assert.notStrictEqual(result.status, 0, 'tainted SQL string via kwarg must block');
  report = readJson(output);
  assert((report.findings || []).some((f) => f.checkId === 'TAINT-SQLI'), 'tainted sql= kwarg is a finding');
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — the SAFE out-of-order case is mis-flagged (positional `args[0]` is the tainted params tuple).

- [ ] **Step 3: Make `sqlIsParameterized` keyword-aware**

In `scripts/lib/taint/engine.js`, replace `sqlIsParameterized` (lines 21-25) with:

```javascript
const SQL_STRING_KW = new Set(['sql', 'query', 'statement', 'operation']);
const SQL_PARAMS_KW = new Set(['params', 'parameters', 'vars', 'args', 'parameter']);

// execute(sql, params) is safe when the tainted value is only in the params, not the SQL string.
// Keyword-aware: the SQL-string arg may be sql=/query=/statement=, the params arg params=/vars=.
function sqlIsParameterized(call, taintedVars, ctx) {
  const args = call.args || [];
  let sqlArg = args.find((a) => a.keyword && SQL_STRING_KW.has(a.keyword));
  let hasParams;
  if (sqlArg) {
    hasParams = args.some((a) => a !== sqlArg && (!a.keyword || SQL_PARAMS_KW.has(a.keyword)));
  } else {
    if (args.length < 2) return false;            // single positional arg → not parameterized
    sqlArg = args[0];
    hasParams = true;                             // positional 2nd arg present
  }
  if (!hasParams) return false;
  return !exprIsTainted(sqlArg, taintedVars, ctx);
}
```

Thread `ctx` through the four call sites so return-taint resolution stays consistent (ctx is
optional; existing callers without ctx keep working): in `analyzeFunctionIntra` (the sink line
~61), in `computeParamCallFlows` (lines ~165 and ~184), and in the `analyzeProjectTaint` emit
pass (line ~300). Each `sqlIsParameterized(call, taintedVars)` becomes
`sqlIsParameterized(call, taintedVars, ctx)` where a `ctx` is in scope (pass `null` where none).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — both new cases plus the existing positional `execute(sql, params)` safe-case test stay green.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "fix(taint): keyword-aware sqlIsParameterized (out-of-order kwargs no longer false-positive)"
```

---

## Final verification (run before handing back for merge)

- [ ] `node tests/rock-house-ci.test.js` → ends with `rock-house-ci tests passed`.
- [ ] `node scripts/rock-house-ci.js --path examples/vulnerable-demo ...` (the demo) still exits non-zero (demo blocks). Use the demo command from the repo `CLAUDE.md`.
- [ ] Self-scan still earns Ouro 10/10 (run the self-scan command from the repo `CLAUDE.md`; `scripts/vendor` stays excluded).
- [ ] `git diff --check master...HEAD` clean; `git status --short` shows no junk.

## Self-review notes

- **Spec coverage:** Part A (return-taint) → Tasks 1-4; Part B (kwargs) → Task 5; Part D (hygiene) → Task 6. Part C (PY-DEBUG) is a SEPARATE plan/branch (`2026-06-03-py-debug-false-positive.md`), per the spec decision.
- **Type consistency:** summary field `returnIsSource` (bool) and `paramTaintsReturn` (Set) are produced in Task 1, consumed via `buildReturnTaint` (Task 2) as `{ returnIsSource, paramReturnIdx:Set<int> }`, consumed by `makeReturnTaintCtx.callReturn` (Task 3), passed to `analyzeProjectTaint(...returnSummary)` (Task 4). `keyword` field on an arg expr is produced in Task 5 (ir.js) and consumed in the two param-mapping sites (engine.js).
- **Honesty invariant preserved:** unresolved/external return-producers yield `'unknown'` → conservative arg-flow (never a silent clean); kwarg naming an absent param → existing blind-edge guard.
