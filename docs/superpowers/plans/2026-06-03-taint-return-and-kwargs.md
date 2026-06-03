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

## Final verification (run before handing back for merge)

- [ ] `node tests/rock-house-ci.test.js` → ends with `rock-house-ci tests passed`.
- [ ] `node scripts/rock-house-ci.js --path examples/vulnerable-demo ...` (the demo) still exits non-zero (demo blocks). Use the demo command from the repo `CLAUDE.md`.
- [ ] Self-scan still earns Ouro 10/10 (run the self-scan command from the repo `CLAUDE.md`; `scripts/vendor` stays excluded).
- [ ] `git diff --check master...HEAD` clean; `git status --short` shows no junk.

## Self-review notes

- **Spec coverage:** Part A (return-taint) → Tasks 1-4; Part B (kwargs) → Task 5; Part D (hygiene) → Task 6. Part C (PY-DEBUG) is a SEPARATE plan/branch (`2026-06-03-py-debug-false-positive.md`), per the spec decision.
- **Type consistency:** summary field `returnIsSource` (bool) and `paramTaintsReturn` (Set) are produced in Task 1, consumed via `buildReturnTaint` (Task 2) as `{ returnIsSource, paramReturnIdx:Set<int> }`, consumed by `makeReturnTaintCtx.callReturn` (Task 3), passed to `analyzeProjectTaint(...returnSummary)` (Task 4). `keyword` field on an arg expr is produced in Task 5 (ir.js) and consumed in the two param-mapping sites (engine.js).
- **Honesty invariant preserved:** unresolved/external return-producers yield `'unknown'` → conservative arg-flow (never a silent clean); kwarg naming an absent param → existing blind-edge guard.
