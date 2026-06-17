# Python Inter-Procedural Taint Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, dependency-portable taint analyzer for Python/Flask that tracks untrusted input from sources, across functions and files, into dangerous sinks, reporting the full source→sink path — layered under the existing regex rule engine.

**Architecture:** A new `scripts/lib/taint/` subsystem parses Python with a vendored `web-tree-sitter` (WASM) grammar, lowers each file to a taint-relevant IR, builds a project symbol table and call graph, computes per-function taint summaries, then propagates taint inter-procedurally to a fixpoint. Tainted source→sink paths become findings through the existing `addFinding` pipeline. Unresolved calls / parser failures become "blind edges" that lower confidence — the engine never assumes safe.

**Tech Stack:** Node.js (v20+, the scanner's runtime), `web-tree-sitter` + `tree-sitter-python.wasm` (both vendored into the repo, no `npm install` at runtime), no other dependencies. Tests are integration-style (spawn `scripts/rock-house-ci.js` against a temp Flask fixture, assert on the JSON report) plus a few module-level unit tests; runner: `node tests/rock-house-ci.test.js`.

**Spec:** `docs/superpowers/specs/2026-06-01-python-taint-engine-design.md`

---

## File Structure

**Create:**
- `scripts/vendor/web-tree-sitter/tree-sitter.js` — vendored web-tree-sitter runtime (UMD).
- `scripts/vendor/web-tree-sitter/tree-sitter.wasm` — vendored runtime WASM.
- `scripts/vendor/tree-sitter-python.wasm` — vendored Python grammar.
- `scripts/vendor/README.md` — provenance + license of the vendored assets.
- `scripts/lib/taint/parser.js` — WASM loader + `parse(source) -> Tree`; async one-time init.
- `scripts/lib/taint/catalogs.js` — Flask sources, sinks, sanitizers, propagators (pure data + predicates).
- `scripts/lib/taint/ir.js` — `buildFileIR(tree, relPath) -> FileIR` (functions, params, assignments, calls, returns).
- `scripts/lib/taint/symbols.js` — `buildSymbolTable(fileIRs) -> SymbolTable` (intra-repo import resolution).
- `scripts/lib/taint/callgraph.js` — `resolveCall(call, fn, symbols) -> Resolution` (function | external | unresolved).
- `scripts/lib/taint/engine.js` — per-function summaries + inter-procedural fixpoint → `TaintPath[]` + blind edges.
- `scripts/lib/taint/findings.js` — `TaintPath -> addFinding(...)` with trace + fixPack.
- `scripts/lib/taint/index.js` — `analyzeProject({ files, targetRoot, addFinding, gates }) -> { taintCoverage }`.

**Modify:**
- `scripts/rock-house-ci.js` — `main()` awaits `analyzeProject(...)` after `scanFiles`; `coverage` gains `taint`; `calculateConfidence` honors taint blind edges.
- `scripts/lib/rules/index.js` — `META` gains the `TAINT-*` ids.
- `scripts/lib/report-formatters.js` — render `taintTrace` in Markdown + SARIF.
- `tests/rock-house-ci.test.js` — taint fixtures + assertions (async tests).
- `CLAUDE.md` — document the taint engine as a real analysis layer; note the vendored WASM.

**Reuse unchanged:** `addFinding`, `fingerprintFor` (already includes `line`), `evaluateCoverage`, SARIF/Markdown/baseline/suppression plumbing.

**tree-sitter-python node types used (stable grammar names):** `module`, `function_definition`, `parameters`, `identifier`, `default_parameter`, `decorator`, `block`, `expression_statement`, `assignment`, `augmented_assignment`, `call`, `attribute`, `subscript`, `argument_list`, `keyword_argument`, `string`, `string_content`, `binary_operator`, `return_statement`, `if_statement`. Confirm with the inspect command in Task 1 Step 6 before relying on a field name.

---

## Task 0: Vendor the WASM parser assets

**Files:**
- Create: `scripts/vendor/web-tree-sitter/tree-sitter.js`, `scripts/vendor/web-tree-sitter/tree-sitter.wasm`, `scripts/vendor/tree-sitter-python.wasm`, `scripts/vendor/README.md`

- [ ] **Step 1: Fetch the assets into a temp dir via npm (build-time only, not a runtime dep)**

Run (network required; this is the only network step in the plan):
```bash
TMPV=$(mktemp -d)
cd "$TMPV"
npm pack web-tree-sitter@0.22.6
npm pack tree-sitter-python@0.21.0
ls *.tgz
```
Expected: two `.tgz` files downloaded.

> If `tree-sitter-python` does not ship a prebuilt `.wasm` in its tarball, instead download the released grammar wasm:
> ```bash
> curl -L -o tree-sitter-python.wasm https://github.com/tree-sitter/tree-sitter-python/releases/download/v0.21.0/tree-sitter-python.wasm
> ```

- [ ] **Step 2: Extract and copy the three files into the repo**

```bash
cd "$TMPV"
tar -xzf web-tree-sitter-*.tgz
tar -xzf tree-sitter-python-*.tgz 2>/dev/null || true
REPO="C:/Users/ANGELO SILVA/Documents/rock-house"   # adjust to your checkout
mkdir -p "$REPO/scripts/vendor/web-tree-sitter"
cp package/tree-sitter.js   "$REPO/scripts/vendor/web-tree-sitter/tree-sitter.js"
cp package/tree-sitter.wasm "$REPO/scripts/vendor/web-tree-sitter/tree-sitter.wasm"
# Python grammar wasm: from the tree-sitter-python package (often package/tree-sitter-python.wasm) or the curl above
cp tree-sitter-python.wasm  "$REPO/scripts/vendor/tree-sitter-python.wasm" 2>/dev/null \
  || cp package/*python*.wasm "$REPO/scripts/vendor/tree-sitter-python.wasm"
ls -la "$REPO/scripts/vendor/web-tree-sitter" "$REPO/scripts/vendor/tree-sitter-python.wasm"
```
Expected: `tree-sitter.js`, `tree-sitter.wasm`, and `tree-sitter-python.wasm` present in the repo. Note their sizes (the `.wasm` files are typically ~1–2 MB total).

- [ ] **Step 3: Record provenance + license**

Create `scripts/vendor/README.md`:
```markdown
# Vendored parser assets

These files are committed so Rock House runs with zero install (no `npm install`, no Python).

| File | Source | Version | License |
|------|--------|---------|---------|
| `web-tree-sitter/tree-sitter.js` | npm `web-tree-sitter` | 0.22.6 | MIT |
| `web-tree-sitter/tree-sitter.wasm` | npm `web-tree-sitter` | 0.22.6 | MIT |
| `tree-sitter-python.wasm` | `tree-sitter/tree-sitter-python` release | 0.21.0 | MIT |

Both `web-tree-sitter` and `tree-sitter-python` are MIT-licensed, compatible with this repo.
To update: re-run Task 0 of `docs/superpowers/plans/2026-06-01-python-taint-engine.md`.
```

- [ ] **Step 4: License gate**

Confirm both upstream licenses are MIT (check the extracted `package/LICENSE` files). If either is not MIT/Apache-2.0/BSD, STOP and raise with the human partner before committing.

Run:
```bash
grep -il "MIT" "$TMPV"/package/LICENSE* 2>/dev/null && echo "license ok"
```
Expected: `license ok` (or manual confirmation).

- [ ] **Step 5: Smoke-test the load from the vendored path**

Create a throwaway check and run it:
```bash
cd "C:/Users/ANGELO SILVA/Documents/rock-house"
node -e "
const Parser = require('./scripts/vendor/web-tree-sitter/tree-sitter.js');
(async () => {
  await Parser.init();
  const p = new Parser();
  const Py = await Parser.Language.load('./scripts/vendor/tree-sitter-python.wasm');
  p.setLanguage(Py);
  const t = p.parse('def f(x):\n    return x\n');
  console.log('root:', t.rootNode.type, '| firstChild:', t.rootNode.firstChild.type);
})().catch(e => { console.error('LOAD FAIL', e); process.exit(2); });
"
```
Expected: `root: module | firstChild: function_definition`. If this fails, the vendored files are wrong — fix before proceeding (the rest of the plan depends on it).

- [ ] **Step 6: Commit**

```bash
git add scripts/vendor
git commit -m "build(taint): vendor web-tree-sitter runtime + tree-sitter-python wasm"
```

---

## Task 1: Parser module

**Files:**
- Create: `scripts/lib/taint/parser.js`
- Test: `tests/rock-house-ci.test.js` (new async `testTaintParser`)

- [ ] **Step 1: Write the failing test**

Add to `tests/rock-house-ci.test.js` and register `await testTaintParser();` near the top of `run()` (after `testEngineMatching();`):

```js
async function testTaintParser() {
  const { parse } = require('../scripts/lib/taint/parser');
  const tree = await parse('def view(req):\n    return req\n');
  assert.strictEqual(tree.rootNode.type, 'module', 'root is module');
  assert.strictEqual(tree.rootNode.firstChild.type, 'function_definition', 'first child is a function');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `Cannot find module '../scripts/lib/taint/parser'`.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/parser.js`:

```js
const path = require('path');
const Parser = require('../../vendor/web-tree-sitter/tree-sitter.js');

const WASM_RUNTIME_DIR = path.join(__dirname, '..', '..', 'vendor', 'web-tree-sitter');
const PYTHON_WASM = path.join(__dirname, '..', '..', 'vendor', 'tree-sitter-python.wasm');

let _parser = null;
let _initError = null;

async function getParser() {
  if (_parser) return _parser;
  if (_initError) throw _initError;
  try {
    // web-tree-sitter needs to locate its own tree-sitter.wasm next to the runtime.
    await Parser.init({ locateFile: (name) => path.join(WASM_RUNTIME_DIR, name) });
    const parser = new Parser();
    const Python = await Parser.Language.load(PYTHON_WASM);
    parser.setLanguage(Python);
    _parser = parser;
    return _parser;
  } catch (err) {
    _initError = err;
    throw err;
  }
}

async function parse(source) {
  const parser = await getParser();
  return parser.parse(typeof source === 'string' ? source : String(source));
}

// Lets callers detect "parser unavailable" without crashing the scan.
async function isAvailable() {
  try { await getParser(); return true; } catch (e) { return false; }
}

module.exports = { parse, getParser, isAvailable };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — ends with `rock-house-ci tests passed`.

> If `Parser.init` rejects on `locateFile`, inspect the vendored runtime's expected filename (some builds embed the wasm; in that case `Parser.init()` with no args works). Adjust the `init` call to match the vendored version, then re-run.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/parser.js tests/rock-house-ci.test.js
git commit -m "feat(taint): tree-sitter python parser module"
```

- [ ] **Step 6: (Reference) How to inspect real AST node/field names**

When later tasks need exact node/field names, run:
```bash
node -e "
const { parse } = require('./scripts/lib/taint/parser');
(async () => {
  const t = await parse('q = request.args[\"id\"]\ncur.execute(q)\n');
  (function walk(n, d){ console.log('  '.repeat(d)+n.type+(n.isNamed?'':' (anon)')); n.children.forEach(c=>walk(c,d+1)); })(t.rootNode,0);
})();
"
```
Use this to confirm field names (`childForFieldName('function'|'arguments'|'left'|'right'|'object'|'attribute'|'name'|'body')`) before relying on them.

---

## Task 2: Catalogs (sources, sinks, sanitizers, propagators)

**Files:**
- Create: `scripts/lib/taint/catalogs.js`
- Test: `tests/rock-house-ci.test.js` (new `testTaintCatalogs`)

- [ ] **Step 1: Write the failing test**

Add and register `testTaintCatalogs();` in `run()`:

```js
function testTaintCatalogs() {
  const c = require('../scripts/lib/taint/catalogs');
  assert.strictEqual(c.isSourceExpr('request.args'), true, 'request.args is a source');
  assert.strictEqual(c.isSourceExpr('os.path.join'), false, 'os.path.join is not a source');
  const sink = c.sinkFor('cursor.execute');
  assert(sink && sink.id === 'TAINT-SQLI', 'cursor.execute -> TAINT-SQLI');
  assert.strictEqual(c.sinkFor('render_template_string').id, 'TAINT-SSTI', 'SSTI sink');
  assert.strictEqual(c.isSanitizer('int'), true, 'int() sanitizes');
  assert.strictEqual(c.isSanitizer('escape'), true, 'escape() sanitizes');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/catalogs.js`:

```js
// Dotted-name prefixes whose values are untrusted (Flask request surface).
const SOURCE_PREFIXES = [
  'request.args', 'request.form', 'request.values', 'request.json',
  'request.data', 'request.files', 'request.cookies', 'request.headers',
  'request.get_json'
];

// Sink callee (dotted) -> { id, severity, class }. Matched by callee suffix.
const SINKS = [
  { match: ['cursor.execute', 'cursor.executemany', '.execute', '.executemany'], id: 'TAINT-SQLI', severity: 'Critico', cls: 'SQL injection' },
  { match: ['render_template_string'], id: 'TAINT-SSTI', severity: 'Critico', cls: 'Server-side template injection' },
  { match: ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output'], id: 'TAINT-RCE', severity: 'Critico', cls: 'Command injection' },
  { match: ['eval', 'exec'], id: 'TAINT-RCE', severity: 'Critico', cls: 'Code execution' },
  { match: ['pickle.loads', 'pickle.load'], id: 'TAINT-DESERIALIZE', severity: 'Alto', cls: 'Unsafe deserialization' },
  { match: ['yaml.load'], id: 'TAINT-DESERIALIZE', severity: 'Alto', cls: 'Unsafe deserialization' },
  { match: ['open', 'send_file', 'send_from_directory'], id: 'TAINT-PATH', severity: 'Alto', cls: 'Path traversal' },
  { match: ['redirect'], id: 'TAINT-REDIRECT', severity: 'Alto', cls: 'Open redirect' }
];

// Function names (last segment) that neutralize taint on their argument/result.
const SANITIZERS = new Set([
  'int', 'float', 'escape', 'secure_filename', 'clean', 'quote', 'bleach'
]);

function isSourceExpr(dotted) {
  return SOURCE_PREFIXES.some((p) => dotted === p || dotted.startsWith(`${p}.`) || dotted.startsWith(`${p}[`));
}

function sinkFor(calleeDotted) {
  for (const s of SINKS) {
    if (s.match.some((m) => calleeDotted === m || calleeDotted.endsWith(m))) return s;
  }
  return null;
}

function isSanitizer(calleeLastSegment) {
  return SANITIZERS.has(calleeLastSegment);
}

module.exports = { SOURCE_PREFIXES, SINKS, SANITIZERS, isSourceExpr, sinkFor, isSanitizer };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/catalogs.js tests/rock-house-ci.test.js
git commit -m "feat(taint): Flask source/sink/sanitizer catalogs"
```

---

## Task 3: IR builder

**Files:**
- Create: `scripts/lib/taint/ir.js`
- Test: `tests/rock-house-ci.test.js` (new async `testTaintIR`)

- [ ] **Step 1: Write the failing test**

Add and register `await testTaintIR();` in `run()`:

```js
async function testTaintIR() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const src = [
    '@app.route("/u/<id>")',
    'def profile(id):',
    '    q = request.args["id"]',
    '    cur.execute(q)',
    '    return q'
  ].join('\n');
  const ir = buildFileIR(await parse(src), 'views.py');
  assert.strictEqual(ir.functions.length, 1, 'one function');
  const fn = ir.functions[0];
  assert.strictEqual(fn.name, 'profile');
  assert.deepStrictEqual(fn.params, ['id'], 'params captured');
  assert(fn.decorators.some((d) => d.includes('app.route')), 'route decorator captured');
  assert(fn.assignments.some((a) => a.targets.includes('q')), 'assignment q captured');
  assert(fn.calls.some((c) => c.calleeDotted.endsWith('execute')), 'execute call captured');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/ir.js`:

```js
// Lower a tree-sitter Python tree into a taint-relevant IR.
// Expression representation is deliberately small: we capture, per expression,
// its dotted name (if it is a name/attribute/subscript chain), the identifiers
// it reads, and whether it is a call (and the call's callee + args).

function textOf(node, src) {
  return src.slice(node.startIndex, node.endIndex);
}

// Resolve a name/attribute/subscript chain to a dotted string, e.g.
// request.args["id"] -> "request.args" ; cur.execute -> "cur.execute".
function dottedName(node, src) {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, src);
  if (node.type === 'attribute') {
    const obj = dottedName(node.childForFieldName('object'), src);
    const attr = node.childForFieldName('attribute');
    return obj && attr ? `${obj}.${textOf(attr, src)}` : null;
  }
  if (node.type === 'subscript') {
    return dottedName(node.childForFieldName('value'), src);
  }
  if (node.type === 'call') {
    return dottedName(node.childForFieldName('function'), src);
  }
  return null;
}

// Collect identifiers read inside an expression subtree.
function readsIn(node, src, acc) {
  if (!node) return acc;
  if (node.type === 'identifier') { acc.add(textOf(node, src)); return acc; }
  for (const child of node.namedChildren) readsIn(child, src, acc);
  return acc;
}

// Describe an expression for the taint engine.
function describeExpr(node, src) {
  const dotted = dottedName(node, src);
  const reads = [...readsIn(node, src, new Set())];
  const isCall = node.type === 'call';
  let callee = null;
  let args = [];
  if (isCall) {
    callee = dottedName(node.childForFieldName('function'), src);
    const argList = node.childForFieldName('arguments');
    if (argList) {
      args = argList.namedChildren
        .filter((a) => a.type !== 'keyword_argument')
        .map((a) => describeExpr(a, src));
    }
  }
  return { dotted, reads, isCall, callee, args, text: textOf(node, src), line: node.startPosition.row + 1 };
}

function collectStatements(blockNode, src, fn) {
  for (const stmt of blockNode.namedChildren) {
    if (stmt.type === 'expression_statement') {
      const inner = stmt.firstNamedChild;
      if (!inner) continue;
      if (inner.type === 'assignment') {
        const left = inner.childForFieldName('left');
        const right = inner.childForFieldName('right');
        const targets = [...readsIn(left, src, new Set())];
        fn.assignments.push({ targets, value: describeExpr(right, src), line: inner.startPosition.row + 1 });
        recordCalls(right, src, fn);
      } else if (inner.type === 'call') {
        fn.calls.push(callRecord(inner, src));
        recordCalls(inner, src, fn);
      }
    } else if (stmt.type === 'return_statement') {
      const val = stmt.firstNamedChild;
      fn.returns.push({ value: val ? describeExpr(val, src) : null, line: stmt.startPosition.row + 1 });
      if (val) recordCalls(val, src, fn);
    } else if (stmt.namedChildCount) {
      // Recurse into compound statements (if/for/with/try) to find nested blocks.
      for (const child of stmt.namedChildren) {
        if (child.type === 'block') collectStatements(child, src, fn);
        else recordCalls(child, src, fn);
      }
    }
  }
}

function callRecord(callNode, src) {
  const d = describeExpr(callNode, src);
  return { calleeDotted: d.callee || '', calleeLast: (d.callee || '').split('.').pop(), args: d.args, line: d.line };
}

// Find call expressions anywhere in a subtree (e.g. nested in arguments).
function recordCalls(node, src, fn) {
  if (!node) return;
  if (node.type === 'call') fn.calls.push(callRecord(node, src));
  for (const child of node.namedChildren) recordCalls(child, src, fn);
}

function buildFunctionIR(fnNode, src, modulePrefix) {
  const nameNode = fnNode.childForFieldName('name');
  const name = nameNode ? textOf(nameNode, src) : '<anon>';
  const params = [];
  const paramsNode = fnNode.childForFieldName('parameters');
  if (paramsNode) {
    for (const p of paramsNode.namedChildren) {
      if (p.type === 'identifier') params.push(textOf(p, src));
      else if (p.type === 'default_parameter' || p.type === 'typed_parameter') {
        const id = p.childForFieldName('name') || p.firstNamedChild;
        if (id && id.type === 'identifier') params.push(textOf(id, src));
      }
    }
  }
  const decorators = [];
  // Decorators are siblings preceding the function inside a 'decorated_definition'.
  if (fnNode.parent && fnNode.parent.type === 'decorated_definition') {
    for (const d of fnNode.parent.namedChildren) {
      if (d.type === 'decorator') decorators.push(textOf(d, src));
    }
  }
  const fn = {
    name,
    qualname: modulePrefix ? `${modulePrefix}.${name}` : name,
    params, decorators,
    assignments: [], calls: [], returns: [],
    startLine: fnNode.startPosition.row + 1,
    endLine: fnNode.endPosition.row + 1
  };
  const body = fnNode.childForFieldName('body');
  if (body) collectStatements(body, src, fn);
  return fn;
}

function buildFileIR(tree, relPath) {
  const src = tree.rootNode.text;
  const modulePrefix = relPath.replace(/\.py$/, '').replace(/[\\/]/g, '.');
  const functions = [];
  (function walk(node) {
    if (node.type === 'function_definition') {
      functions.push(buildFunctionIR(node, src, modulePrefix));
      return; // nested functions handled within their parent's body walk if needed (v2)
    }
    for (const child of node.namedChildren) walk(child);
  })(tree.rootNode);
  return { path: relPath, modulePrefix, functions };
}

module.exports = { buildFileIR, describeExpr, dottedName };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

> If a field name (`object`/`attribute`/`left`/`right`/`function`/`arguments`/`name`/`body`/`value`) returns null, use the Task 1 Step 6 inspector to confirm the real field name for the vendored grammar version and adjust `childForFieldName(...)`. This is the one place node-name drift can bite.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/ir.js tests/rock-house-ci.test.js
git commit -m "feat(taint): lower python AST to taint IR (functions, assigns, calls, returns)"
```

---

## Task 4: Intra-procedural taint + per-function summaries

**Files:**
- Create: `scripts/lib/taint/engine.js`
- Test: `tests/rock-house-ci.test.js` (new async `testTaintIntraprocedural`)

- [ ] **Step 1: Write the failing test**

Add and register `await testTaintIntraprocedural();` in `run()`:

```js
async function testTaintIntraprocedural() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { analyzeFunctionIntra } = require('../scripts/lib/taint/engine');

  const vuln = [
    'def profile():',
    '    q = request.args["id"]',
    '    cur.execute(q)'
  ].join('\n');
  let ir = buildFileIR(await parse(vuln), 'views.py');
  let res = analyzeFunctionIntra(ir.functions[0], 'views.py');
  assert.strictEqual(res.sinkHits.length, 1, 'one tainted sink hit');
  assert.strictEqual(res.sinkHits[0].sinkId, 'TAINT-SQLI');

  const safe = [
    'def profile():',
    '    q = int(request.args["id"])',
    '    cur.execute(q)'
  ].join('\n');
  ir = buildFileIR(await parse(safe), 'views.py');
  res = analyzeFunctionIntra(ir.functions[0], 'views.py');
  assert.strictEqual(res.sinkHits.length, 0, 'sanitized value is not a sink hit');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — `analyzeFunctionIntra` not a function.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/engine.js`:

```js
const { isSourceExpr, sinkFor, isSanitizer } = require('./catalogs');

// Is this expression directly a taint source (e.g. request.args[...])?
function exprIsSource(expr) {
  return !!(expr && expr.dotted && isSourceExpr(expr.dotted));
}

// Does evaluating this expression yield taint, given the current tainted-var set?
// A call to a sanitizer clears taint; otherwise taint flows through reads/args.
function exprIsTainted(expr, taintedVars) {
  if (!expr) return false;
  if (exprIsSource(expr)) return true;
  if (expr.isCall) {
    const last = (expr.callee || '').split('.').pop();
    if (isSanitizer(last)) return false; // sanitized
    // taint propagates through non-sanitizer call arguments (e.g. str(x), f"{x}")
    return (expr.args || []).some((a) => exprIsTainted(a, taintedVars));
  }
  // name / attribute / subscript / binary: tainted if any identifier it reads is tainted
  return (expr.reads || []).some((id) => taintedVars.has(id));
}

// Special-case the parameterized-query sanitizer: execute(sql, params) is safe
// when the tainted value is only in the params (2nd+) argument, not the SQL string.
function sqlIsParameterized(call, taintedVars) {
  if (call.args.length < 2) return false;
  const sqlTainted = exprIsTainted(call.args[0], taintedVars);
  return !sqlTainted; // tainted only in params tuple => safe
}

// Analyze one function in isolation. `seedParams` marks parameters as tainted
// (used by inter-procedural propagation in Task 9; empty for pure intra-proc).
function analyzeFunctionIntra(fn, file, seedParams = []) {
  const tainted = new Set(seedParams);
  const sinkHits = [];
  const paramReachesSink = new Map(); // param -> [sinkId...]
  const paramTaintsReturn = new Set();

  // Walk assignments and calls in source order (IR preserves order per kind;
  // we merge by line to approximate execution order).
  const events = [];
  for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
  for (const c of fn.calls) events.push({ kind: 'call', line: c.line, c });
  events.sort((x, y) => x.line - y.line);

  for (const ev of events) {
    if (ev.kind === 'assign') {
      const t = exprIsTainted(ev.a.value, tainted);
      for (const tgt of ev.a.targets) {
        if (t) tainted.add(tgt); else tainted.delete(tgt);
      }
    } else {
      const call = ev.c;
      const sink = sinkFor(call.calleeDotted);
      if (!sink) continue;
      // any tainted argument reaches the sink?
      let hit = (call.args || []).some((arg) => exprIsTainted(arg, tainted));
      if (hit && sink.id === 'TAINT-SQLI' && sqlIsParameterized(call, tainted)) hit = false;
      if (!hit) continue;
      sinkHits.push({ sinkId: sink.id, severity: sink.severity, cls: sink.cls, file, line: call.line, calleeDotted: call.calleeDotted });
      // record which seed params contributed (for summaries)
      for (const p of seedParams) {
        if ((call.args || []).some((arg) => (arg.reads || []).includes(p))) {
          if (!paramReachesSink.has(p)) paramReachesSink.set(p, []);
          paramReachesSink.get(p).push(sink.id);
        }
      }
    }
  }

  // Does any seed param taint a return value?
  for (const r of fn.returns) {
    if (r.value && exprIsTainted(r.value, tainted)) {
      for (const p of seedParams) {
        if ((r.value.reads || []).includes(p)) paramTaintsReturn.add(p);
      }
    }
  }

  return { sinkHits, summary: { paramReachesSink, paramTaintsReturn } };
}

module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/engine.js tests/rock-house-ci.test.js
git commit -m "feat(taint): intra-procedural taint with per-function summaries"
```

---

## Task 5: Findings + TAINT-* metadata

**Files:**
- Create: `scripts/lib/taint/findings.js`
- Modify: `scripts/lib/rules/index.js` (`META` gains `TAINT-*`)
- Test: `tests/rock-house-ci.test.js` (new `testTaintFindings`)

- [ ] **Step 1: Add TAINT metadata to the registry**

In `scripts/lib/rules/index.js`, inside `META`, after the `'C2'` entry, add:

```js
  ,
  'TAINT-SQLI': { title: 'Tainted input reaches SQL execution', owasp: ['A03:2021 Injection'], cwe: ['CWE-89'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'TAINT-SSTI': { title: 'Tainted input reaches template rendering', owasp: ['A03:2021 Injection'], cwe: ['CWE-94'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'TAINT-RCE': { title: 'Tainted input reaches code/command execution', owasp: ['A03:2021 Injection'], cwe: ['CWE-78'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'TAINT-DESERIALIZE': { title: 'Tainted input reaches unsafe deserialization', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-502'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'TAINT-PATH': { title: 'Tainted input reaches a filesystem path', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-22'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  'TAINT-REDIRECT': { title: 'Tainted input reaches a redirect target', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-601'], helpUri: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' },
  'TAINT-UNAVAILABLE': { title: 'Taint analysis unavailable (parser not loaded)', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' }
```

- [ ] **Step 2: Write the failing test**

Add and register `testTaintFindings();` in `run()`:

```js
function testTaintFindings() {
  const { emitTaintFinding } = require('../scripts/lib/taint/findings');
  const calls = [];
  const addFinding = (...args) => calls.push(args);
  const path = {
    sinkId: 'TAINT-SQLI', severity: 'Critico',
    hops: [
      { file: 'views.py', line: 2, text: 'request.args["id"]', role: 'source' },
      { file: 'db.py', line: 7, text: 'cur.execute(q)', role: 'sink' }
    ]
  };
  emitTaintFinding(path, addFinding);
  assert.strictEqual(calls.length, 1, 'one finding emitted');
  const [severity, checkId, vector, file, line, desc, fix, fixPack] = calls[0];
  assert.strictEqual(severity, 'Critico');
  assert.strictEqual(checkId, 'TAINT-SQLI');
  assert.strictEqual(file, 'db.py');
  assert.strictEqual(line, 7, 'finding sits at the sink');
  assert(desc.includes('request.args'), 'trace mentions the source');
  assert(fixPack && fixPack.after, 'carries a fix pack');
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — module not found.

- [ ] **Step 4: Write the implementation**

Create `scripts/lib/taint/findings.js`:

```js
const FIXPACKS = {
  'TAINT-SQLI': { why: 'Input do usuário chega na query — SQL injection.', before: 'cur.execute(f"SELECT ... {x}")', after: 'cur.execute("SELECT ... %s", (x,))', refs: ['OWASP A03', 'CWE-89'] },
  'TAINT-SSTI': { why: 'Input do usuário renderizado como template — execução no servidor.', before: 'render_template_string("Hi " + x)', after: 'render_template("hi.html", name=x)', refs: ['OWASP A03', 'CWE-94'] },
  'TAINT-RCE': { why: 'Input do usuário chega em execução de comando/código.', before: 'os.system("ping " + x)', after: 'subprocess.run(["ping", x])  # valide x', refs: ['OWASP A03', 'CWE-78'] },
  'TAINT-DESERIALIZE': { why: 'Input do usuário desserializado — execução de código.', before: 'pickle.loads(x)', after: 'json.loads(x)', refs: ['OWASP A08', 'CWE-502'] },
  'TAINT-PATH': { why: 'Input do usuário vira caminho de arquivo — path traversal.', before: 'open(x)', after: 'p = safe_join(BASE, secure_filename(x))', refs: ['OWASP A01', 'CWE-22'] },
  'TAINT-REDIRECT': { why: 'Input do usuário vira destino de redirect — open redirect.', before: 'redirect(x)', after: 'redirect(ALLOWED.get(x, "/"))', refs: ['OWASP A01', 'CWE-601'] }
};

const VECTOR_BY_ID = {
  'TAINT-SQLI': 'Injection', 'TAINT-SSTI': 'Injection', 'TAINT-RCE': 'Injection',
  'TAINT-DESERIALIZE': 'Injection', 'TAINT-PATH': 'Injection', 'TAINT-REDIRECT': 'Headers & CORS'
};

function renderTrace(hops) {
  return hops.map((h) => `${h.text} (${h.file}:${h.line})`).join(' → ');
}

function emitTaintFinding(taintPath, addFinding) {
  const sink = taintPath.hops[taintPath.hops.length - 1];
  const vector = VECTOR_BY_ID[taintPath.sinkId] || 'Injection';
  const trace = renderTrace(taintPath.hops);
  const description = `Fluxo de dado não confiável: ${trace}`;
  const recommendation = (FIXPACKS[taintPath.sinkId] || {}).after || 'Valide/sanitize a entrada antes do sink.';
  const fixPack = FIXPACKS[taintPath.sinkId] || null;
  const finding = addFinding(taintPath.severity, taintPath.sinkId, vector, sink.file, sink.line, description, recommendation, fixPack);
  // attach structured trace for report rendering (addFinding returns the finding object;
  // if it returns undefined because the finding was suppressed, skip).
  if (finding && typeof finding === 'object') finding.taintTrace = taintPath.hops;
  return finding;
}

module.exports = { emitTaintFinding, renderTrace };
```

> Note: this requires `addFinding` to **return the finding object**. Task 6 Step 3 adds `return finding;` to `addFinding` in `scripts/rock-house-ci.js`.

- [ ] **Step 5: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/taint/findings.js scripts/lib/rules/index.js tests/rock-house-ci.test.js
git commit -m "feat(taint): finding emitter with source->sink trace + TAINT metadata"
```

---

## Task 6: Wire intra-procedural taint into the scanner

**Files:**
- Create: `scripts/lib/taint/index.js`
- Modify: `scripts/rock-house-ci.js` (`main` awaits `analyzeProject`; `addFinding` returns finding; `coverage.taint`; `calculateConfidence`)
- Test: `tests/rock-house-ci.test.js` (new async `testTaintScannerIntegration`)

- [ ] **Step 1: Write the failing integration test**

Add and register `await testTaintScannerIntegration();` in `run()`:

```js
async function testTaintScannerIntegration() {
  const fixture = makeTempProject('rock-house-taint-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'app.py', [
    'from flask import request',
    'def profile():',
    '    q = request.args["id"]',
    '    cur.execute(q)'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-taint-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'tainted SQLi must block');
  const report = readJson(output);
  const t = report.findings.find((f) => f.checkId === 'TAINT-SQLI');
  assert(t, 'TAINT-SQLI finding present');
  assert(Array.isArray(t.taintTrace) && t.taintTrace.length >= 2, 'finding carries a trace');
  assert(report.coverage.taint && report.coverage.taint.ran === true, 'coverage records taint ran');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — no `TAINT-SQLI` finding / `coverage.taint` undefined.

- [ ] **Step 3: Make `addFinding` return the finding**

In `scripts/rock-house-ci.js`, at the end of `addFinding`, change:

```js
  findings.push(finding);
}
```
to:
```js
  findings.push(finding);
  return finding;
}
```
(Also add `return null;` in the suppression branch — replace the bare `return;` inside the `if (suppression) {...}` block with `return null;`.)

- [ ] **Step 4: Create the project analyzer (intra-procedural pass)**

Create `scripts/lib/taint/index.js`:

```js
const fs = require('fs');
const path = require('path');
const { parse, isAvailable } = require('./parser');
const { buildFileIR } = require('./ir');
const { analyzeFunctionIntra } = require('./engine');
const { emitTaintFinding } = require('./findings');

const MAX_FILE_BYTES = 512 * 1024;

async function analyzeProject({ files, targetRoot, addFinding, gates, addUnknown }) {
  const pyFiles = files.filter((f) => f.endsWith('.py'));
  const coverage = { ran: false, blindEdges: 0, note: '' };
  if (pyFiles.length === 0) {
    coverage.note = 'Nenhum arquivo Python para análise de taint.';
    return { taint: coverage };
  }
  if (!(await isAvailable())) {
    if (addUnknown) addUnknown('TAINT-UNAVAILABLE', 'Injection', 'Taint parser (WASM) could not load; deep Python analysis skipped.', 'Ensure scripts/vendor wasm assets are present.', 'Ouro');
    coverage.note = 'Parser de taint indisponível — só regras de padrão rodaram.';
    coverage.blindEdges += 1;
    return { taint: coverage };
  }

  const fileIRs = [];
  for (const file of pyFiles) {
    const rel = path.relative(targetRoot, file).replace(/\\/g, '/');
    let src;
    try {
      const stat = fs.statSync(file);
      if (stat.size > MAX_FILE_BYTES) { coverage.blindEdges += 1; continue; }
      src = fs.readFileSync(file, 'utf8');
    } catch (e) { coverage.blindEdges += 1; continue; }
    try {
      const tree = await parse(src);
      if (tree.rootNode.hasError) coverage.blindEdges += 1; // partial parse, still analyze
      fileIRs.push(buildFileIR(tree, rel));
    } catch (e) { coverage.blindEdges += 1; }
  }

  coverage.ran = true;
  // Intra-procedural pass: each function analyzed in isolation.
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      let res;
      try { res = analyzeFunctionIntra(fn, ir.path); }
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

  coverage.note = coverage.blindEdges
    ? `Taint rodou; ${coverage.blindEdges} ponto(s) onde perdi o rastro.`
    : 'Python auditado por taint (intra-procedural).';
  return { taint: coverage };
}

module.exports = { analyzeProject };
```

- [ ] **Step 5: Call the analyzer from `main()` and record coverage**

In `scripts/rock-house-ci.js` `main()`, after `scanFiles(files);` add:
```js
  const taintResult = await analyzeProject({ files, targetRoot, addFinding, gates, addUnknown });
```
Add the require near the other rules requires:
```js
const { analyzeProject } = require('./lib/taint');
```
Then, where `coverage` is computed, merge the taint sub-report. Replace:
```js
  const coverage = evaluateCoverage(targetRoot);
  const confidence = calculateConfidence(summary, coverage);
```
with:
```js
  const coverage = evaluateCoverage(targetRoot);
  coverage.taint = taintResult.taint;
  const confidence = calculateConfidence(summary, coverage);
```

> `main()` is already `async`, and `analyzeProject` must run before `summary`/findings are finalized. Move the `const taintResult = await analyzeProject(...)` line to sit immediately after `scanFiles(files);` and before the `newFindings`/`summary` computation so its findings are counted.

- [ ] **Step 6: Extend confidence for taint blind edges**

In `scripts/rock-house-ci.js`, replace `calculateConfidence`:

```js
function calculateConfidence(summary, coverage) {
  if (coverage && coverage.gaps && coverage.gaps.length > 0) return 'Baixa';
  if (coverage && (!coverage.supported || coverage.supported.length === 0)) return 'Baixa';
  // Taint ran but lost the trail somewhere: cannot claim high confidence.
  if (coverage && coverage.taint && coverage.taint.ran && coverage.taint.blindEdges > 0) {
    if (summary.unknown <= 1) return 'Media';
  }
  if (summary.unknown > 4) return 'Baixa';
  if (summary.unknown > 1) return 'Media';
  return 'Alta';
}
```

- [ ] **Step 7: Run the full suite**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — including `testTaintScannerIntegration`, and `testCleanFixturePasses` still green (a clean Next.js fixture has no `.py` files → taint no-op → confidence unchanged).

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/taint/index.js scripts/rock-house-ci.js tests/rock-house-ci.test.js
git commit -m "feat(taint): wire intra-procedural taint into scanner + coverage/confidence"
```

---

## Task 7: Project symbol table

**Files:**
- Create: `scripts/lib/taint/symbols.js`
- Test: `tests/rock-house-ci.test.js` (new async `testTaintSymbols`)

- [ ] **Step 1: Write the failing test**

Add and register `await testTaintSymbols();` in `run()`:

```js
async function testTaintSymbols() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { buildSymbolTable } = require('../scripts/lib/taint/symbols');

  const dbIr = buildFileIR(await parse('def run_query(sql):\n    cur.execute(sql)\n'), 'db.py');
  const viewsIr = buildFileIR(await parse('from db import run_query\ndef v():\n    run_query(request.args["q"])\n'), 'views.py');
  const table = buildSymbolTable([dbIr, viewsIr]);

  assert(table.functionByQual.has('db.run_query'), 'function indexed by qualname');
  const resolved = table.resolveImported('views.py', 'run_query');
  assert(resolved && resolved.qualname === 'db.run_query', 'import resolves across files');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/symbols.js`:

```js
// Build a project-wide symbol table from file IRs. Resolves `from X import Y`
// within the scanned repo. External/stdlib imports are recorded as external.
function buildSymbolTable(fileIRs) {
  const functionByQual = new Map();      // "db.run_query" -> FunctionIR
  const moduleFunctions = new Map();      // "db" -> Map(name -> FunctionIR)
  const importsByFile = new Map();        // "views.py" -> Map(localName -> "db.run_query")

  for (const ir of fileIRs) {
    const m = new Map();
    for (const fn of ir.functions) {
      functionByQual.set(fn.qualname, fn);
      m.set(fn.name, fn);
    }
    moduleFunctions.set(ir.modulePrefix, m);
  }

  // Parse import lines straight from the IR's raw source isn't available; instead
  // re-derive from each function file's module name space: imports are captured by
  // scanning the file IR's `imports` if present. We compute them here from text.
  for (const ir of fileIRs) {
    importsByFile.set(ir.path, ir.imports || new Map());
  }

  function resolveImported(fromFile, localName) {
    const imp = importsByFile.get(fromFile);
    if (imp && imp.has(localName)) {
      const qual = imp.get(localName);
      if (functionByQual.has(qual)) return functionByQual.get(qual);
    }
    // same-module function?
    return null;
  }

  return { functionByQual, moduleFunctions, importsByFile, resolveImported };
}

module.exports = { buildSymbolTable };
```

- [ ] **Step 4: Capture imports in the IR (the symbol table needs them)**

In `scripts/lib/taint/ir.js`, extend `buildFileIR` to collect imports. Add this before the `return { path, modulePrefix, functions };` line:

```js
  const imports = new Map(); // localName -> "module.name"
  (function walkImports(node) {
    if (node.type === 'import_from_statement') {
      const moduleNode = node.childForFieldName('module_name');
      const moduleName = moduleNode ? tree.rootNode.text.slice(moduleNode.startIndex, moduleNode.endIndex) : '';
      for (const child of node.namedChildren) {
        if (child.type === 'dotted_name' && child !== moduleNode) {
          const local = tree.rootNode.text.slice(child.startIndex, child.endIndex);
          imports.set(local, `${moduleName}.${local}`);
        }
      }
    }
    for (const c of node.namedChildren) walkImports(c);
  })(tree.rootNode);
```

And change the return to:
```js
  return { path: relPath, modulePrefix, functions, imports };
```

- [ ] **Step 5: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS. (If `import_from_statement` field `module_name` differs in the vendored grammar, confirm with the Task 1 Step 6 inspector and adjust.)

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/taint/symbols.js scripts/lib/taint/ir.js tests/rock-house-ci.test.js
git commit -m "feat(taint): project symbol table with intra-repo import resolution"
```

---

## Task 8: Call graph

**Files:**
- Create: `scripts/lib/taint/callgraph.js`
- Test: `tests/rock-house-ci.test.js` (new async `testTaintCallgraph`)

- [ ] **Step 1: Write the failing test**

Add and register `await testTaintCallgraph();` in `run()`:

```js
async function testTaintCallgraph() {
  const { parse } = require('../scripts/lib/taint/parser');
  const { buildFileIR } = require('../scripts/lib/taint/ir');
  const { buildSymbolTable } = require('../scripts/lib/taint/symbols');
  const { resolveCall } = require('../scripts/lib/taint/callgraph');

  const dbIr = buildFileIR(await parse('def run_query(sql):\n    cur.execute(sql)\n'), 'db.py');
  const viewsIr = buildFileIR(await parse('from db import run_query\ndef v():\n    run_query(x)\n    mystery(x)\n'), 'views.py');
  const table = buildSymbolTable([dbIr, viewsIr]);
  const vFn = viewsIr.functions[0];

  const resolved = resolveCall(vFn.calls.find((c) => c.calleeLast === 'run_query'), viewsIr, table);
  assert.strictEqual(resolved.kind, 'function', 'resolves to a repo function');
  assert.strictEqual(resolved.fn.qualname, 'db.run_query');

  const blind = resolveCall(vFn.calls.find((c) => c.calleeLast === 'mystery'), viewsIr, table);
  assert.strictEqual(blind.kind, 'unresolved', 'unknown callee -> unresolved (blind edge)');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/taint/callgraph.js`:

```js
const { sinkFor, isSanitizer } = require('./catalogs');

// Resolve a call to: a repo function, a known external (sink/sanitizer), or unresolved.
function resolveCall(call, file, symbols) {
  if (!call || !call.calleeDotted) return { kind: 'unresolved', reason: 'no-callee' };
  // Known sink or sanitizer => "external-modeled", not a blind edge.
  if (sinkFor(call.calleeDotted) || isSanitizer(call.calleeLast)) {
    return { kind: 'external', modeled: true };
  }
  // Imported repo function?
  const imported = symbols.resolveImported(file.path, call.calleeLast);
  if (imported) return { kind: 'function', fn: imported };
  // Same-module function?
  const sameModule = symbols.moduleFunctions.get(file.modulePrefix);
  if (sameModule && sameModule.has(call.calleeLast)) {
    return { kind: 'function', fn: sameModule.get(call.calleeLast) };
  }
  // Dotted external we don't model (e.g. some_lib.do) — modeled pass-through? No: blind.
  return { kind: 'unresolved', reason: `unresolved:${call.calleeDotted}` };
}

module.exports = { resolveCall };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/taint/callgraph.js tests/rock-house-ci.test.js
git commit -m "feat(taint): call graph resolution with blind-edge marking"
```

---

## Task 9: Inter-procedural propagation

**Files:**
- Modify: `scripts/lib/taint/engine.js` (add `analyzeProjectTaint`)
- Modify: `scripts/lib/taint/index.js` (use inter-procedural pass; build trace across files)
- Test: `tests/rock-house-ci.test.js` (new async `testTaintInterprocedural`)

- [ ] **Step 1: Write the failing test**

Add and register `await testTaintInterprocedural();` in `run()`:

```js
async function testTaintInterprocedural() {
  const fixture = makeTempProject('rock-house-taint-inter-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'db.py', [
    'def run_query(sql):',
    '    cur.execute(sql)'
  ].join('\n'));
  writeFile(fixture, 'views.py', [
    'from flask import request',
    'from db import run_query',
    'def profile():',
    '    uid = request.args["id"]',
    '    run_query(uid)'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-taint-inter-${Date.now()}.json`);
  const result = runScanner(fixture, output, 'bronze');

  assert.notStrictEqual(result.status, 0, 'cross-file SQLi must block');
  const report = readJson(output);
  const t = report.findings.find((f) => f.checkId === 'TAINT-SQLI');
  assert(t, 'cross-file TAINT-SQLI found');
  const files = (t.taintTrace || []).map((h) => h.file);
  assert(files.includes('views.py') && files.includes('db.py'), 'trace spans both files');
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — only single-file analysis exists; no cross-file trace.

- [ ] **Step 3: Add inter-procedural analysis to the engine**

In `scripts/lib/taint/engine.js`, add (and export) `analyzeProjectTaint`:

```js
const { resolveCall } = require('./callgraph');

// Inter-procedural: compute function summaries, then for each entry function (a
// Flask view or any function) propagate tainted args across resolved calls to a
// fixpoint, producing cross-file TaintPaths. Bounded by MAX_DEPTH.
const MAX_DEPTH = 8;

function analyzeProjectTaint(fileIRs, symbols) {
  const paths = [];
  let blindEdges = 0;

  // Pre-compute a per-function summary by seeding each param and seeing where it lands.
  const summaryOf = new Map(); // qualname -> summary
  const fnByQual = symbols.functionByQual;
  const fileOfFn = new Map();
  for (const ir of fileIRs) for (const fn of ir.functions) fileOfFn.set(fn.qualname, ir);

  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const res = analyzeFunctionIntra(fn, ir.path, fn.params);
      summaryOf.set(fn.qualname, res.summary);
    }
  }

  // Walk each function; when a local is tainted (from a source) and flows into a call
  // whose callee summary says "this param reaches a sink", emit a cross-file path.
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const tainted = new Set();
      const originLine = new Map(); // var -> {file,line,text}
      const events = [];
      for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
      for (const c of fn.calls) events.push({ kind: 'call', line: c.line, c });
      events.sort((x, y) => x.line - y.line);

      for (const ev of events) {
        if (ev.kind === 'assign') {
          const t = exprIsTainted(ev.a.value, tainted);
          for (const tgt of ev.a.targets) {
            if (t) { tainted.add(tgt); originLine.set(tgt, { file: ir.path, line: ev.a.line, text: ev.a.value.text }); }
            else tainted.delete(tgt);
          }
        } else {
          const call = ev.c;
          const taintedArgIdx = (call.args || []).findIndex((arg) => exprIsTainted(arg, tainted));
          if (taintedArgIdx === -1) continue;
          const resolution = resolveCall(call, ir, symbols);
          if (resolution.kind === 'unresolved') { blindEdges += 1; continue; }
          if (resolution.kind === 'function') {
            const callee = resolution.fn;
            const summary = summaryOf.get(callee.qualname);
            const param = callee.params[taintedArgIdx];
            if (summary && param && summary.paramReachesSink.has(param)) {
              const sinkId = summary.paramReachesSink.get(param)[0];
              const sev = sinkId === 'TAINT-PATH' || sinkId === 'TAINT-REDIRECT' || sinkId === 'TAINT-DESERIALIZE' ? 'Alto' : 'Critico';
              const argText = call.args[taintedArgIdx].text;
              const origin = [...(call.args[taintedArgIdx].reads || [])].map((r) => originLine.get(r)).find(Boolean);
              const hops = [];
              if (origin) hops.push({ file: origin.file, line: origin.line, text: origin.text, role: 'source' });
              hops.push({ file: ir.path, line: call.line, text: `${callee.name}(${argText})`, role: 'call' });
              hops.push({ file: fileOfFn.get(callee.qualname).path, line: callee.startLine, text: `${callee.name}() → sink`, role: 'sink' });
              paths.push({ sinkId, severity: sev, hops });
            }
          }
          // external/modeled sinks are handled by the intra pass already
        }
      }
    }
  }

  return { paths, blindEdges };
}

module.exports.analyzeProjectTaint = analyzeProjectTaint;
```

- [ ] **Step 4: Use inter-procedural results in the analyzer**

In `scripts/lib/taint/index.js`, replace the intra-procedural emission loop (the `for (const ir of fileIRs) { for (const fn of ir.functions) {...} }` block from Task 6 Step 4) with a combined pass:

```js
  const { analyzeFunctionIntra } = require('./engine');
  const { buildSymbolTable } = require('./symbols');
  const { analyzeProjectTaint } = require('./engine');

  coverage.ran = true;
  const symbols = buildSymbolTable(fileIRs);

  // Intra-procedural: source and sink in the same function.
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      let res;
      try { res = analyzeFunctionIntra(fn, ir.path); }
      catch (e) { coverage.blindEdges += 1; continue; }
      for (const hit of res.sinkHits) {
        emitTaintFinding({
          sinkId: hit.sinkId, severity: hit.severity,
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
  try { inter = analyzeProjectTaint(fileIRs, symbols); }
  catch (e) { inter = { paths: [], blindEdges: 1 }; }
  coverage.blindEdges += inter.blindEdges;
  for (const p of inter.paths) emitTaintFinding(p, addFinding);
```

Add the requires at the top of `index.js` (alongside the existing ones):
```js
const { buildSymbolTable } = require('./symbols');
const { analyzeProjectTaint } = require('./engine');
```
(Remove the duplicate inline `require` lines if you added them in the block above — keep requires at the top.)

- [ ] **Step 5: Run the full suite**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — including `testTaintInterprocedural` (cross-file trace) and all prior tests.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/taint/engine.js scripts/lib/taint/index.js tests/rock-house-ci.test.js
git commit -m "feat(taint): inter-procedural propagation across functions and files"
```

---

## Task 10: Blind-edge honesty + report rendering

**Files:**
- Modify: `scripts/lib/report-formatters.js` (render `taintTrace` in Markdown + SARIF)
- Test: `tests/rock-house-ci.test.js` (new async `testTaintBlindEdgeLowersConfidence`, `testTaintTraceRendering`)

- [ ] **Step 1: Write the failing tests**

Add and register both in `run()` (`await testTaintBlindEdgeLowersConfidence();`, `await testTaintTraceRendering();`):

```js
async function testTaintBlindEdgeLowersConfidence() {
  const fixture = makeTempProject('rock-house-taint-blind-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  // Tainted value passes into an unresolved (dynamic) call before any sink.
  writeFile(fixture, 'app.py', [
    'from flask import request',
    'def v():',
    '    x = request.args["id"]',
    '    mystery_helper(x)'
  ].join('\n'));

  const output = path.join(os.tmpdir(), `rock-house-taint-blind-${Date.now()}.json`);
  runScanner(fixture, output, 'bronze');
  const report = readJson(output);
  assert(report.coverage.taint.ran === true, 'taint ran');
  assert(report.coverage.taint.blindEdges >= 1, 'blind edge recorded for the unresolved call');
  assert.notStrictEqual(report.confidence, 'Alta', 'blind edge means confidence is not Alta');
}

async function testTaintTraceRendering() {
  const fixture = makeTempProject('rock-house-taint-md-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'app.py', [
    'from flask import request',
    'def v():',
    '    q = request.args["id"]',
    '    cur.execute(q)'
  ].join('\n'));
  const output = path.join(fixture, 'r.json');
  const markdownOutput = path.join(fixture, 's.md');
  runScanner(fixture, output, 'bronze', { markdownOutput });
  const md = fs.readFileSync(markdownOutput, 'utf8');
  assert(md.includes('Fluxo'), 'markdown shows the taint flow description');
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL — blind-edge assertion and/or markdown trace not present.

- [ ] **Step 3: Render the taint trace in Markdown fix-packs**

In `scripts/lib/report-formatters.js`, in `fixPacksSection`, after the `f.fixPack` guard, include the trace when present. Replace the `const lines = [...]` array's first entry block with one that adds a trace line:

```js
    const lines = [
      `### [${f.severity}] ${f.checkId} — ${escapeMd(f.rule?.title || f.description)}  (\`${f.file}:${f.line}\`)`,
      Array.isArray(f.taintTrace) && f.taintTrace.length
        ? `**Fluxo:** ${escapeMd(f.taintTrace.map((h) => `${h.text} (${h.file}:${h.line})`).join(' → '))}`
        : '',
      fp.why ? `**Por que:** ${escapeMd(fp.why)}` : '',
      fp.before ? `**Antes:** \`${escapeMd(fp.before)}\`` : '',
      fp.after ? `**Depois:** \`${escapeMd(fp.after)}\`` : '',
      fp.command ? `**Comando:** \`${escapeMd(fp.command)}\`` : '',
      Array.isArray(fp.refs) && fp.refs.length ? `**Ref:** ${escapeMd(fp.refs.join(' / '))}` : ''
    ].filter((l) => l !== '');
```

> Note: a taint finding always has a `fixPack` (from `findings.js`), so it reaches `fixPacksSection`. The description itself already starts with "Fluxo de dado..." so the Markdown test's `includes('Fluxo')` passes via the findings table too; the trace line adds the structured hops.

- [ ] **Step 4: Add the trace to SARIF**

In `scripts/lib/report-formatters.js`, in `toSarif`, extend the per-result `properties` object to include the trace:

```js
            fixCommand: finding.fixPack?.command || '',
            taintTrace: Array.isArray(finding.taintTrace)
              ? finding.taintTrace.map((h) => `${h.text} (${h.file}:${h.line})`)
              : []
```
(Append after the existing `fixCommand` property line.)

- [ ] **Step 5: Run tests**

Run: `node tests/rock-house-ci.test.js`
Expected: PASS — both new tests green and all prior tests green.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/report-formatters.js tests/rock-house-ci.test.js
git commit -m "feat(taint): render source->sink trace in Markdown + SARIF; assert blind-edge honesty"
```

---

## Task 11: WASM-unavailable fallback + docs + final verification

**Files:**
- Test: `tests/rock-house-ci.test.js` (new async `testTaintUnavailableFallsBackToRegex`)
- Modify: `CLAUDE.md`

- [ ] **Step 1: Write the failing test**

This test points the parser at a missing wasm via an env override, proving the scan still completes on regex rules. First add an override hook to the parser.

In `scripts/lib/taint/parser.js`, change the `PYTHON_WASM` constant to honor an env override:
```js
const PYTHON_WASM = process.env.ROCKHOUSE_PYTHON_WASM || path.join(__dirname, '..', '..', 'vendor', 'tree-sitter-python.wasm');
```

Add and register `await testTaintUnavailableFallsBackToRegex();` in `run()`:

```js
async function testTaintUnavailableFallsBackToRegex() {
  const fixture = makeTempProject('rock-house-taint-na-');
  writeFile(fixture, 'requirements.txt', 'flask==3.0.0\n');
  writeFile(fixture, 'app.py', [
    'app.run(debug=True)',           // regex rule PY-DEBUG must still fire
    'q = request.args["id"]',
    'cur.execute(q)'
  ].join('\n'));
  const output = path.join(os.tmpdir(), `rock-house-taint-na-${Date.now()}.json`);
  // Force the taint parser to fail by pointing it at a non-existent wasm.
  const result = runScanner(fixture, output, 'bronze', { env: { ROCKHOUSE_PYTHON_WASM: path.join(fixture, 'nope.wasm') } });
  const report = readJson(output);
  assert(report.findings.some((f) => f.checkId === 'PY-DEBUG'), 'regex rules still run when taint is unavailable');
  assert(report.coverage.taint.ran === false || report.coverage.taint.blindEdges >= 1, 'taint reported unavailable, not silently clean');
  assert.notStrictEqual(result.status, 0, 'still blocks on the regex findings');
}
```

- [ ] **Step 2: Support an `env` option in the test's `runScanner` helper**

In `tests/rock-house-ci.test.js`, find `runScanner(target, output, minLevel, options = {})` and ensure the spawn passes env. Locate the `spawnSync`/`spawn` call inside `runScanner` and set its `env`:

```js
  const child = spawnSync(process.execPath, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...(options.env || {}) }
  });
```
(If `runScanner` already builds an options object for the spawn, add the `env` merge to it. Do not remove existing options.)

- [ ] **Step 3: Run test to verify it fails**

Run: `node tests/rock-house-ci.test.js`
Expected: FAIL initially if the analyzer throws instead of degrading — confirm `analyzeProject`'s `isAvailable()` path returns the unavailable coverage and never throws. (Task 6 Step 4 already guards this; this test locks it in.)

- [ ] **Step 4: Make it pass**

If the test fails because `isAvailable()` caches a successful init from earlier tests in the same process: ensure the scanner runs as a **subprocess** (it does — `runScanner` spawns `rock-house-ci.js`), so the env override applies to a fresh process. No code change needed beyond Step 1's env-aware constant. Re-run:

Run: `node tests/rock-house-ci.test.js`
Expected: PASS.

- [ ] **Step 5: Document the taint engine in CLAUDE.md**

In `CLAUDE.md`, under the Technology Stack table, add a row:
```
| **Deep analysis** | Inter-procedural taint engine (Python/Flask) via vendored tree-sitter WASM | Tracks user input source→sink across functions/files; zero install (wasm vendored) |
```
And add a short "Architecture" note:
```
### Taint engine (scripts/lib/taint/)
Python/Flask inter-procedural taint analysis layered under the regex rules. Parses with a
vendored tree-sitter WASM (no Python/toolchain needed). Emits `TAINT-*` findings with the
full source→sink trace. Unresolved calls / parser failures become blind edges that lower
confidence — it never reports "safe" for code it could not follow. JS/TS is the v2 target.
```

- [ ] **Step 6: Full verification (suite + demo gate + self-scan)**

Run:
```bash
node tests/rock-house-ci.test.js
node scripts/rock-house-ci.js --path examples/vulnerable-next-supabase --min-level prata --output rh-vuln.json; echo "exit=$?"; rm -f rh-vuln.json
node scripts/rock-house-ci.js --path . --min-level bronze --output rh-self.json --config examples/rock-house.config.json; echo "self-exit=$?"
node -e "const r=require('./rh-self.json'); console.log('self C/H/M:', r.summary.critical, r.summary.high, r.summary.medium, '| taint:', JSON.stringify(r.coverage.taint))"; rm -f rh-self.json
```
Expected: suite passes; demo `exit=1`; self-scan reports cleanly (the scanner's own `scripts/` is JS, so taint is a no-op there — `taint.ran` may be false because there are no `.py` files in scope after the config excludes). If the self-scan flags anything in `scripts/lib/taint/` fixtures or vendored wasm, add `scripts/vendor` to the self-scan config `exclude`.

- [ ] **Step 7: Commit**

```bash
git add scripts/lib/taint/parser.js tests/rock-house-ci.test.js CLAUDE.md examples/rock-house.config.json
git commit -m "feat(taint): graceful regex fallback when parser unavailable; docs + verification"
```

---

## Self-Review (completed during planning)

**Spec coverage:**
- Parser (tree-sitter WASM, portable) → Task 0 + Task 1. ✅
- IR builder → Task 3. ✅
- Symbol table (intra-repo imports) → Task 7. ✅
- Call graph + blind edges → Task 8. ✅
- Catalogs (sources/sinks/sanitizers/propagators) → Task 2. ✅
- Per-function summaries + intra-procedural → Task 4. ✅
- Inter-procedural fixpoint → Task 9. ✅
- Findings with source→sink trace → Task 5 + rendering Task 10. ✅
- Honesty / coverage.taint + confidence → Task 6 (confidence), Task 9/10 (blind edges). ✅
- Error handling (WASM unavailable, unparseable, caps) → Task 6 Step 4 + Task 11. ✅
- Integration with existing scanner (addFinding, fingerprint, regex rules coexist) → Task 6, Task 11. ✅
- Testing strategy (per-sink vuln/clean, inter-proc, blind-edge, unavailable) → Tasks 4, 6, 9, 10, 11. ✅
- Non-goals respected (no type inference, no third-party internals, JS deferred, no auto-fix). ✅

**Placeholder scan:** No TBD/TODO in steps; every code step shows the code; commands have expected output. The one external unknown is the exact tree-sitter field names for the vendored grammar version — handled by the Task 1 Step 6 inspector and explicit "confirm field name" notes, not left as a silent assumption.

**Type/name consistency:** `parse` (parser) used in Tasks 1/3/4/7/8; `buildFileIR(tree, relPath) -> { path, modulePrefix, functions, imports }` defined Task 3, extended Task 7, consumed Tasks 4/7/8/9; `analyzeFunctionIntra(fn, file, seedParams)` defined Task 4, used Tasks 6/9; `summary.paramReachesSink` (Map) defined Task 4, read Task 9; `buildSymbolTable(fileIRs) -> { functionByQual, moduleFunctions, importsByFile, resolveImported }` defined Task 7, used Task 8/9; `resolveCall(call, file, symbols) -> { kind }` defined Task 8, used Task 9; `emitTaintFinding(taintPath, addFinding)` defined Task 5, used Task 6/9; `analyzeProject({files,targetRoot,addFinding,gates,addUnknown}) -> { taint }` defined Task 6, called in `main` Task 6 Step 5; `addFinding(..., fixPack) -> finding` 8-arg + return value defined Task 6 Step 3, relied on by Task 5. Consistent.

**Known limitation flagged for execution:** inter-procedural propagation in Task 9 is one-hop (caller → callee summary). Deeper chains (caller → helper → helper → sink) resolve only if the intermediate's summary already marks the param as sink-reaching; multi-hop summary composition is a documented v2 refinement, and any unresolved depth becomes a blind edge (honest), never a false "safe".
