# Rock House — Python Inter-Procedural Taint Engine (v1)

**Date:** 2026-06-01
**Status:** Approved (design)
**Branch:** TBD (`feat/python-taint-engine`)
**Depends on:** `feat/scanner-rule-registry` (the declarative rule engine + coverage-aware confidence this layers on top of)

## Problem

Rock House's deterministic CI scanner (`scripts/rock-house-ci.js`) now has a declarative
rule registry with pattern/config rules for JS and Python, in-engine secret detection,
and coverage-aware confidence. But every rule is still **single-line regex with a context
window** — it cannot follow data. The vulnerabilities that actually sink money-handling
apps are *flow* bugs: untrusted input traveling from a source, through variables and
function calls, into a dangerous sink. A pattern rule sees `cursor.execute(query)` but
cannot tell whether `query` came from `request.args` (SQLi) or a constant (safe). The
result is a tool that either cries wolf on every `execute(` or — worse — stays silent and
**passes a vulnerable app**, which is the exact masking the tool exists to prevent.

The revenue projects (Bot Radar AC, Agenda) are **Flask/Python**, the stack with the
weakest deep coverage today. This is where a real taint engine earns its keep first.

## Goal

A deterministic, dependency-portable **taint analyzer for Python/Flask** that tracks
untrusted input from sources, **across functions and files** (inter-procedural), to
dangerous sinks, and reports the **full source→sink path**. It runs as a new analysis
layer beside the existing regex rules, feeding the same `addFinding` pipeline so SARIF,
Markdown, baseline, and suppressions work unchanged. When the analysis hits something it
cannot follow, it records a **blind edge** that lowers confidence — it never assumes safe.

## Decisions locked during brainstorming

1. **Depth lives in the deterministic scanner** (not the LLM audit mode). The scanner is
   the product brain; the LLM audit stays as a complementary deep dive.
2. **Allow a parser dependency** to get real AST/taint (chosen over staying regex-only).
   Robustness beats the strict zero-dependency rule — but we preserve portability by using
   a **WASM** parser, so no language toolchain must be installed on the user's machine.
3. **Python/Flask first** (v1). JS/TS is v2, reusing the same engine architecture.
4. **Inter-procedural from the start** (v1), built on per-function taint summaries plus a
   call graph — not intra-procedural-only. (Intra-procedural per-function analysis is the
   internal building block the inter-procedural propagation consumes, so it is validated
   on its own before the graph layer is exercised.)

## Non-Goals (v1)

- **No full type inference.** The engine reasons about taint, not types. Method resolution
  is best-effort by name/import, not by inferred class hierarchy.
- **No descent into third-party library internals.** Library calls are modeled via
  catalogs (source/sink/sanitizer/propagator). An unmodeled library call is a **blind
  edge**, not an assumption of safety.
- **No JS/TS** (v2, reuses the engine).
- **No auto-fix / no code mutation.** Findings stay text-only, consistent with the
  existing scanner.
- **No whole-program points-to / alias analysis.** Aliasing is handled only through direct
  assignment and call/return propagation; complex aliasing is a documented limitation.
- **Bounded analysis.** Call-graph traversal depth and fixpoint iterations are capped to
  keep runtime predictable; hitting a cap records a blind edge.

## Architecture

A new `scripts/lib/taint/` subsystem with single-responsibility modules. The scanner runs
it alongside the existing `runRules` engine; both emit through `addFinding`.

```
scripts/lib/taint/
  parser.js        # web-tree-sitter loader + Python grammar; file text -> AST
  ir.js            # AST -> per-file IR: functions, params, assignments, calls, returns, sink exprs
  symbols.js       # project symbol table: intra-repo import resolution, module/function lookup
  callgraph.js     # call sites -> resolved function defs; unresolved => blind edge
  catalogs.js      # Flask sources, sinks, sanitizers, propagators (data, not code paths)
  engine.js        # per-function taint summaries + inter-procedural fixpoint -> tainted paths
  findings.js      # tainted path -> finding object (trace, severity, fixPack) via addFinding
  index.js         # entry: analyzeProject(files, addFinding, gates, coverage) -> runs the pipeline
```

**Vendored asset:** `scripts/vendor/tree-sitter-python.wasm` and the `web-tree-sitter`
runtime. These are committed to the repo (the "portable" promise: clone and run, no
`npm install`, no Python). License compatibility is verified in Task 0.

### 1. Parser (`parser.js`)

- Loads `web-tree-sitter` and the bundled `tree-sitter-python.wasm`.
- `parse(source: string) -> Tree`. Async init (WASM load) done once and cached.
- If WASM fails to load on the host, the engine degrades gracefully: it emits a single
  `UNKNOWN` (`TAINT-UNAVAILABLE`) and the regex rules still run. The scanner never crashes
  because taint is unavailable.

### 2. IR builder (`ir.js`)

From a file's AST, produce a `FileIR`:

```
FileIR = {
  path: string,
  functions: FunctionIR[],
  moduleAssignments: Assignment[]   // top-level assigns (e.g., app = Flask(__name__))
}
FunctionIR = {
  name: string,
  qualname: string,                 // module-qualified, e.g. "views.profile"
  params: string[],
  decorators: string[],             // e.g. "app.route('/u/<id>')", "login_required"
  statements: Stmt[]                 // ordered; assignments, calls, returns, control nodes
  startLine, endLine
}
Assignment = { targets: string[], valueExpr: Expr, line }
Call = { callee: CalleeRef, args: Expr[], line }     // CalleeRef: name / attribute chain
Return = { valueExpr: Expr | null, line }
```

The IR is intentionally a thin, taint-relevant projection of the AST (assignments, calls,
returns, f-strings, subscripts, attribute access) — not a full Python semantic model.

### 3. Symbol table (`symbols.js`)

- Walk all `FileIR`s; index `qualname -> FunctionIR` and `module -> exports`.
- Resolve `import x`, `from a.b import c`, and relative imports **within the scanned repo**.
  External imports (stdlib, third-party) are recorded as **external symbols** (modeled by
  catalogs, otherwise blind).
- Resolution is by name + import path; no class-hierarchy inference (Non-Goal).

### 4. Call graph (`callgraph.js`)

- For each `Call`, resolve `CalleeRef` to a `FunctionIR` (intra-repo) or an external/catalog
  symbol, or **unresolved**.
- `unresolved` (dynamic dispatch, `getattr`, a name we cannot bind) → emit a **blind edge**
  record `{ at: file:line, reason }`. Blind edges are first-class output, fed to coverage.
- Cap traversal at `MAX_DEPTH` (default 8) and total visited nodes; exceeding the cap also
  records a blind edge rather than silently stopping.

### 5. Catalogs (`catalogs.js`)

Pure data describing Flask/Python taint semantics. Extensible without touching engine code.

- **Sources** (produce taint): `request.args`, `request.form`, `request.values`,
  `request.json`, `request.get_json(...)`, `request.data`, `request.files`,
  `request.cookies`, `request.headers`, and **view path params** (params of a function whose
  decorator is `@app.route`/`@blueprint.route` with `<...>` converters).
- **Sinks** (dangerous if reached by taint), each with a severity and a `TAINT-*` id:
  | Sink pattern | id | Severity | Class |
  |---|---|---|---|
  | `cursor.execute` / `executemany` (non-parameterized arg tainted) | `TAINT-SQLI` | Critico | SQL injection |
  | `render_template_string(...)` | `TAINT-SSTI` | Critico | SSTI / RCE |
  | `subprocess.*(..., shell=True)`, `os.system`, `os.popen` | `TAINT-RCE` | Critico | Command injection |
  | `eval` / `exec` | `TAINT-RCE` | Critico | Code execution |
  | `pickle.loads` / `pickle.load` | `TAINT-DESERIALIZE` | Alto | Unsafe deserialization |
  | `yaml.load` (no SafeLoader) | `TAINT-DESERIALIZE` | Alto | Unsafe deserialization |
  | `open(...)`, `send_file(...)`, `send_from_directory(path,...)` | `TAINT-PATH` | Alto | Path traversal |
  | `redirect(...)`, `Response(..., headers={'Location':...})` | `TAINT-REDIRECT` | Alto | Open redirect |
- **Sanitizers** (clear taint when applied): parameterized-query placeholder usage (`execute(sql, params)` where the tainted value is in the params tuple, not the SQL string), `markupsafe.escape`, `int(...)`, `float(...)`, `werkzeug.utils.secure_filename`, explicit allowlist membership checks (`x in ALLOWED`), `bleach.clean`.
- **Propagators** (taint flows through): f-strings, `str` concatenation/format, `.join`,
  list/dict/tuple construction and indexing, slicing, `+`.

### 6. Taint engine (`engine.js`)

Two phases, to a fixpoint:

1. **Per-function summaries (intra-procedural).** For each `FunctionIR`, compute a taint
   state over locals: seed from sources (and from parameters marked tainted by the caller),
   propagate through assignments/propagators, clear at sanitizers, and record:
   - **sink hits** reached by tainted values (with the in-function path), and
   - a **summary**: `{ paramsThatTaintReturn: Set, paramsThatReachSink: Map<param, sink[]> }`.
2. **Inter-procedural propagation.** Walk the call graph: when a call passes a tainted
   argument into a parameter that the callee's summary says reaches a sink (or taints the
   return that flows onward in the caller), record a cross-function tainted path. Iterate
   until summaries stop changing or the cap is hit.

Output: a list of `TaintPath`:

```
TaintPath = {
  sinkId,            // TAINT-SQLI ...
  severity,
  hops: [ { file, line, node, role } ]   // role: 'source' | 'propagate' | 'call' | 'sink'
  sanitizedBy: null  // present only as a debugging aid; a sanitized path is NOT emitted
}
```

### 7. Findings (`findings.js`)

Each `TaintPath` becomes a finding via the existing `addFinding(severity, checkId, vector,
file, line, description, fix, fixPack)`:

- `file`/`line` = the **sink** location (where the bug manifests).
- `description` includes a compact rendered trace: `request.args['id'] (views.py:10) →
  uid (views.py:11) → build_query(uid) (db.py:4) → cursor.execute (db.py:7)`.
- `fixPack` per sink class (why / before / after / refs), e.g. for `TAINT-SQLI`:
  parameterized query.
- A new report field `finding.taintTrace = hops[]` carries the structured path for
  Markdown/SARIF rendering (rendered in the existing fix-pack section; SARIF
  `properties.taintTrace`).

### 8. Honesty / coverage integration

Blind edges (unresolved calls, external-but-unmodeled functions on a tainted path, depth
caps, WASM-unavailable) are aggregated and surfaced:

- `coverage` gains `taint: { ran: bool, blindEdges: number, note }`.
- Confidence rule extends (building on `feat/scanner-rule-registry`'s
  `calculateConfidence`): if the Python taint engine ran but hit blind edges **on paths
  that reach a sink**, confidence is capped at `Media` with a note naming where it lost the
  trail. A clean taint run over Python raises the existing "audited" honesty from
  "pattern-only" to "taint-audited". The engine never converts "I couldn't follow this"
  into "this is safe."

## Data Flow

```
files (.py)
  -> parser: tree-sitter AST per file
  -> ir: FileIR (functions, assigns, calls, returns)
  -> symbols: project symbol table (intra-repo imports)
  -> callgraph: resolved edges + blind edges
  -> engine: per-function summaries -> inter-procedural fixpoint -> TaintPath[]
  -> findings: addFinding(...) + taintTrace
  -> coverage: taint.ran / blindEdges -> confidence
  -> report (JSON / SARIF / Markdown) [unchanged pipeline]
```

## Integration with the existing scanner

- `scripts/rock-house-ci.js` `main()` calls `analyzeProject(pyFiles, addFinding, gates,
  coverageAccumulator)` after `scanFiles(files)`. Python files are selected by extension.
- The existing Python **regex** rules (`PY-SQL`, `PY-SHELL`, `PY-PICKLE`, `PY-YAML`,
  `PY-TEMPLATE`, `PY-DEBUG`) remain as the cheap, broad layer that fires even when taint
  can't run (e.g., WASM unavailable). Taint adds **precise, path-backed** findings under
  `TAINT-*` ids. Where both fire on the same line, they are distinct `checkId`s and
  de-duplicate independently (the fingerprint already includes `line`).
- No change to assurance, DAST, observability, baseline, or suppression code.

## Error Handling

- **WASM load failure / parser unavailable:** emit `UNKNOWN TAINT-UNAVAILABLE`, continue
  with regex rules. Never throw out of `analyzeProject`.
- **Unparseable file (syntax error):** skip that file's taint analysis, record a blind edge
  for it, continue. Regex rules still scan it line-by-line.
- **Cap exceeded (depth/iterations/nodes):** stop that traversal, record a blind edge.
- All engine errors are caught at the `analyzeProject` boundary and converted to a blind
  edge + a logged warning, never a crash.

## Testing Strategy

Fixture-driven, mirroring the existing `tests/rock-house-ci.test.js` integration style
(spawn the scanner against a temp Flask project, assert on the JSON report). Each sink
class gets a **vulnerable** and a **clean (sanitized)** fixture, plus inter-procedural and
blind-edge fixtures:

- Per sink (`TAINT-SQLI`, `TAINT-SSTI`, `TAINT-RCE`, `TAINT-DESERIALIZE`, `TAINT-PATH`,
  `TAINT-REDIRECT`): vulnerable fixture flags with the correct id; sanitized fixture is
  clean.
- **Inter-procedural fixture:** source in `views.py`, sink in `db.py` via a helper —
  asserts the path is found and the trace lists both files.
- **Sanitizer-across-functions fixture:** taint sanitized in a helper before the sink —
  asserts no finding.
- **Blind-edge fixture:** tainted value passed into an unresolved/dynamic call before a
  sink — asserts no false "safe", a blind edge recorded, and confidence capped at `Media`.
- **WASM-unavailable simulation:** forces parser init failure — asserts `TAINT-UNAVAILABLE`
  UNKNOWN and that regex Python rules still produce their findings.
- **Performance smoke:** a fixture with N functions stays under a wall-clock cap.

Unit-level tests for `ir.js`, `callgraph.js`, and `engine.js` summaries are added where
integration coverage is insufficient to localize a regression.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `web-tree-sitter` WASM bundle size / commit weight | Vendor a single grammar; measure; document size in Task 0 |
| Inter-procedural precision vs runtime | Function summaries (not whole-program re-analysis) + depth/iteration caps + blind edges |
| Import resolution edge cases (relative, re-export) | Best-effort resolver; unresolved => blind edge (honest), never guessed |
| License of vendored grammar/runtime | Verified MIT/Apache-compatible in Task 0 before vendoring |
| False positives eroding trust | Sanitizer catalog + "only emit a path with a clear unsanitized source→sink"; calibrate against clean fixtures and a self-scan |

## Future (v2+, out of scope)

- **JS/TS** taint reusing this engine (swap grammar + catalogs).
- **Cross-request / stored taint** (taint persisted to DB then read back).
- **Config-aware sources** (e.g., values read from a tainted config).
- Smarter alias/points-to analysis.

## Affected / New Files

- New: `scripts/lib/taint/{parser,ir,symbols,callgraph,catalogs,engine,findings,index}.js`
- New: `scripts/vendor/tree-sitter-python.wasm` + `web-tree-sitter` runtime (vendored)
- Modify: `scripts/rock-house-ci.js` (`main` calls `analyzeProject`; coverage gains `taint`)
- Modify: `scripts/lib/report-formatters.js` (render `taintTrace` in Markdown + SARIF)
- Modify: `scripts/lib/rules/index.js` `META` (add `TAINT-*` ids' titles/OWASP/CWE)
- Modify: `tests/rock-house-ci.test.js` (taint fixtures + assertions)
- Modify: `CLAUDE.md` (document the taint engine as a real analysis layer)
