# Rock House — Taint Honesty Fixes (return-taint, kwargs, PY-DEBUG)

**Date:** 2026-06-03
**Status:** Approved (design)
**Branch:** `feat/python-taint-engine` (pre-merge fixes) + parallel skill-rule branch for PY-DEBUG
**Reviewers:** Angelo + Codex (Codex review requested on the implementation plan before execution)

## Problem

A Codex review of the `feat/python-taint-engine` branch (handoff 2026-06-03)
found the inter-procedural taint engine is "technically strong, tests pass, but
not yet honest enough to be called complete." Verified against current branch
code, the findings split into two classes:

**Silent-safe holes (violate the product's core invariant).** The engine's DNA,
stated in the 2026-06-02 handoff, is: *"never report safe for code I couldn't
follow — losing the trail must become a blind edge, never a silent clean."* Two
holes break this:

1. **Return-taint never propagates.** `paramTaintsReturn` is populated
   (`scripts/lib/taint/engine.js:75`) and returned in the summary (`:79`), but
   the fixpoint (`:240-271`) only composes `paramReachesSink` and
   `paramReachesBlind`. It never consumes `paramTaintsReturn`, and there is no
   notion of a function whose return is a source directly (`return request.args`).
   Result: a helper like `def get_q(): return request.args['q']` assigned to `q`
   and passed to `cur.execute(q)` reports **clean and silent** — a false negative
   dressed as a clean bill of health.
2. **Keyword arguments are dropped silently.** `scripts/lib/taint/ir.js:47` does
   `.filter((a) => a.type !== 'keyword_argument')`. A sink called by keyword
   (`cur.execute(query=user_input)`) ends up with `args=[]`, so the emit pass
   sets `taintedArgIdx = -1` and `continue`s. The flow vanishes **without even
   becoming a blind edge.**

**Recall gaps (already honest — degrade to blind edge today).** Not blockers:

3. **Module-alias call resolution.** `scripts/lib/taint/callgraph.js` resolves
   `from db import run_query` but not `import db; db.run_query(...)`. However an
   unresolved call already increments `blindEdges` (`engine.js:302`), so this is
   honest — it only loses recall.

**Separate skill-rule bug (independent of the engine).**

4. **PY-DEBUG false positive.** `scripts/lib/rules/python-flask.js:4` regex
   `/^\s*DEBUG\s*=\s*True/` matches `DEBUG = True` inside a `DevConfig` class and
   flags it **Alto** even when production uses `ProdConfig` (`DEBUG=False`).
   Surfaced during the real Bot Radar AC1 audit — a false Alto erodes trust in
   the scanner.

Plus repo hygiene that blocks a clean CI: a leftover junk file, an untracked
planning doc, and trailing-whitespace failures in `git diff --check`.

## Goal

Close the two silent-safe holes with **full propagation** (catch the real SQLi,
not just degrade), fix the PY-DEBUG false positive this cycle, and clean repo
hygiene — so the PR #1 can merge without shipping a silent "safe." Recall gaps
and supply-chain hardening become post-merge backlog issues.

## Non-Goals (this pass)

- Module-alias call resolution (#3) — post-merge issue; already honest.
- SHA256 checksums for vendored Tree-sitter assets (#6) — post-merge issue.
- Any change to the regex-rule engine beyond the PY-DEBUG scoping fix.

## Decisions (locked in brainstorm 2026-06-03)

- **#1/#2 → full propagation**, not honest-degrade. Catch the SQLi as a real
  finding with a cross-function trace.
- **PY-DEBUG → in scope this cycle, but on its OWN branch off `master`** (own PR,
  parallel to PR #1). It does not touch the taint engine, so it stays out of the
  taint PR to keep that merge clean.
- **`.planning/phases/01-skill-router/01-RESEARCH.md` → versioned** (`git add`),
  consistent with its tracked siblings (`PLAN`, `SUMMARY`) and Codex's note. The
  `MAX_DEPTH` junk file → deleted.
- **Split:** #1, #2, PY-DEBUG, hygiene are pre-merge; #3, #6 are post-merge.
- **Codex reviews the implementation plan** before execution.

## Design

### Part A — Return-taint propagation (#1)

The engine already runs an intra-procedural pass per function producing a
`summary`, then a bounded fixpoint composing summaries across the call graph,
then an emit pass walking each function to produce paths + blind edges. Return
taint plugs into all three.

**A1. Intra-pass — model return taint.** Extend each function's summary with:
- `returnIsSource: boolean` — the function returns a source expression directly
  (e.g. `return request.args['q']`), independent of any parameter. Computed by
  testing each `return` value with the existing source predicate.
- `paramTaintsReturn: Set<param>` — already collected (`engine.js:75`); now it
  will actually be consumed.

**A2. Fixpoint — compose return taint transitively.** Add a third reachability
relation alongside `paramReachesSink` / `paramReachesBlind`:
- A function's effective `returnIsTainted` is `returnIsSource` OR (it returns a
  param `p` AND a tainted value flows into `p`). Across calls: if `F` calls `G`,
  binds a tainted/`returnIsTainted`-derived value to `G`'s param at index `i`,
  and `G.paramTaintsReturn` contains that param, then `G(...)`'s return is
  tainted in `F`. Monotonic add into the same bounded loop; non-convergence
  still degrades honestly (existing HOLE-2 logic).

**A3. Emit pass — call-expression taint.** In the emit pass, a call expression
whose resolved callee has `returnIsTainted` makes its assignment target tainted
(`exprIsTainted` must treat such a call as a source). Then the existing
sink-detection logic fires: `q = get_q()` → `q` tainted → `cur.execute(q)` →
`TAINT-SQLI` finding with a cross-function trace (the hop builder includes the
helper → return → caller-assignment → sink chain).

**A4. Honest fallback.** If a call's callee is unresolved but the call's return
flows into a sink, that is a blind edge (already covered by the unresolved path
at `engine.js:302`), not a silent clean.

**Regression fixtures (both must produce a finding):**
- `helper-returns-source`: `def get_q(): return request.args['q']` → `q = get_q()` → `cur.execute(q)`.
- `helper-returns-param`: `def wrap(x): return x` → `q = wrap(request.args['q'])` → `cur.execute(q)`.
- Control (no regression): a helper that returns a constant must stay clean.

### Part B — Keyword-argument support (#2)

**B1. IR — stop dropping kwargs.** `ir.js` must include `keyword_argument`
nodes in the call's argument list, each carrying its keyword name and value
expression (positional args carry no name).

**B2. Sink detection — any tainted arg fires.** For external/modeled sinks
(e.g. `cur.execute`) the engine only needs to know *some* argument is tainted;
a tainted keyword value triggers the sink regardless of position.

**B3. Resolved-callee mapping — bind by name.** For a resolved internal
function, a keyword arg binds to the parameter with the **same name**, not by
position. The flow/emit logic maps `name=value` to `callee.params` by name;
positional args keep index mapping. If a kwarg names a param the callee doesn't
have (`**kwargs` / arity mismatch), that is a blind edge, not a silent drop.

**Regression fixture:** `cur.execute(query=user_input)` → `TAINT-SQLI` finding.

### Part C — PY-DEBUG false positive (#4) — SEPARATE BRANCH/PR

This ships on its own branch off `master` (own PR, parallel to PR #1); it does
not touch the taint engine. The rule is single-line regex with no class context. Two viable heuristics:

- **C-pref (context-aware suppression):** when the `DEBUG=True` match sits inside
  a class whose name matches `/Dev|Test|Debug|Local/`, AND the file also defines
  a config class with `DEBUG=False` (a prod config), downgrade or suppress. This
  needs a small lookbehind for the enclosing `class` line (the engine already
  does a 25-line lookahead elsewhere, so bounded context scanning has precedent).
- **C-alt (severity reclass):** lower bare `DEBUG=True` in a config-class file to
  Média with a note, reserving Alto for `app.run(debug=True)` (runtime, not
  config). Smaller, less precise.

Recommendation: **C-pref** — it targets the exact false positive (Dev config +
existing Prod config) without weakening the genuine `app.run(debug=True)` case.
Final heuristic to be confirmed in the plan; Codex review will weigh in.

**Regression fixtures:** Dev/Prod config pair (no Alto) vs `app.run(debug=True)`
(still Alto) vs a lone `DEBUG=True` config with no Prod counterpart (stays Alto —
genuinely risky).

### Part D — Repo hygiene

- Delete the `MAX_DEPTH` junk file (artifact of `node -e` on Git Bash/Windows).
- Version `.planning/phases/01-skill-router/01-RESEARCH.md` (`git add`), matching
  its tracked siblings and closing Codex's open question.
- Fix trailing whitespace in `scripts/vendor/README.md` and the blank line at
  EOF of `docs/superpowers/specs/2026-05-31-scanner-rule-registry-design.md` so
  `git diff --check master...HEAD` is clean.

## Testing

- All new behavior is covered by fixtures added to `tests/rock-house-ci.test.js`
  (the existing harness), asserting on emitted findings and blind-edge counts.
- Existing suite must stay green; demo must still block (exit 1); self-scan must
  stay Ouro 10/10.
- `git diff --check master...HEAD` must pass.

## Verification (definition of done, pre-merge)

1. `helper-returns-source` and `helper-returns-param` fixtures → `TAINT-SQLI`
   finding with cross-function trace.
2. `cur.execute(query=user_input)` → `TAINT-SQLI` finding.
3. Dev/Prod config pair → no PY-DEBUG Alto; `app.run(debug=True)` → still Alto.
4. `node tests/rock-house-ci.test.js` → `rock-house-ci tests passed`.
5. Self-scan Ouro 10/10; demo blocks.
6. `git diff --check master...HEAD` clean; no untracked junk in `git status`.

## Post-merge backlog (issues to file)

- **#3** module-alias call resolution (`import db; db.run_query()`) — recall.
- **#6** SHA256 checksums for vendored Tree-sitter assets — supply-chain.
- README/Marketplace update mentioning the taint engine as deep-analysis layer.
