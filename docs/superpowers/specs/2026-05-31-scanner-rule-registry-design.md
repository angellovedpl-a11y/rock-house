# Rock House — Scanner Rule Registry & Coverage-Aware Confidence

**Date:** 2026-05-31
**Status:** Approved (design)
**Branch:** `feat/scanner-rule-registry`

## Problem

The deterministic CI scanner (`scripts/rock-house-ci.js`) has a strong CI/CD
platform (SARIF, baseline diff, suppressions, signed assurance bundle, DAST,
GitHub annotations) wrapped around a **shallow detection core**. An expert
review of the engine found:

1. **Confidently blind.** `calculateScore` starts at 10 and only subtracts;
   `calculateConfidence` keys off the `UNKNOWN` count, **not off coverage of the
   detected stack**. A Flask project — which the static engine barely inspects —
   passes with a high score and can earn **Ouro**. This is the worst failure
   mode of a security scanner: a false negative dressed as a clean bill of health.
2. **No in-engine secret detection.** The #1 vibe-coder vulnerability. The engine
   only flags `NEXT_PUBLIC_*` and `service_role`. `CLAUDE.md` claims "gitleaks
   patterns" but the CI scanner never invokes gitleaks — it only emits an
   `UNKNOWN` (S2). Real secrets (AWS, Stripe, Google, GitHub, PEM keys, JWT,
   hardcoded `SECRET_KEY`/passwords) pass through.
3. **Lopsided language coverage.** ~90% of rules are JS/Next/Supabase. Python/Flask
   gets zero static rules despite being the revenue projects (Bot Radar AC,
   Agenda). `.sql` files are read but no SQLi pattern exists.
4. **Single-line regex, not data flow.** `lines.forEach` inspects one line at a
   time. Real vulnerabilities are source → sink across lines/functions. Only
   `shouldFlagInnerHtml` (a 25-line lookahead) nods at flow. High false-negative
   rate by construction.
5. **Brittle, stack-specific regex.** The CORS check is shaped to the Next.js
   header-config object; a Flask `CORS(app, origins="*")` won't match. The
   ownership check (`A3`) only matches the literal `.eq('id', params.id)`.
6. **One-sentence fixes.** Each finding carries a single `fix` string — no code
   example, no before/after, no command. For an audience that does not know how
   to fix, this is the gap between "you have XSS" and the bug actually getting fixed.

## Goal

Raise the **detection engine** to the level of the platform around it, without
breaking the dependency-free / cross-platform philosophy or the 28 passing tests.
Two P0 pillars, then language parity and actionable remediation:

- **P0** Coverage-aware confidence (stop approving what wasn't audited).
- **P0** In-engine secret detection.
- **P1** Python/Flask rule parity.
- **P1** Rich fix packs (before → after + command).
- **P2** Light source→sink flow + activate dormant generic rules.

## Non-Goals (this pass)

- No auto-fix that modifies user code (`--fix`). Findings stay text-only.
- No new external dependencies. Engine stays plain Node, zero install.
- No rewrite of the working plumbing (assurance, baseline, DAST core, SARIF).
- No full AST/taint analysis — that is the documented future (Approach C).

## Architecture

### Approach chosen: B — declarative rule registry

Selected over (A) extending the inline-regex god-function `scanFiles`, and over
(C) full AST/taint, which would require a parser dependency and is out of scope.

Detection rules move from inline regex + a metadata-only `rules.js` into a
declarative registry under `scripts/lib/rules/`:

```
scripts/lib/rules/
  index.js          # loads all families, exposes rules[] + coverage helpers
  secrets.js        # P0 — provider patterns + entropy heuristic
  injection.js      # XSS, SQLi, command injection, eval
  python-flask.js   # P1 — Python/Flask specific
  headers-cors.js   # H1/H2/H3/H4/H7 static (mirrors DAST checks)
  auth-access.js    # ownership / IDOR
  supply-chain.js   # loose version, lockfile
```

### Rule shape

```js
{
  id: 'SEC-AWS',                 // stable check id (see Compatibility)
  severity: 'Critico',           // Critico | Alto | Medio | Baixo
  vector: 'Secrets',             // grouping label used in report
  languages: ['*'],              // '*' or ext list: ['py'], ['js','ts','tsx']
  pattern: /AKIA[0-9A-Z]{16}/,   // primary detection regex
  flow: null,                    // optional windowed confirmation, see below
  allowlist: [/\.env\.example$/],// optional FP guards (path or line)
  message: 'AWS access key hardcoded in source.',
  owasp: ['A02:2021 Cryptographic Failures'],
  cwe: ['CWE-798'],
  helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  fixPack: { /* see Fix Packs */ }
}
```

### Engine

`scanFiles` becomes generic. For each source file, the engine:

1. Determines the file language from extension.
2. Iterates the registry, testing only rules whose `languages` match.
3. For a `pattern` hit, if `rule.flow` is set, runs a **windowed confirmation**
   (generalized from `shouldFlagInnerHtml`): look ahead `flow.window` lines,
   require `flow.confirm`, and skip if `flow.negate` matches (e.g. a sanitizer).
4. Applies `rule.allowlist` (path/line) to suppress known false positives.
5. Emits a finding via the existing `addFinding(...)`, preserving suppression and
   baseline behavior. The dedup **fingerprint now includes the line number**
   (`checkId + file + line + description`) so two distinct occurrences that share a
   `checkId` — e.g. the four `H4` rules or the two `PY-SQL` rules — can no longer
   collapse into one and silently hide a finding (Codex plan-review correction #3).
   Adding `line` invalidates pre-existing baseline files once (all findings read as
   "new" until regenerated); this is a documented one-time reset.

**Regex statefulness guard (in code, not convention).** `.test()` is stateful when a
regex carries the `/g` or `/y` flag and would skip alternate matches across lines. The
engine wraps every regex test in a helper that resets `lastIndex` before matching, so a
stray flag in any rule can never produce an intermittent false negative — the guard
lives in the engine, not in a written rule-authoring convention (Codex correction #4).

The light-flow helper is the only "flow" mechanism in this pass. Real multi-file
taint is explicitly deferred (Approach C).

## Coverage-Aware Confidence (P0)

The engine records, during a run, a **coverage map**: for each detected stack,
whether a matching rule family was loaded and executed against matching files.

- Detected stack **with** a matching rule family that ran → coverage OK.
- Detected stack **without** a matching rule family (a true blind spot, e.g.
  Django, Go, Rails) → coverage GAP.

**Detection is repo-wide, not root-only (Codex correction #2).** Stack signals and
blind-spot manifests are collected by a single bounded walk of the whole tree
(skipping `node_modules`, `.git`, build dirs, etc.), so a monorepo's
`services/api/Cargo.toml` or `apps/web/package.json` is found wherever it lives — not
just at the repository root. A blind spot buried in a sub-package no longer slips past.

New confidence rule, layered on top of the existing UNKNOWN-based logic:

- Any coverage GAP for a detected stack → **confidence forced to `Baixa`** and a
  blind-spot note is recorded.
- **No recognized stack at all** (empty `supported`) → also **forced to `Baixa`**
  (Codex correction #1). A clean (empty) gap list is *not* enough to call a repo
  "audited": if nothing recognized was inspected, we approved nothing of substance, so
  `audited` requires `gaps.length === 0` **and** `supported.length > 0`.
- Otherwise → existing UNKNOWN-based confidence logic applies unchanged.

Because `Baixa` confidence already routes to `Bloqueado` in
`decideCertification`, a project on an unsupported stack — or one we don't recognize
at all — can no longer earn a passing grade by silence. The report gains a
**"Cobertura"** section (JSON + Markdown) listing, per detected stack: `audited` /
`not audited` and which rule families ran.

> **Calibration note:** purely static sites (HTML/CSS, no framework manifest) would
> otherwise read as "no recognized stack" → `Baixa`. A root/sub `index.html` counts as
> a minimal `static` supported signal (the engine does run `*`/`html` rules on it), so
> Angelo's static freelance sites aren't false-blocked while genuinely opaque repos are.

### Test-safety of this change

The existing `testCleanFixturePasses` fixture is Next.js; JS/headers/auth/
supply-chain families run against it → coverage OK → confidence stays as today
(`Media` from the 2 D2/D3 UNKNOWNs) → still certifies Prata → still passes the
bronze gate. The change only downgrades stacks we genuinely cannot audit.

## In-Engine Secret Detection (P0)

New `secrets.js` family. Two detection layers:

1. **Provider patterns** (Critico): AWS `AKIA…`, Stripe `sk_live`/`rk_live`,
   Google `AIza…`, GitHub `ghp_`/`gho_`/`ghs_`, Slack `xox[baprs]-…`, OpenAI
   `sk-…`, PEM private-key headers, JWT (`eyJ…` 3-part), and hardcoded
   `SECRET_KEY = "…"` / `password = "…"` assignments.
2. **Entropy heuristic** (Alto): long high-entropy string literals assigned to a
   key/token/secret-looking identifier, above a Shannon-entropy threshold.

**False-positive allowlist** (mandatory, to protect `testCleanFixturePasses` and
real repos): skip files matching `.env.example`, `*example*`, `*test*`,
`*fixture*`, `*.md`; skip placeholder values (`xxx…`, `your-…-here`, `changeme`,
`<…>`, `process.env.*`, `os.environ…`). Entropy layer never fires on these.

Gitleaks remains an **optional** deep/history scan (regex over file content
cannot see deleted-but-committed secrets in git history). The skill no longer
depends on it to catch the obvious in-tree case.

## Python / Flask Rules (P1)

New `python-flask.js` family (`languages: ['py']`, SQL where relevant):

| id | Severity | Detects |
|----|----------|---------|
| PY-DEBUG | Alto | `app.run(debug=True)` / `DEBUG = True` in prod config |
| PY-SECRET | Critico | hardcoded `SECRET_KEY = "literal"` (also caught by secrets family; keep one canonical id) |
| PY-SHELL | Critico | `subprocess.*(… shell=True)` with non-literal arg, `os.system(`, `os.popen(` |
| PY-PICKLE | Alto | `pickle.loads(` / `pickle.load(` on external input |
| PY-YAML | Alto | `yaml.load(` without `SafeLoader` |
| PY-SQL | Critico | SQL string built with f-string / `%` / `.format` / concatenation |
| PY-TEMPLATE | Alto | `render_template_string(` with non-literal input |

Each ships a fix pack and a vulnerable + clean test fixture.

## Generic / JS Gap Rules (P2)

- Activate **static** `H1/H2/H3` (missing header config in code where statically
  visible) and `H7` (open redirect: `redirect(req.query.*)` / `res.redirect(`
  with user input) — these IDs exist in `rules.js` but never fire statically today.
- **Command injection**: `child_process.exec(`/`execSync(` with interpolated input.
- **Path traversal**: `fs.*`/`open(` with unsanitized `req`/`params`/`input`.
- **SSRF**: `fetch(`/`axios(`/`requests.get(` with user-controlled URL.
- **Weak crypto**: `createHash('md5'|'sha1')`, `hashlib.md5`/`sha1`.
- **Insecure randomness**: `Math.random()` feeding a token/password/secret.

## Fix Packs (P1)

Each rule carries:

```js
fixPack: {
  why: 'Short impact sentence in PT-BR.',
  before: 'AWS_KEY = "AKIA..."',
  after:  'AWS_KEY = os.environ["AWS_KEY"]',
  command: 'git rm --cached config.py   # then rotate the key',  // optional
  refs: ['OWASP A02', 'CWE-798']
}
```

Rendering:

- **JSON**: finding gains a `fixPack` object alongside `recommendation` (the
  existing one-line `recommendation` is kept for backward compatibility and
  SARIF `help`).
- **Markdown**: a new per-finding block renders `why` + `before → after` +
  `command`. The summary findings table is unchanged; a "Pacotes de Correção"
  detail section is added below it for the top findings.
- **SARIF**: `fixPack.before/after/command` added to `result.properties`; rule
  `help.text` includes the before/after snippet.

Text-only. No file mutation.

## Migration Plan (keep all 28 tests green)

1. **Extract without behavior change.** Move existing inline checks into the
   registry under their current `checkId`s (S4, A1, I3, I2, I4, H4, S7, A3, D1,
   D4) with identical severity/message. Rewire `scanFiles` to the generic engine.
   Run `npm test` → all 28 green before adding anything.
2. **Add coverage map + confidence change.** Add "Cobertura" to report. Re-run
   full suite; confirm clean & vulnerable fixtures unchanged.
3. **Add families incrementally**, each behind its own TDD fixture pair
   (vulnerable + clean): secrets → python-flask → generic/JS gaps.
4. **Add fix packs** to all rules; extend formatters; assert presence in a new
   formatter test.
5. New rules are **additive** and calibrated (entropy + allowlist + language
   scope) so they never fire on `testCleanFixturePasses`.
6. `npm test` must pass after every family. Green is the gate to proceed.

## Future — Approach C (documented, not in scope)

Migrate the windowed-flow helper to **real taint analysis**: source → sink with
an AST, tracking data across functions and files. This likely introduces a
parser dependency, which breaks the current dependency-free constraint — making
it the natural inflection point toward the **npm plugin / SaaS** evolution noted
in `CLAUDE.md`. Captured here as the north star; out of scope for this pass.

## Affected Files

- `scripts/rock-house-ci.js` — `scanFiles` → generic engine; coverage map; wire
  confidence; stack detection feeds coverage.
- `scripts/lib/rules/*` — new registry (index + families).
- `scripts/lib/rules.js` — folded into the registry (metadata now lives with rules).
- `scripts/lib/report-formatters.js` — Cobertura section, fix-pack rendering, SARIF fields.
- `scripts/lib/js-detection.js` — generalized into the flow helper used by the engine.
- `tests/rock-house-ci.test.js` — new fixtures per family + coverage + fix-pack assertions.
- `CLAUDE.md` — correct the "gitleaks patterns" claim to reflect in-engine secrets.
- `SKILL.md` / `vectors/*` / `stacks/flask.md` — optional sync so the LLM-guided
  audit and the CI scanner agree (secondary; not a blocker for this pass).
```

