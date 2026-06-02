# Vendored WASM Assets

These files are vendored so Rock House can parse Python without any `npm install` at runtime.

## File Provenance

| File | Source | Version | License | Size |
|------|--------|---------|---------|------|
| `web-tree-sitter/tree-sitter.js` | npm: `web-tree-sitter` (CJS build, copied from `tree-sitter.cjs`) | 0.25.0 | MIT | 160,642 B |
| `web-tree-sitter/tree-sitter.wasm` | npm: `web-tree-sitter` | 0.25.0 | MIT | 204,350 B |
| `tree-sitter-python.wasm` | GitHub release: `tree-sitter/tree-sitter-python` | 0.25.0 | MIT | 457,883 B |

npm source: https://www.npmjs.com/package/web-tree-sitter  
GitHub source: https://github.com/tree-sitter/tree-sitter-python/releases/tag/v0.25.0

## Version notes

- `web-tree-sitter` 0.25.0 and `tree-sitter-python` 0.25.0 share the same tree-sitter core version and ABI — they must be upgraded together.
- The npm package ships `tree-sitter.cjs` (CommonJS) alongside `tree-sitter.js` (ESM). We vendor the CJS build as `tree-sitter.js` so Node.js `require()` works without a `package.json`.
- `tree-sitter-python`'s npm package (v0.21.0) ships only native `.node` prebuilts, not a WASM. The WASM is published as a GitHub release asset starting from v0.23.3.

## Working invocation (for `scripts/parser.js` — next task)

```js
const path = require('path');
const { Parser, Language } = require('./vendor/web-tree-sitter/tree-sitter.js');

await Parser.init({
  locateFile: (name) => path.join(__dirname, 'vendor/web-tree-sitter', name)
});

const parser = new Parser();
const Python = await Language.load(path.join(__dirname, 'vendor/tree-sitter-python.wasm'));
parser.setLanguage(Python);

const tree = parser.parse('def f(x):\n    return x\n');
// tree.rootNode.type === 'module'
// tree.rootNode.firstChild.type === 'function_definition'
```

Key points:
- Named exports `{ Parser, Language }` — NOT a default export.
- `Parser.init({ locateFile })` must be called once before constructing any `Parser`.
- `locateFile` is required so the runtime can find `tree-sitter.wasm` in the vendored path.
- `Language.load(filePath)` accepts a file path string in Node.js (reads via `fs/promises`).

## Updating

To update these assets, re-run Task 0 of `docs/superpowers/plans/2026-06-01-python-taint-engine.md`.
