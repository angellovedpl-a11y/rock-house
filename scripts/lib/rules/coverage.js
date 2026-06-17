const fs = require('fs');
const path = require('path');

// Stacks Rock House has NO rule family for -> detecting one is a blind spot.
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

// Source extensions Rock House actually has rule families for. Finding any of these
// means we genuinely audited that language — even without a framework manifest.
const AUDITED_SOURCE = {
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'javascript', '.tsx': 'javascript',
  '.py': 'python',
  '.html': 'static'
};

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
      const sourceLang = AUDITED_SOURCE[path.extname(name)];
      if (sourceLang) supported.add(sourceLang);
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
// If no supported stack was recognized at all, we inspected nothing of substance ->
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
