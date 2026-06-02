'use strict';

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
      const he = typeof tree.rootNode.hasError === 'function' ? tree.rootNode.hasError() : tree.rootNode.hasError;
      if (he) coverage.blindEdges += 1;
      fileIRs.push(buildFileIR(tree, rel));
    } catch (e) { coverage.blindEdges += 1; }
  }

  coverage.ran = true;
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
