'use strict';

const { isSourceExpr, sinkFor, isSanitizer } = require('./catalogs');

function exprIsSource(expr) {
  return !!(expr && expr.dotted && isSourceExpr(expr.dotted));
}

// Does evaluating this expression yield taint, given the current tainted-var set?
function exprIsTainted(expr, taintedVars) {
  if (!expr) return false;
  if (exprIsSource(expr)) return true;
  if (expr.isCall) {
    const last = (expr.callee || '').split('.').pop();
    if (isSanitizer(last)) return false;               // sanitized — check BEFORE reads
    return (expr.args || []).some((a) => exprIsTainted(a, taintedVars)); // taint flows through non-sanitizer calls
  }
  return (expr.reads || []).some((id) => taintedVars.has(id));
}

// execute(sql, params) is safe when the tainted value is only in the params, not the SQL string.
function sqlIsParameterized(call, taintedVars) {
  if (call.args.length < 2) return false;
  return !exprIsTainted(call.args[0], taintedVars);
}

// seedParams marks params as tainted (used by inter-procedural propagation later; empty for pure intra-proc).
function analyzeFunctionIntra(fn, file, seedParams = []) {
  const tainted = new Set(seedParams);
  const sinkHits = [];
  const paramReachesSink = new Map();
  const paramTaintsReturn = new Set();

  // Deduplicate calls by (line, calleeDotted) — ir.js may record nested calls twice.
  const seenCallKeys = new Set();
  const uniqueCalls = fn.calls.filter((c) => {
    const key = `${c.line}:${c.calleeDotted}`;
    if (seenCallKeys.has(key)) return false;
    seenCallKeys.add(key);
    return true;
  });

  const events = [];
  for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
  for (const c of uniqueCalls) events.push({ kind: 'call', line: c.line, c });
  events.sort((x, y) => x.line - y.line);

  for (const ev of events) {
    if (ev.kind === 'assign') {
      const t = exprIsTainted(ev.a.value, tainted);
      for (const tgt of ev.a.targets) { if (t) tainted.add(tgt); else tainted.delete(tgt); }
    } else {
      const call = ev.c;
      const sink = sinkFor(call.calleeDotted);
      if (!sink) continue;
      let hit = (call.args || []).some((arg) => exprIsTainted(arg, tainted));
      if (hit && sink.id === 'TAINT-SQLI' && sqlIsParameterized(call, tainted)) hit = false;
      if (!hit) continue;
      sinkHits.push({ sinkId: sink.id, severity: sink.severity, cls: sink.cls, file, line: call.line, calleeDotted: call.calleeDotted });
      for (const p of seedParams) {
        if ((call.args || []).some((arg) => (arg.reads || []).includes(p))) {
          if (!paramReachesSink.has(p)) paramReachesSink.set(p, []);
          paramReachesSink.get(p).push(sink.id);
        }
      }
    }
  }

  for (const r of fn.returns) {
    if (r.value && exprIsTainted(r.value, tainted)) {
      for (const p of seedParams) if ((r.value.reads || []).includes(p)) paramTaintsReturn.add(p);
    }
  }

  return { sinkHits, summary: { paramReachesSink, paramTaintsReturn } };
}

const { resolveCall } = require('./callgraph');

const MAX_DEPTH = 8; // reserved for future multi-hop; current pass is one-hop caller->callee summary

function analyzeProjectTaint(fileIRs, symbols) {
  const paths = [];
  let blindEdges = 0;

  // 1) Per-function summaries (seed each param tainted, see where it lands).
  const summaryOf = new Map(); // qualname -> summary
  const fileOfFn = new Map();  // qualname -> FileIR
  for (const ir of fileIRs) for (const fn of ir.functions) fileOfFn.set(fn.qualname, ir);
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const res = analyzeFunctionIntra(fn, ir.path, fn.params);
      summaryOf.set(fn.qualname, res.summary);
    }
  }

  // 2) Walk each function; a tainted local flowing into a call whose callee summary
  //    marks that param as sink-reaching => cross-file path.
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const tainted = new Set();
      const originOf = new Map(); // var -> { file, line, text }
      const events = [];
      for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
      // Deduplicate calls by (line, calleeDotted) — same as intra pass.
      const seenInterCallKeys = new Set();
      for (const c of fn.calls) {
        const key = `${c.line}:${c.calleeDotted}`;
        if (!seenInterCallKeys.has(key)) { seenInterCallKeys.add(key); events.push({ kind: 'call', line: c.line, c }); }
      }
      events.sort((x, y) => x.line - y.line);

      for (const ev of events) {
        if (ev.kind === 'assign') {
          const t = exprIsTainted(ev.a.value, tainted);
          for (const tgt of ev.a.targets) {
            if (t) { tainted.add(tgt); originOf.set(tgt, { file: ir.path, line: ev.a.line, text: ev.a.value.text }); }
            else tainted.delete(tgt);
          }
        } else {
          const call = ev.c;
          const taintedArgIdx = (call.args || []).findIndex((arg) => exprIsTainted(arg, tainted));
          if (taintedArgIdx === -1) continue;
          const resolution = resolveCall(call, ir, symbols);
          if (resolution.kind === 'unresolved') { blindEdges += 1; continue; }
          if (resolution.kind !== 'function') continue; // external/modeled sinks handled by intra pass
          const callee = resolution.fn;
          const summary = summaryOf.get(callee.qualname);
          const param = callee.params[taintedArgIdx];
          if (!summary || !param || !summary.paramReachesSink.has(param)) continue;
          const sinkId = summary.paramReachesSink.get(param)[0];
          const sev = (sinkId === 'TAINT-PATH' || sinkId === 'TAINT-REDIRECT' || sinkId === 'TAINT-DESERIALIZE') ? 'Alto' : 'Critico';
          const argExpr = call.args[taintedArgIdx];
          const origin = (argExpr.reads || []).map((r) => originOf.get(r)).find(Boolean);
          const calleeFile = fileOfFn.get(callee.qualname);
          const hops = [];
          if (origin) hops.push({ file: origin.file, line: origin.line, text: origin.text, role: 'source' });
          hops.push({ file: ir.path, line: call.line, text: `${callee.name}(${argExpr.text})`, role: 'call' });
          hops.push({ file: calleeFile.path, line: callee.startLine, text: `${callee.name}() → sink`, role: 'sink' });
          paths.push({ sinkId, severity: sev, hops });
        }
      }
    }
  }

  return { paths, blindEdges };
}

module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource, analyzeProjectTaint };
