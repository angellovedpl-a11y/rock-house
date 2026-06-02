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

module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource };
