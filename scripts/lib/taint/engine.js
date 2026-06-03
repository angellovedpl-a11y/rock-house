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
  const sourceTainted = new Set(); // tainted IGNORING params (source-driven only) → returnIsSource
  const sinkHits = [];
  const paramReachesSink = new Map();
  const paramTaintsReturn = new Set();
  // Params that flow (directly here, or transitively via the fixpoint) into an
  // UNRESOLVED call — an honest blind edge the engine cannot follow. Seeded empty
  // by the intra pass; populated from blindFlows + composed through the fixpoint.
  const paramReachesBlind = new Set();

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
      const ts = exprIsTainted(ev.a.value, sourceTainted);
      for (const tgt of ev.a.targets) { if (ts) sourceTainted.add(tgt); else sourceTainted.delete(tgt); }
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

  let returnIsSource = false;
  for (const r of fn.returns) {
    if (!r.value) continue;
    if (exprIsTainted(r.value, tainted)) {
      for (const p of seedParams) if ((r.value.reads || []).includes(p)) paramTaintsReturn.add(p);
    }
    if (exprIsTainted(r.value, sourceTainted)) returnIsSource = true;
  }

  return { sinkHits, summary: { paramReachesSink, paramTaintsReturn, paramReachesBlind, returnIsSource } };
}

const { resolveCall } = require('./callgraph');

// Bound on summary-composition fixpoint iterations. Also bounds trace/path depth and
// guarantees termination on cyclic (even self-recursive) call graphs: each iteration
// only adds sink-reachability facts, the lattice is finite, and we stop on "no change".
const MAX_DEPTH = 8;

function sevForSink(sinkId) {
  return (sinkId === 'TAINT-PATH' || sinkId === 'TAINT-REDIRECT' || sinkId === 'TAINT-DESERIALIZE') ? 'Alto' : 'Critico';
}

// Walk a function with its params seeded as tainted and report, per call, which
// of the function's OWN params taint each argument (provenance), plus per-var origin
// for trace building. Sanitizer/parameterized-SQL gating is identical to the intra
// pass: a value laundered through int()/escape()/etc. is NOT tainted, so it produces
// no flow and never composes into a sink.
//
// Returns:
//   resolvedFlows: [{ param, argIndex, calleeQual, calleeName, callLine, argText, origin }]
//       — a seed param flows into a RESOLVED repo function's argument at argIndex.
//   blindFlows:    [{ callLine, calleeDotted, params }]
//       — a tainted arg (from a source or a seed param) flows into an UNRESOLVED call.
//         `params` is the set of THIS function's seed params whose taint reaches that
//         unresolved call, so the fixpoint can compose "param reaches a blind edge"
//         transitively (and the emit pass can raise an honest blind edge).
function computeParamCallFlows(fn, file, symbols) {
  const seedParams = fn.params || [];
  const seedSet = new Set(seedParams);
  // provenance: var -> Set(seedParam) that taints it. A var tainted only by a source
  // (not by any param) maps to an empty set but is present in `taintedBySource`.
  const provenance = new Map();
  const taintedBySource = new Set(); // vars tainted (incl. via source), regardless of params
  const originOf = new Map();        // var -> { file, line, text }
  for (const p of seedParams) provenance.set(p, new Set([p]));

  const resolvedFlows = [];
  const blindFlows = [];

  // taintedVars view (booleans) for the existing exprIsTainted gate.
  const taintedVars = new Set(seedParams);

  // Which seed params taint this expression? Honors sanitizer gating via exprIsTainted.
  function provenanceOf(expr) {
    const set = new Set();
    if (!expr) return set;
    if (!exprIsTainted(expr, taintedVars)) return set; // sanitized / untainted → no provenance
    for (const id of expr.reads || []) {
      const pv = provenance.get(id);
      if (pv) for (const p of pv) set.add(p);
    }
    return set;
  }

  const events = [];
  for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
  const seenInterCallKeys = new Set();
  for (const c of fn.calls) {
    const key = `${c.line}:${c.calleeDotted}`;
    if (!seenInterCallKeys.has(key)) { seenInterCallKeys.add(key); events.push({ kind: 'call', line: c.line, c }); }
  }
  events.sort((x, y) => x.line - y.line);

  for (const ev of events) {
    if (ev.kind === 'assign') {
      const t = exprIsTainted(ev.a.value, taintedVars);
      const pv = provenanceOf(ev.a.value);
      for (const tgt of ev.a.targets) {
        if (t) {
          taintedVars.add(tgt); taintedBySource.add(tgt);
          provenance.set(tgt, new Set(pv));
          originOf.set(tgt, { file: file.path, line: ev.a.line, text: ev.a.value.text });
        } else {
          taintedVars.delete(tgt); taintedBySource.delete(tgt);
          provenance.delete(tgt); originOf.delete(tgt);
        }
      }
    } else {
      const call = ev.c;
      // Parameterized SQL (execute(sql, params)) where the SQL string is clean is safe.
      const sink = sinkFor(call.calleeDotted);
      const args = call.args || [];
      const taintedArgIdx = args.findIndex((arg) => exprIsTainted(arg, taintedVars));
      if (taintedArgIdx === -1) continue;
      if (sink && sink.id === 'TAINT-SQLI' && sqlIsParameterized(call, taintedVars)) continue;

      const resolution = resolveCall(call, file, symbols);
      if (resolution.kind === 'external') continue; // modeled sink/sanitizer — intra pass owns it
      if (resolution.kind === 'unresolved') {
        // Which of THIS function's params taint any argument of the unresolved call?
        // Those params reach a blind edge (directly). The fixpoint composes the rest.
        const blindParams = new Set();
        for (const arg of args) for (const p of provenanceOf(arg)) blindParams.add(p);
        blindFlows.push({ callLine: call.line, calleeDotted: call.calleeDotted, params: [...blindParams] });
        continue;
      }
      // resolution.kind === 'function' — a resolved repo call. Record a flow for every
      // tainted argument whose taint derives (at least partly) from one of THIS
      // function's params, so the fixpoint can compose transitively.
      const callee = resolution.fn;
      for (let i = 0; i < args.length; i++) {
        const argExpr = args[i];
        if (!exprIsTainted(argExpr, taintedVars)) continue;
        if (sink && sink.id === 'TAINT-SQLI' && i === 0 && sqlIsParameterized(call, taintedVars)) continue;
        const pv = provenanceOf(argExpr);
        const origin = (argExpr.reads || []).map((r) => originOf.get(r)).find(Boolean);
        const calleeParam = (callee.params || [])[i];
        if (!calleeParam) continue; // arity mismatch / *args — can't map; skip (callee summary unaffected)
        for (const param of pv) {
          resolvedFlows.push({
            param, argIndex: i, calleeQual: callee.qualname, calleeName: callee.name,
            callLine: call.line, argText: argExpr.text, origin
          });
        }
        // A source-tainted (not param-tainted) arg flowing into a resolved callee is the
        // entry-point case; it does not compose a param of THIS function but the inter
        // walk below handles emission. No flow recorded here.
      }
    }
  }

  return { resolvedFlows, blindFlows };
}

function analyzeProjectTaint(fileIRs, symbols) {
  const paths = [];
  let blindEdges = 0;

  const fileOfFn = new Map();  // qualname -> FileIR
  const fnByQual = new Map();  // qualname -> FunctionIR
  for (const ir of fileIRs) {
    for (const fn of ir.functions) { fileOfFn.set(fn.qualname, ir); fnByQual.set(fn.qualname, fn); }
  }

  // 1) Initial summaries: direct (modeled) sinks reached within each function.
  const summaryOf = new Map(); // qualname -> summary { paramReachesSink, paramTaintsReturn }
  const flowsOf = new Map();   // qualname -> { resolvedFlows, blindFlows }
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const res = analyzeFunctionIntra(fn, ir.path, fn.params);
      summaryOf.set(fn.qualname, res.summary);
      const flows = computeParamCallFlows(fn, ir, symbols);
      flowsOf.set(fn.qualname, flows);
      // Seed "param reaches a blind edge" from this function's DIRECT unresolved-tail flows.
      for (const bf of flows.blindFlows) {
        for (const p of bf.params || []) res.summary.paramReachesBlind.add(p);
      }
    }
  }

  // 2) Compose summaries to a fixpoint, bounded by MAX_DEPTH iterations. A param p of F
  //    reaches a sink if it flows into a resolved callee G at index i AND G's param[i]
  //    reaches a sink (transitively). Monotonic + finite + "no change" stop ⇒ terminates
  //    even on cyclic / self-recursive call graphs.
  //    The SAME fixpoint also composes "param reaches a blind edge": if p flows into a
  //    resolved callee G at index i and G's param[i] reaches a blind edge, so does p.
  //    If the loop hits the iteration cap while still making changes, the reachability
  //    data is INCOMPLETE (non-converged) — recorded so the emit pass degrades honestly.
  let converged = false;
  for (let iter = 0; iter < MAX_DEPTH; iter++) {
    let changed = false;
    for (const [qual, flows] of flowsOf) {
      const summary = summaryOf.get(qual);
      for (const flow of flows.resolvedFlows) {
        const calleeSummary = summaryOf.get(flow.calleeQual);
        if (!calleeSummary) continue;
        const callee = fnByQual.get(flow.calleeQual);
        const calleeParam = callee && (callee.params || [])[flow.argIndex];
        if (!calleeParam) continue;
        // Compose sink-reachability.
        if (calleeSummary.paramReachesSink.has(calleeParam)) {
          const sinkId = calleeSummary.paramReachesSink.get(calleeParam)[0];
          const existing = summary.paramReachesSink.get(flow.param) || [];
          if (!existing.includes(sinkId)) {
            if (!summary.paramReachesSink.has(flow.param)) summary.paramReachesSink.set(flow.param, []);
            summary.paramReachesSink.get(flow.param).push(sinkId);
            changed = true;
          }
        }
        // Compose blind-edge reachability (HOLE 1): an unresolved tail deep in a
        // resolved chain propagates "reaches a blind edge" up to the entry param.
        if (calleeSummary.paramReachesBlind.has(calleeParam) && !summary.paramReachesBlind.has(flow.param)) {
          summary.paramReachesBlind.add(flow.param);
          changed = true;
        }
      }
    }
    if (!changed) { converged = true; break; } // fixpoint reached — data is complete
    // else: still propagating. If this was the last allowed pass, we exit the loop
    // with converged === false → reachability is INCOMPLETE (over-depth, HOLE 2).
  }

  // 3) Emit cross-file paths + honest blind edges by walking each function once more.
  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
      const tainted = new Set();
      const originOf = new Map(); // var -> { file, line, text }
      const events = [];
      for (const a of fn.assignments) events.push({ kind: 'assign', line: a.line, a });
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
            else { tainted.delete(tgt); originOf.delete(tgt); }
          }
        } else {
          const call = ev.c;
          const sink = sinkFor(call.calleeDotted);
          const taintedArgIdx = (call.args || []).findIndex((arg) => exprIsTainted(arg, tainted));
          if (taintedArgIdx === -1) continue;
          // Parameterized SQL with a clean string is safe — not a flow, not a blind edge.
          if (sink && sink.id === 'TAINT-SQLI' && sqlIsParameterized(call, tainted)) continue;
          const resolution = resolveCall(call, ir, symbols);
          if (resolution.kind === 'unresolved') { blindEdges += 1; continue; }
          if (resolution.kind !== 'function') continue; // external/modeled sinks handled by intra pass
          const callee = resolution.fn;
          const summary = summaryOf.get(callee.qualname);
          const param = callee.params[taintedArgIdx];
          if (!summary || !param) {
            // Resolved callee but we can't map the argument to a param (arity/star-args):
            // sink-reachability is UNKNOWN within the bound → honest blind edge.
            blindEdges += 1;
            continue;
          }
          // HOLE 1: the tainted arg maps to a param that flows into an UNRESOLVED call
          // (directly or transitively). We can't follow past that point → blind edge.
          // (If it ALSO reaches a known sink we fall through and emit the path instead.)
          if (summary.paramReachesBlind.has(param) && !summary.paramReachesSink.has(param)) {
            blindEdges += 1;
            continue;
          }
          if (!summary.paramReachesSink.has(param)) {
            // Resolved & (within the bound) NOT known to reach a sink. If the fixpoint
            // did NOT converge (HOLE 2: chain deeper than MAX_DEPTH), this "clean"
            // verdict is untrustworthy → degrade honestly to a blind edge rather than
            // silently report safe. Converged runs are unaffected.
            if (!converged) blindEdges += 1;
            continue;
          }
          const sinkId = summary.paramReachesSink.get(param)[0];
          const sev = sevForSink(sinkId);
          const argExpr = call.args[taintedArgIdx];
          const origin = (argExpr.reads || []).map((r) => originOf.get(r)).find(Boolean);
          const hops = buildHops(callee, fileOfFn, fnByQual, flowsOf, param, ir, call, argExpr, origin);
          paths.push({ sinkId, severity: sev, hops });
        }
      }
    }
  }

  return { paths, blindEdges };
}

// Per-function return-taint: returnIsSource (source-driven, unconditional) and the
// param indices whose taint reaches the return. Composed to a bounded fixpoint so a
// function that returns the value of a resolved call to a return-tainted function is
// itself return-tainted. Unresolved/external return-producers do NOT set returnIsSource
// here — exprIsTainted falls back to its conservative arg-flow for those.
function buildReturnTaint(fileIRs, symbols) {
  const summary = new Map();  // qualname -> { returnIsSource, paramReturnIdx:Set<int> }

  for (const ir of fileIRs) {
    for (const fn of ir.functions) {
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

// Build a source→…→sink hop trace, expanding intermediate resolved hops up to MAX_DEPTH
// so deep chains (profile → wrapper → run_query → execute) point at the TRUE sink file/line.
function buildHops(callee, fileOfFn, fnByQual, flowsOf, entryParam, callerIr, call, argExpr, origin) {
  const hops = [];
  if (origin) hops.push({ file: origin.file, line: origin.line, text: origin.text, role: 'source' });
  hops.push({ file: callerIr.path, line: call.line, text: `${callee.name}(${argExpr.text})`, role: 'call' });

  // Follow the resolved chain: from `callee` with `entryParam`, descend through resolved
  // flows toward the first modeled sink, recording each intermediate call. Bounded by
  // MAX_DEPTH and a visited-set so cycles can't loop forever.
  let curQual = callee.qualname;
  let curParam = entryParam;
  const visited = new Set();
  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    if (visited.has(`${curQual}#${curParam}`)) break;
    visited.add(`${curQual}#${curParam}`);
    const curFn = fnByQual.get(curQual);
    const curFile = fileOfFn.get(curQual);
    if (!curFn || !curFile) break;
    // Does this function hit a modeled sink directly on curParam? Detect via a fresh intra
    // pass seeded with ONLY curParam, so every recorded sinkHit is reached via the tracked
    // param. Pick the first such hit (sinkHits are in source order) as the trace endpoint.
    const intra = analyzeFunctionIntra(curFn, curFile.path, [curParam]);
    const directHit = intra.sinkHits[0];
    // Find the next resolved hop that carries curParam onward.
    const flows = flowsOf.get(curQual);
    const next = flows && flows.resolvedFlows.find((f) => f.param === curParam);
    if (directHit) {
      hops.push({ file: directHit.file, line: directHit.line, text: `${directHit.calleeDotted}(...)`, role: 'sink' });
      return hops;
    }
    if (!next) break;
    const nextFn = fnByQual.get(next.calleeQual);
    const nextFile = fileOfFn.get(next.calleeQual);
    if (!nextFn || !nextFile) break;
    hops.push({ file: curFile.path, line: next.callLine, text: `${nextFn.name}(${next.argText})`, role: 'call' });
    curQual = next.calleeQual;
    curParam = (nextFn.params || [])[next.argIndex];
    if (!curParam) break;
  }
  // Fallback sink hop (couldn't fully expand): point at the callee definition.
  const calleeFile = fileOfFn.get(callee.qualname);
  hops.push({ file: (calleeFile || callerIr).path, line: callee.startLine, text: `${callee.name}() → sink`, role: 'sink' });
  return hops;
}

module.exports = { analyzeFunctionIntra, exprIsTainted, exprIsSource, analyzeProjectTaint, computeParamCallFlows, buildReturnTaint };
