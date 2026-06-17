'use strict';

// callgraph.js — resolves a call record to: a repo function, a known external
// (modeled sink/sanitizer), or an unresolved blind edge.

const { sinkFor, isSanitizer } = require('./catalogs');

/**
 * Resolve a call to one of:
 *   { kind: 'function',  fn: FunctionIR }           — repo-internal call
 *   { kind: 'external',  modeled: true }             — known sink/sanitizer
 *   { kind: 'unresolved', reason: string }           — blind edge
 *
 * @param {object} call       — call record from ir.js ({ calleeDotted, calleeLast, args, line })
 * @param {object} file       — FileIR for the file that contains the call
 * @param {object} symbols    — symbol table from symbols.js
 */
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

  // Unknown callee — blind edge.
  return { kind: 'unresolved', reason: `unresolved:${call.calleeDotted}` };
}

module.exports = { resolveCall };
