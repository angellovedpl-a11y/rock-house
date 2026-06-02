'use strict';

// symbols.js — project-wide symbol table for inter-procedural taint analysis.
//
// buildSymbolTable(fileIRs) indexes all functions by qualified name and resolves
// `from X import Y` imports across files within the same repo.

function buildSymbolTable(fileIRs) {
  const functionByQual = new Map();   // "db.run_query" -> FunctionIR
  const moduleFunctions = new Map();  // "db" -> Map(name -> FunctionIR)
  const importsByFile = new Map();    // "views.py" -> Map(localName -> "db.run_query")

  for (const ir of fileIRs) {
    const m = new Map();
    for (const fn of ir.functions) {
      functionByQual.set(fn.qualname, fn);
      m.set(fn.name, fn);
    }
    moduleFunctions.set(ir.modulePrefix, m);
    importsByFile.set(ir.path, ir.imports || new Map());
  }

  function resolveImported(fromFile, localName) {
    const imp = importsByFile.get(fromFile);
    if (imp && imp.has(localName)) {
      const qual = imp.get(localName);
      if (functionByQual.has(qual)) return functionByQual.get(qual);
    }
    return null;
  }

  return { functionByQual, moduleFunctions, importsByFile, resolveImported };
}

module.exports = { buildSymbolTable };
