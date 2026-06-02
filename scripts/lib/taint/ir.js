'use strict';

// ir.js — lowers a tree-sitter Python AST into a taint-relevant IR.
//
// Confirmed field names (via inspector on real grammar):
//   function_definition : name, parameters, body
//   assignment          : left, right
//   attribute           : object, attribute
//   subscript           : value (the subscripted object), subscript (the key)
//   call                : function, arguments

function textOf(node, src) {
  return src.slice(node.startIndex, node.endIndex);
}

function dottedName(node, src) {
  if (!node) return null;
  if (node.type === 'identifier') return textOf(node, src);
  if (node.type === 'attribute') {
    const obj = dottedName(node.childForFieldName('object'), src);
    const attr = node.childForFieldName('attribute');
    return obj && attr ? `${obj}.${textOf(attr, src)}` : null;
  }
  if (node.type === 'subscript') return dottedName(node.childForFieldName('value'), src);
  if (node.type === 'call') return dottedName(node.childForFieldName('function'), src);
  return null;
}

function readsIn(node, src, acc) {
  if (!node) return acc;
  if (node.type === 'identifier') { acc.add(textOf(node, src)); return acc; }
  for (const child of node.namedChildren) readsIn(child, src, acc);
  return acc;
}

function describeExpr(node, src) {
  const dotted = dottedName(node, src);
  const reads = [...readsIn(node, src, new Set())];
  const isCall = node.type === 'call';
  let callee = null;
  let args = [];
  if (isCall) {
    callee = dottedName(node.childForFieldName('function'), src);
    const argList = node.childForFieldName('arguments');
    if (argList) {
      args = argList.namedChildren
        .filter((a) => a.type !== 'keyword_argument')
        .map((a) => describeExpr(a, src));
    }
  }
  return {
    dotted,
    reads,
    isCall,
    callee,
    args,
    text: textOf(node, src),
    line: node.startPosition.row + 1
  };
}

function callRecord(callNode, src) {
  const d = describeExpr(callNode, src);
  return {
    calleeDotted: d.callee || '',
    calleeLast: (d.callee || '').split('.').pop(),
    args: d.args,
    line: d.line
  };
}

function recordCalls(node, src, fn) {
  if (!node) return;
  if (node.type === 'call') fn.calls.push(callRecord(node, src));
  for (const child of node.namedChildren) recordCalls(child, src, fn);
}

function collectStatements(blockNode, src, fn) {
  for (const stmt of blockNode.namedChildren) {
    if (stmt.type === 'expression_statement') {
      const inner = stmt.firstNamedChild;
      if (!inner) continue;
      if (inner.type === 'assignment') {
        const left = inner.childForFieldName('left');
        const right = inner.childForFieldName('right');
        const targets = [...readsIn(left, src, new Set())];
        fn.assignments.push({
          targets,
          value: describeExpr(right, src),
          line: inner.startPosition.row + 1
        });
        recordCalls(right, src, fn);
      } else if (inner.type === 'call') {
        fn.calls.push(callRecord(inner, src));
        recordCalls(inner, src, fn);
      }
    } else if (stmt.type === 'return_statement') {
      const val = stmt.firstNamedChild;
      fn.returns.push({
        value: val ? describeExpr(val, src) : null,
        line: stmt.startPosition.row + 1
      });
      if (val) recordCalls(val, src, fn);
    } else if (stmt.namedChildCount) {
      for (const child of stmt.namedChildren) {
        if (child.type === 'block') collectStatements(child, src, fn);
        else recordCalls(child, src, fn);
      }
    }
  }
}

function buildFunctionIR(fnNode, src, modulePrefix) {
  const nameNode = fnNode.childForFieldName('name');
  const name = nameNode ? textOf(nameNode, src) : '<anon>';
  const params = [];
  const paramsNode = fnNode.childForFieldName('parameters');
  if (paramsNode) {
    for (const p of paramsNode.namedChildren) {
      if (p.type === 'identifier') {
        params.push(textOf(p, src));
      } else if (p.type === 'default_parameter' || p.type === 'typed_parameter') {
        const id = p.childForFieldName('name') || p.firstNamedChild;
        if (id && id.type === 'identifier') params.push(textOf(id, src));
      }
    }
  }
  const decorators = [];
  if (fnNode.parent && fnNode.parent.type === 'decorated_definition') {
    for (const d of fnNode.parent.namedChildren) {
      if (d.type === 'decorator') decorators.push(textOf(d, src));
    }
  }
  const fn = {
    name,
    qualname: modulePrefix ? `${modulePrefix}.${name}` : name,
    params,
    decorators,
    assignments: [],
    calls: [],
    returns: [],
    startLine: fnNode.startPosition.row + 1,
    endLine: fnNode.endPosition.row + 1
  };
  const body = fnNode.childForFieldName('body');
  if (body) collectStatements(body, src, fn);
  return fn;
}

function buildFileIR(tree, relPath) {
  const src = tree.rootNode.text;
  const modulePrefix = relPath.replace(/\.py$/, '').replace(/[\\/]/g, '.');
  const functions = [];
  (function walk(node) {
    if (node.type === 'function_definition') {
      functions.push(buildFunctionIR(node, src, modulePrefix));
      return;
    }
    for (const child of node.namedChildren) walk(child);
  })(tree.rootNode);
  return { path: relPath, modulePrefix, functions };
}

module.exports = { buildFileIR, describeExpr, dottedName };
