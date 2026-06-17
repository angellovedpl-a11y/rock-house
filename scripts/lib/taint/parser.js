'use strict';

const path = require('path');
const { Parser, Language } = require('../../vendor/web-tree-sitter/tree-sitter.js');

const WASM_RUNTIME_DIR = path.join(__dirname, '..', '..', 'vendor', 'web-tree-sitter');
const PYTHON_WASM = process.env.ROCKHOUSE_PYTHON_WASM
  || path.join(__dirname, '..', '..', 'vendor', 'tree-sitter-python.wasm');

let _parser = null;
let _initError = null;

async function getParser() {
  if (_parser) return _parser;
  if (_initError) throw _initError;
  try {
    await Parser.init({ locateFile: (name) => path.join(WASM_RUNTIME_DIR, name) });
    const parser = new Parser();
    const Python = await Language.load(PYTHON_WASM);
    parser.setLanguage(Python);
    _parser = parser;
    return _parser;
  } catch (err) {
    _initError = err;
    throw err;
  }
}

async function parse(source) {
  const parser = await getParser();
  return parser.parse(typeof source === 'string' ? source : String(source));
}

// Lets callers detect "parser unavailable" without crashing the scan.
async function isAvailable() {
  try { await getParser(); return true; } catch (e) { return false; }
}

module.exports = { parse, getParser, isAvailable };
