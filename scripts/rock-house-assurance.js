#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { computeAssuranceDigest } = require('./lib/assurance');

const args = parseArgs(process.argv.slice(2));
const file = args.file ? path.resolve(args.file) : '';
const write = args.write === true;

if (!file) usage('Missing --file path to assurance JSON.');
if (!fs.existsSync(file)) usage(`Assurance file does not exist: ${file}`);

let assurance;
try {
  assurance = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (error) {
  usage(`Could not parse assurance file ${file}: ${error.message}`);
}

const digest = computeAssuranceDigest(assurance);
if (write) {
  assurance.integrity = {
    schemaVersion: 1,
    algorithm: 'sha256',
    digest
  };
  fs.writeFileSync(file, `${JSON.stringify(assurance, null, 2)}\n`, 'utf8');
  console.log(`Updated integrity digest in ${file}`);
} else {
  console.log(digest);
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      parsed[key] = true;
    } else {
      parsed[key] = next;
      i += 1;
    }
  }
  return parsed;
}

function usage(message) {
  console.error(`Rock House assurance error: ${message}`);
  process.exit(2);
}
