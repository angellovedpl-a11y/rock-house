#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { computeAssuranceDigest, signablePayload } = require('./lib/assurance');

const args = parseArgs(process.argv.slice(2));
const file = args.file ? path.resolve(args.file) : '';
const writeIntegrity = args.write === true || args['write-integrity'] === true;
const sign = args.sign === true;
const verify = args.verify === true;
const privateKeyFile = args['private-key'] ? path.resolve(args['private-key']) : '';
const publicKeyFile = args['public-key'] ? path.resolve(args['public-key']) : '';
const keyId = args['key-id'] ? String(args['key-id']) : '';

if (!file) usage('Missing --file path to assurance JSON.');
if (!fs.existsSync(file)) usage(`Assurance file does not exist: ${file}`);

let assurance;
try {
  assurance = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (error) {
  usage(`Could not parse assurance file ${file}: ${error.message}`);
}

const digest = computeAssuranceDigest(assurance);
if (writeIntegrity) {
  assurance.integrity = {
    schemaVersion: 1,
    algorithm: 'sha256',
    digest
  };
}

if (sign) {
  if (!privateKeyFile) usage('Missing --private-key path for signature generation.');
  if (!keyId) usage('Missing --key-id for signature generation.');
  if (!fs.existsSync(privateKeyFile)) usage(`Private key file does not exist: ${privateKeyFile}`);
  const privateKey = fs.readFileSync(privateKeyFile, 'utf8');
  const signature = crypto.sign(null, Buffer.from(signablePayload(assurance), 'utf8'), privateKey).toString('base64');
  assurance.signature = {
    schemaVersion: 1,
    algorithm: 'ed25519',
    keyId,
    signature
  };
}

if (verify) {
  if (!publicKeyFile) usage('Missing --public-key path for signature verification.');
  if (!fs.existsSync(publicKeyFile)) usage(`Public key file does not exist: ${publicKeyFile}`);
  const publicKey = fs.readFileSync(publicKeyFile, 'utf8');
  const valid = assurance.signature && crypto.verify(
    null,
    Buffer.from(signablePayload(assurance), 'utf8'),
    publicKey,
    Buffer.from(String(assurance.signature.signature || ''), 'base64')
  );
  if (!valid) {
    usage(`Signature verification failed for ${file}`);
  }
  console.log(`Signature verified for ${file}`);
  process.exit(0);
}

if (writeIntegrity || sign) {
  fs.writeFileSync(file, `${JSON.stringify(assurance, null, 2)}\n`, 'utf8');
  console.log(`Updated assurance metadata in ${file}`);
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
