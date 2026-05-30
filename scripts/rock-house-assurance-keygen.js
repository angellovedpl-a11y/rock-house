#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = parseArgs(process.argv.slice(2));
const privateOut = args['private-out'] ? path.resolve(args['private-out']) : '';
const publicOut = args['public-out'] ? path.resolve(args['public-out']) : '';

if (!privateOut || !publicOut) {
  usage('Provide --private-out and --public-out paths.');
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
fs.mkdirSync(path.dirname(privateOut), { recursive: true });
fs.mkdirSync(path.dirname(publicOut), { recursive: true });
fs.writeFileSync(privateOut, privateKey.export({ type: 'pkcs8', format: 'pem' }), 'utf8');
fs.writeFileSync(publicOut, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
console.log(`Generated Ed25519 key pair:\nprivate=${privateOut}\npublic=${publicOut}`);

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
  console.error(`Rock House assurance keygen error: ${message}`);
  process.exit(2);
}
