// Shared allowlist: never scan these files for secrets (placeholders/fixtures).
const FILE_ALLOWLIST = [
  /\.env\.example$/i, /example/i, /test/i, /fixture/i, /\.md$/i, /\.lock$/i
];
// Lines that are obviously not real secrets.
const LINE_ALLOWLIST = [
  /your[-_].*[-_](key|secret|token)|here|changeme|placeholder|xxx{2,}|<[^>]+>/i,
  /process\.env|os\.environ|import\.meta\.env/
];

function entropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const ch in freq) {
    const p = freq[ch] / str.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const ENTROPY_ASSIGN = /\b(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key)\b\s*[:=]\s*['"]([A-Za-z0-9+/_=-]{20,})['"]/i;

module.exports = [
  {
    id: 'SEC-AWS', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    message: 'Hardcoded AWS access key id found in source.',
    recommendation: 'Move the key to an environment variable and rotate it immediately.',
    fixPack: {
      why: 'Chave AWS no código = quem clonar o repo controla sua conta AWS.',
      before: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
      after: 'AWS_KEY = os.environ["AWS_KEY"]',
      command: 'git rm --cached config.py  # depois ROTACIONE a chave no IAM',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-STRIPE', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/,
    message: 'Hardcoded Stripe live secret key found in source.',
    recommendation: 'Move it to an environment variable and roll the key in the Stripe dashboard.',
    fixPack: {
      why: 'Chave sk_live_ move dinheiro real: quem tiver ela cobra e estorna na sua conta.',
      before: 'STRIPE = "sk_live_4eC39Hq..."',
      after: 'STRIPE = process.env.STRIPE_SECRET_KEY',
      command: 'Roll a chave no painel Stripe e atualize a env var',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-GOOGLE', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    message: 'Hardcoded Google API key found in source.',
    recommendation: 'Restrict and rotate the key; load it from an environment variable.',
    fixPack: {
      why: 'Chave Google exposta pode gerar cobrança e abuso de API na sua conta.',
      before: 'const KEY = "AIza...";',
      after: 'const KEY = process.env.GOOGLE_API_KEY;',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-GITHUB', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    pattern: /\bgh[opsu]_[0-9A-Za-z]{36}\b/,
    message: 'Hardcoded GitHub token found in source.',
    recommendation: 'Revoke the token on GitHub and load it from an environment variable.',
    fixPack: {
      why: 'Token GitHub dá acesso aos seus repositórios e Actions.',
      before: 'token = "ghp_xxxxxxxx..."',
      after: 'token = os.environ["GITHUB_TOKEN"]',
      command: 'Revogue em github.com/settings/tokens',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-PEM', severity: 'Critico', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    message: 'Hardcoded private key block found in source.',
    recommendation: 'Remove the key from the repo, rotate it, and store it in a secret manager.',
    fixPack: {
      why: 'Chave privada no repo permite personificar seu servidor/serviço.',
      before: '-----BEGIN RSA PRIVATE KEY-----\\n...',
      after: '// carregue de um arquivo fora do repo / secret manager',
      command: 'git rm --cached <arquivo>  # e gere um novo par de chaves',
      refs: ['OWASP A02', 'CWE-798']
    }
  },
  {
    id: 'SEC-ENTROPY', severity: 'Alto', vector: 'Secrets', languages: ['*'],
    allowlist: FILE_ALLOWLIST, lineAllowlist: LINE_ALLOWLIST,
    customMatch: (lines, index) => {
      const m = ENTROPY_ASSIGN.exec(lines[index]);
      if (!m) return false;
      return entropy(m[1]) >= 3.5;
    },
    message: 'High-entropy value assigned to a secret-looking variable.',
    recommendation: 'If this is a real secret, move it to an environment variable and rotate it.',
    fixPack: {
      why: 'String longa e aleatória colada num campo "secret/token/password" costuma ser credencial real.',
      before: 'API_TOKEN = "f3Q9...32 chars aleatórios..."',
      after: 'API_TOKEN = os.environ["API_TOKEN"]',
      refs: ['OWASP A02', 'CWE-798']
    }
  }
];
