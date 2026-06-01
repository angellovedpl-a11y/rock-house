module.exports = [
  {
    id: 'H4', severity: 'Alto', vector: 'Headers & CORS', languages: ['*'],
    pattern: /Access-Control-Allow-Origin['"]?\s*,?\s*value:\s*['"]\*/,
    message: 'CORS allows every origin.',
    recommendation: 'Use an explicit origin allowlist.',
    fixPack: {
      why: 'CORS * deixa qualquer site ler respostas autenticadas do seu domínio.',
      before: "Access-Control-Allow-Origin: '*'",
      after: "origin: ['https://app.seudominio.com']",
      refs: ['OWASP A05', 'CWE-942']
    }
  },
  {
    id: 'H4', severity: 'Alto', vector: 'Headers & CORS', languages: ['*'],
    pattern: /origin\s*:\s*['"]\*/,
    message: 'CORS allows every origin.',
    recommendation: 'Use an explicit origin allowlist.',
    fixPack: {
      why: 'CORS * deixa qualquer site ler respostas autenticadas do seu domínio.',
      before: "cors({ origin: '*' })",
      after: "cors({ origin: ['https://app.seudominio.com'] })",
      refs: ['OWASP A05', 'CWE-942']
    }
  },
  {
    id: 'H4', languages: ['*'],
    pattern: /Access-Control-Allow-Credentials['"]?\s*,?\s*value:\s*['"]true/,
    gate: { id: 'H4', status: 'WARN', note: 'Credentials are enabled; open CORS becomes critical if paired with wildcard origin.' }
  },
  {
    id: 'H4', languages: ['*'],
    pattern: /credentials\s*:\s*true/,
    gate: { id: 'H4', status: 'WARN', note: 'Credentials are enabled; open CORS becomes critical if paired with wildcard origin.' }
  },
  {
    id: 'H7', severity: 'Alto', vector: 'Headers & CORS', languages: ['js', 'py'],
    pattern: /\bredirect\s*\(\s*(?:req\.|request\.)?(?:query|args|params|body|GET)[.\[]/,
    message: 'Redirect target taken directly from user input (open redirect).',
    recommendation: 'Map redirect targets through a reviewed allowlist of relative paths.',
    fixPack: {
      why: 'Redirecionar pro destino que o usuário mandar facilita phishing com seu domínio.',
      before: 'res.redirect(req.query.next)',
      after: 'const dest = ALLOWED[req.query.next] || "/"; res.redirect(dest);',
      refs: ['OWASP A01', 'CWE-601']
    }
  }
];
