const RULES = {
  S2: { title: 'Git history secrets scan unavailable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S4: { title: 'Sensitive public environment variable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S7: { title: 'Stack trace disclosure', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-209'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A1: { title: 'Privileged key in client-side code', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-798', 'CWE-200'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A3: { title: 'Missing ownership check', owasp: ['A01:2021 Broken Access Control', 'API1:2023 Broken Object Level Authorization'], cwe: ['CWE-639', 'CWE-862'], helpUri: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/' },
  I2: { title: 'DOM XSS sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I3: { title: 'React HTML injection sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I4: { title: 'External input reaches code execution', owasp: ['A03:2021 Injection'], cwe: ['CWE-95'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  H4: { title: 'Permissive CORS', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-942'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  D1: { title: 'Missing lockfile', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D2: { title: 'Dependency audit unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D3: { title: 'Advisory database unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D4: { title: 'Loose dependency version', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' }
};

function ruleFor(checkId) {
  return RULES[checkId] || {
    title: checkId,
    owasp: [],
    cwe: [],
    helpUri: 'https://owasp.org/www-project-top-ten/'
  };
}

function impactFor(severity) {
  if (severity === 'Critico') return 'May allow data exposure, account takeover, or full system compromise.';
  if (severity === 'Alto') return 'May significantly weaken confidentiality, integrity, or access control.';
  if (severity === 'Medio') return 'May increase risk under specific conditions.';
  return 'Hardening improvement.';
}

module.exports = {
  impactFor,
  ruleFor
};
