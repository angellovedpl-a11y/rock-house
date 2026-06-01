const META = {
  S2: { title: 'Git history secrets scan unavailable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S4: { title: 'Sensitive public environment variable', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  S7: { title: 'Stack trace disclosure', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-209'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A1: { title: 'Privileged key in client-side code', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-798', 'CWE-200'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A3: { title: 'Missing ownership check', owasp: ['A01:2021 Broken Access Control', 'API1:2023 Broken Object Level Authorization'], cwe: ['CWE-639', 'CWE-862'], helpUri: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/' },
  A4: { title: 'Protected route accessible without authentication', owasp: ['A01:2021 Broken Access Control', 'API2:2023 Broken Authentication'], cwe: ['CWE-306', 'CWE-862'], helpUri: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/' },
  I2: { title: 'DOM XSS sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I3: { title: 'React HTML injection sink', owasp: ['A03:2021 Injection'], cwe: ['CWE-79'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  I4: { title: 'External input reaches code execution', owasp: ['A03:2021 Injection'], cwe: ['CWE-95'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  H1: { title: 'Missing Content-Security-Policy header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H2: { title: 'Missing Strict-Transport-Security header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-319'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H3: { title: 'Missing X-Content-Type-Options header', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-16'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H4: { title: 'Permissive CORS', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-942'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H5: { title: 'Server header disclosure', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-200'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H6: { title: 'Dynamic target unreachable', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-770'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  H7: { title: 'Open redirect in dynamic response', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-601'], helpUri: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' },
  D1: { title: 'Missing lockfile', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D2: { title: 'Dependency audit unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D3: { title: 'Advisory database unavailable', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  D4: { title: 'Loose dependency version', owasp: ['A06:2021 Vulnerable and Outdated Components'], cwe: ['CWE-1104'], helpUri: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  R0: { title: 'Missing high-risk assurance bundle', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R1: { title: 'Missing dynamic security testing evidence', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-693'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R2: { title: 'Missing runtime monitoring evidence', owasp: ['A09:2021 Security Logging and Monitoring Failures'], cwe: ['CWE-778'], helpUri: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  R3: { title: 'Missing specialized security review evidence', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-656'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R4: { title: 'Missing human deployment approval evidence', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-285'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R5: { title: 'Invalid assurance integrity digest', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-353'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R6: { title: 'Invalid assurance signature', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R7: { title: 'Approval environment violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-284'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R8: { title: 'Approval reference violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-285'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R9: { title: 'Approval validity violates assurance policy', owasp: ['A04:2021 Insecure Design'], cwe: ['CWE-613'], helpUri: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  R10: { title: 'Assurance signed with revoked key', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  R11: { title: 'Assurance signed with non-allowed key', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-347'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  // --- new ids (detection metadata; rule objects added in later tasks) ---
  'SEC-GENERIC': { title: 'Hardcoded secret', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-AWS': { title: 'Hardcoded AWS access key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-STRIPE': { title: 'Hardcoded Stripe live key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-GOOGLE': { title: 'Hardcoded Google API key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-GITHUB': { title: 'Hardcoded GitHub token', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-PEM': { title: 'Hardcoded private key', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'SEC-ENTROPY': { title: 'High-entropy secret-like literal', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-798'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'PY-DEBUG': { title: 'Flask debug mode enabled', owasp: ['A05:2021 Security Misconfiguration'], cwe: ['CWE-489'], helpUri: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  'PY-SHELL': { title: 'Shell command injection risk', owasp: ['A03:2021 Injection'], cwe: ['CWE-78'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'PY-PICKLE': { title: 'Unsafe deserialization (pickle)', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-502'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'PY-YAML': { title: 'Unsafe YAML load', owasp: ['A08:2021 Software and Data Integrity Failures'], cwe: ['CWE-502'], helpUri: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  'PY-SQL': { title: 'SQL built from string formatting', owasp: ['A03:2021 Injection'], cwe: ['CWE-89'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'PY-TEMPLATE': { title: 'Server-side template injection risk', owasp: ['A03:2021 Injection'], cwe: ['CWE-94'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'I5': { title: 'OS command injection', owasp: ['A03:2021 Injection'], cwe: ['CWE-78'], helpUri: 'https://owasp.org/Top10/A03_2021-Injection/' },
  'I6': { title: 'Path traversal', owasp: ['A01:2021 Broken Access Control'], cwe: ['CWE-22'], helpUri: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  'I7': { title: 'Server-side request forgery', owasp: ['A10:2021 Server-Side Request Forgery'], cwe: ['CWE-918'], helpUri: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
  'C1': { title: 'Weak cryptographic hash', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-327'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  'C2': { title: 'Insecure randomness for secret', owasp: ['A02:2021 Cryptographic Failures'], cwe: ['CWE-338'], helpUri: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' }
};

// Families are added in later tasks. Each exports an array of detection rules.
const families = [];
try { families.push(require('./injection')); } catch (e) { /* added in Task 3/7 */ }
try { families.push(require('./secrets')); } catch (e) { /* added in Task 5 */ }
try { families.push(require('./python-flask')); } catch (e) { /* added in Task 6 */ }
try { families.push(require('./headers-cors')); } catch (e) { /* added in Task 3 */ }
try { families.push(require('./auth-access')); } catch (e) { /* added in Task 3 */ }

const DETECTION_RULES = families.flat();

function ruleFor(checkId) {
  return META[checkId] || { title: checkId, owasp: [], cwe: [], helpUri: 'https://owasp.org/www-project-top-ten/' };
}

function impactFor(severity) {
  if (severity === 'Critico') return 'May allow data exposure, account takeover, or full system compromise.';
  if (severity === 'Alto') return 'May significantly weaken confidentiality, integrity, or access control.';
  if (severity === 'Medio') return 'May increase risk under specific conditions.';
  return 'Hardening improvement.';
}

module.exports = { META, DETECTION_RULES, ruleFor, impactFor };
