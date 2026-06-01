const { shouldFlagInnerHtml } = require('../js-detection');

module.exports = [
  {
    id: 'I3', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /dangerouslySetInnerHTML/,
    message: 'React dangerouslySetInnerHTML can create XSS if content is user-controlled.',
    recommendation: 'Render text normally or sanitize HTML with a reviewed sanitizer.',
    fixPack: {
      why: 'HTML controlado pelo usuário vira execução de script no navegador da vítima.',
      before: '<div dangerouslySetInnerHTML={{ __html: comment }} />',
      after: '<div>{comment}</div>  // ou DOMPurify.sanitize(comment)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I2', severity: 'Alto', vector: 'Injection', languages: ['js', 'html'],
    customMatch: (lines, index) => shouldFlagInnerHtml(lines, index),
    message: 'innerHTML assignment can create DOM XSS.',
    recommendation: 'Use textContent or sanitize trusted HTML before inserting it.',
    fixPack: {
      why: 'innerHTML com dado dinâmico executa <script>/onerror injetado.',
      before: 'el.innerHTML = `<b>${user.name}</b>`;',
      after: 'el.textContent = user.name;  // ou DOMPurify.sanitize(...)',
      refs: ['OWASP A03', 'CWE-79']
    }
  },
  {
    id: 'I4', severity: 'Critico', vector: 'Injection', languages: ['js'],
    pattern: /\beval\s*\(|setTimeout\s*\([^,)]*(req|query|body|input|message)/,
    message: 'External input appears to reach code execution.',
    recommendation: 'Remove eval-like execution and validate input with a schema.',
    fixPack: {
      why: 'Entrada externa chegando em eval = execução remota de código.',
      before: 'eval(req.query.expr)',
      after: 'const value = schema.parse(req.query.expr);  // sem eval',
      refs: ['OWASP A03', 'CWE-95']
    }
  }
];
