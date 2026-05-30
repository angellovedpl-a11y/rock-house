function shouldFlagInnerHtml(lines, index) {
  const line = lines[index];
  if (!/\binnerHTML\s*=/.test(line)) return false;

  const expression = collectAssignmentExpression(lines, index);
  if (/(escapeHtml|sanitizeHtml|DOMPurify\.sanitize)\s*\(/.test(expression)) return false;
  if (/\$\{[^}]+\}/.test(expression)) return true;

  const rhs = expression.split(/\binnerHTML\s*=/)[1] || '';
  if (/^\s*['"`][\s\S]*['"`]\s*;?\s*$/.test(rhs)) return false;
  if (/^\s*[A-Za-z_$][\w$]*\([^)]*\)\s*;?\s*$/.test(rhs)) return false;

  return /(\+|\b(req|query|body|input|message|user|data|payload|params)\b)/i.test(rhs);
}

function collectAssignmentExpression(lines, startIndex) {
  const collected = [];
  for (let i = startIndex; i < Math.min(lines.length, startIndex + 25); i += 1) {
    collected.push(lines[i]);
    if (/;\s*$/.test(lines[i])) break;
  }
  return collected.join('\n');
}

module.exports = {
  shouldFlagInnerHtml
};
