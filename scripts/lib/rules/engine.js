const LANGUAGE_BY_EXT = {
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js',
  '.ts': 'js', '.tsx': 'js',
  '.py': 'py',
  '.sql': 'sql',
  '.html': 'html', '.css': 'css',
  '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml'
};

function languageFor(ext) {
  return LANGUAGE_BY_EXT[ext] || 'other';
}

function ruleAppliesToFile(rule, language, rel) {
  const langs = rule.languages || ['*'];
  if (!langs.includes('*') && !langs.includes(language)) return false;
  if (rule.pathTest && !rule.pathTest(rel)) return false;
  if (rule.allowlist && rule.allowlist.some((re) => re.test(rel))) return false;
  return true;
}

function flowConfirms(rule, lines, index) {
  const flow = rule.flow;
  if (!flow) return true;
  const text = flow.context
    ? lines.slice(Math.max(0, index - flow.context), Math.min(lines.length, index + flow.context + 1)).join('\n')
    : lines.slice(index, Math.min(lines.length, index + (flow.window || 25))).join('\n');
  if (flow.negate && flow.negate.test(text)) return false;
  if (flow.confirm && !flow.confirm.test(text)) return false;
  return true;
}

function runRules({ rules, language, rel, lines, addFinding, gates }) {
  for (const rule of rules) {
    if (!ruleAppliesToFile(rule, language, rel)) continue;
    lines.forEach((line, index) => {
      if (rule.lineAllowlist && rule.lineAllowlist.some((re) => re.test(line))) return;
      const hit = rule.customMatch
        ? rule.customMatch(lines, index, rel)
        : rule.pattern.test(line);
      if (!hit) return;
      if (!rule.customMatch && !flowConfirms(rule, lines, index)) return;
      if (rule.gate) {
        gates.push({
          id: rule.gate.id,
          status: rule.gate.status,
          evidence: `${rel}:${index + 1}`,
          note: rule.gate.note
        });
        return;
      }
      addFinding(rule.severity, rule.id, rule.vector, rel, index + 1, rule.message, rule.recommendation, rule.fixPack);
    });
  }
}

module.exports = { languageFor, runRules };
