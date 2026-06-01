const REPO_URL = 'https://github.com/angellovedpl-a11y/rock-house';

function toMarkdown(report) {
  const statusLine = report.result === 'blocked'
    ? 'Deploy bloqueado pelo Rock House.'
    : 'Gate Rock House aprovado para o nivel configurado.';
  const topFindings = report.findings.slice(0, 10);
  const topUnknown = report.unknown.slice(0, 10);

  return [
    '# Rock House Security Gate',
    '',
    `**Resultado:** ${report.result}`,
    `**Certificacao:** ${report.certification}`,
    `**Score:** ${report.score}/10`,
    `**Confianca:** ${report.confidence}`,
    `**Alvo:** \`${report.target}\``,
    `**Perfil de risco:** \`${report.riskProfile}\``,
    report.assurance.file ? `**Assurance:** \`${report.assurance.file}\`` : '',
    report.dast.configured ? `**DAST:** \`${report.dast.url}\` (${report.dast.executed ? 'executado' : 'nao executado'})` : '',
    report.observability.configured ? `**Observability:** ${report.observability.note}` : '',
    report.baseline.path ? `**Baseline:** \`${report.baseline.path}\` (${report.baseline.matched} conhecidos, ${report.baseline.new} novos)` : '',
    '',
    statusLine,
    '',
    '## Resumo',
    '',
    '| Critico | Alto | Medio | Baixo | UNKNOWN |',
    '|---------|------|-------|-------|---------|',
    `| ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} | ${report.summary.unknown} |`,
    '',
    '## Cobertura',
    '',
    report.coverage
      ? `${report.coverage.audited ? '✅' : '⚠️'} ${report.coverage.note}`
      : 'Cobertura não avaliada.',
    report.coverage && report.coverage.gaps && report.coverage.gaps.length
      ? `**Pontos cegos:** ${report.coverage.gaps.join(', ')}`
      : '',
    '',
    '## Bloqueios / Findings',
    '',
    topFindings.length ? findingsTable(topFindings) : 'Nenhum finding reportado.',
    '',
    report.findings.length > topFindings.length ? `_Mostrando 10 de ${report.findings.length} findings._` : '',
    '',
    '## Pacotes de Correcao',
    '',
    fixPacksSection(topFindings),
    '',
    '## Supressoes',
    '',
    report.suppressed.length ? suppressedTable(report.suppressed.slice(0, 10)) : 'Nenhuma supressao aplicada.',
    '',
    report.suppressed.length > 10 ? `_Mostrando 10 de ${report.suppressed.length} supressoes._` : '',
    '',
    '## Baseline',
    '',
    report.baseline.path
      ? `Baseline carregado. Findings conhecidos: ${report.baseline.matched}. Findings novos: ${report.baseline.new}. Modo fail-on-new-only: ${report.baseline.failOnNewOnly}.`
      : 'Nenhum baseline carregado.',
    '',
    '## UNKNOWN',
    '',
    topUnknown.length ? unknownTable(topUnknown) : 'Nenhum UNKNOWN reportado.',
    '',
    report.unknown.length > topUnknown.length ? `_Mostrando 10 de ${report.unknown.length} UNKNOWN._` : '',
    '',
    '## Proximas Acoes',
    '',
    nextActions(report).map((action, index) => `${index + 1}. ${action}`).join('\n'),
    ''
  ].filter((line) => line !== null).join('\n');
}

function toSarif(report) {
  const rulesById = new Map();
  for (const finding of report.findings) {
    if (!rulesById.has(finding.checkId)) {
      rulesById.set(finding.checkId, {
        id: finding.checkId,
        name: `${finding.vector}: ${finding.rule?.title || finding.checkId}`,
        shortDescription: { text: finding.description },
        fullDescription: { text: `${finding.description} ${finding.impact}` },
        help: { text: `${finding.recommendation}\n\nOWASP: ${(finding.rule?.owasp || []).join(', ') || 'n/a'}\nCWE: ${(finding.rule?.cwe || []).join(', ') || 'n/a'}` },
        helpUri: finding.rule?.helpUri,
        properties: {
          precision: 'medium',
          securitySeverity: securitySeverity(finding.severity),
          tags: [
            'security',
            'rock-house',
            finding.vector.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
            ...(finding.rule?.owasp || []),
            ...(finding.rule?.cwe || [])
          ]
        }
      });
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Rock House',
            informationUri: REPO_URL,
            semanticVersion: report.version.replace(/^[^0-9]*/, '') || '0.1.0',
            rules: Array.from(rulesById.values())
          }
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.checkId,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.severity}: ${finding.description} Recommendation: ${finding.recommendation}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.file.replace(/\\/g, '/')
                },
                region: {
                  startLine: Math.max(1, finding.line || 1)
                }
              }
            }
          ],
          properties: {
            severity: finding.severity,
            vector: finding.vector,
            owasp: finding.rule?.owasp || [],
            cwe: finding.rule?.cwe || [],
            impact: finding.impact,
            recommendation: finding.recommendation,
            fixBefore: finding.fixPack?.before || '',
            fixAfter: finding.fixPack?.after || '',
            fixCommand: finding.fixPack?.command || ''
          }
        }))
      }
    ]
  };
}

function suppressedTable(items) {
  const rows = [
    '| Severidade | Check | OWASP/CWE | Arquivo | Motivo | Expira |',
    '|------------|-------|----------|---------|--------|--------|'
  ];
  for (const item of items) {
    rows.push(`| ${escapeMd(item.severity)} | ${escapeMd(item.checkId)} | ${escapeMd(ruleLabel(item))} | \`${escapeMd(`${item.file}:${item.line}`)}\` | ${escapeMd(item.suppression.reason)} | ${escapeMd(item.suppression.expires || 'n/a')} |`);
  }
  return rows.join('\n');
}

function findingsTable(items) {
  const rows = [
    '| Severidade | Check | OWASP/CWE | Arquivo | Descricao | Recomendacao |',
    '|------------|-------|----------|---------|-----------|--------------|'
  ];
  for (const finding of items) {
    rows.push(`| ${escapeMd(finding.severity)} | ${escapeMd(finding.checkId)} | ${escapeMd(ruleLabel(finding))} | \`${escapeMd(`${finding.file}:${finding.line}`)}\` | ${escapeMd(finding.description)} | ${escapeMd(finding.recommendation)} |`);
  }
  return rows.join('\n');
}

function fixPacksSection(items) {
  const blocks = [];
  for (const f of items) {
    if (!f.fixPack) continue;
    const fp = f.fixPack;
    const lines = [
      `### [${f.severity}] ${f.checkId} — ${escapeMd(f.rule?.title || f.description)}  (\`${f.file}:${f.line}\`)`,
      fp.why ? `**Por que:** ${escapeMd(fp.why)}` : '',
      fp.before ? `**Antes:** \`${escapeMd(fp.before)}\`` : '',
      fp.after ? `**Depois:** \`${escapeMd(fp.after)}\`` : '',
      fp.command ? `**Comando:** \`${escapeMd(fp.command)}\`` : '',
      Array.isArray(fp.refs) && fp.refs.length ? `**Ref:** ${escapeMd(fp.refs.join(' / '))}` : ''
    ].filter((l) => l !== '');
    blocks.push(lines.join('\n'));
  }
  return blocks.length ? blocks.join('\n\n') : 'Nenhum pacote de correcao disponivel.';
}

function unknownTable(items) {
  const rows = [
    '| Check | OWASP/CWE | Area | Motivo | Como Resolver | Bloqueia |',
    '|-------|----------|------|--------|---------------|----------|'
  ];
  for (const item of items) {
    rows.push(`| ${escapeMd(item.checkId)} | ${escapeMd(ruleLabel(item))} | ${escapeMd(item.area)} | ${escapeMd(item.whyUnknown)} | ${escapeMd(item.howToResolve)} | ${escapeMd(item.blocks)} |`);
  }
  return rows.join('\n');
}

function ruleLabel(item) {
  const rule = item.rule || { owasp: [], cwe: [] };
  return [...(rule.owasp || []), ...(rule.cwe || [])].join(', ') || 'n/a';
}

function nextActions(report) {
  if (report.summary.critical > 0) {
    return [
      'Corrigir todos os findings Critico antes de qualquer deploy.',
      'Rodar novamente o gate com JSON e SARIF.',
      'Reduzir UNKNOWN que bloqueiam Ouro ou Prata.'
    ];
  }
  if (report.summary.high > 0) {
    return [
      'Corrigir findings Alto para sair de Bronze.',
      'Revisar as evidencias no JSON/SARIF.',
      'Rodar o modo interativo `/rock-house certify` para revisar camadas.'
    ];
  }
  if (report.summary.unknown > 0) {
    return [
      'Resolver UNKNOWN pendentes para aumentar confianca.',
      'Executar scanners externos de secrets/dependencias quando aplicavel.',
      'Reexecutar o gate para buscar Prata/Ouro.'
    ];
  }
  return [
    'Manter o gate no CI.',
    'Rodar `/rock-house certify` antes de releases maiores.',
    'Adicionar testes de seguranca para novos fluxos sensiveis.'
  ];
}

function escapeMd(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

function sarifLevel(severity) {
  if (severity === 'Critico' || severity === 'Alto') return 'error';
  if (severity === 'Medio') return 'warning';
  return 'note';
}

function securitySeverity(severity) {
  if (severity === 'Critico') return '9.0';
  if (severity === 'Alto') return '7.0';
  if (severity === 'Medio') return '5.0';
  return '2.0';
}

module.exports = {
  toMarkdown,
  toSarif
};
