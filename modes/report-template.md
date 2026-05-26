# Report Template

Defines the exact output format for Rock House audit reports. All reports are in PT-BR.

## Report Header

```markdown
# 🏠 Relatório de Auditoria de Segurança — Rock House

**Projeto:** [nome do projeto]
**Data:** [YYYY-MM-DD]
**Stack detectada:** [frameworks e tecnologias encontradas]
**Módulos de vetor carregados:** [lista dos módulos usados]
**Avaliação geral:** [palha/madeira/pedra/fortaleza] ([score]/10)
```

## Severity Definitions

Use these objective criteria — do not assign severity subjectively.

| Nível | Critério | Ação |
|-------|----------|------|
| 🔴 **Crítico** | Explorável sem autenticação. Pode causar vazamento de dados ou comprometimento total do sistema. | Corrigir imediatamente |
| 🟠 **Alto** | Explorável com esforço mínimo. Impacto significativo na confidencialidade ou integridade. | Corrigir em 24h |
| 🟡 **Médio** | Requer condições específicas para explorar. Impacto limitado. | Corrigir em 1 semana |
| 🟢 **Baixo** | Risco teórico ou melhoria de hardening. Impacto mínimo. | Corrigir quando possível |

## Individual Finding Format

Each finding MUST use this exact structure:

```markdown
### Finding [NNN]: [título descritivo em PT-BR]

| Campo | Detalhe |
|-------|---------|
| **Severidade** | [🔴 Crítico / 🟠 Alto / 🟡 Médio / 🟢 Baixo] |
| **Vetor** | [categoria do ataque — ex: Injection, Auth & Access] |
| **Arquivo** | `[caminho/do/arquivo.ext]:[linha]` |
| **Descrição** | [o que foi encontrado, linguagem clara sem jargão] |
| **Impacto** | [o que um atacante poderia fazer] |
| **Defesa Atual** | [o que protege agora — "Nenhuma" se não houver] |
| **Defesa Recomendada** | [o que deveria estar em vigor] |
| **Sugestão de Fix** | [exemplo de código ou configuração concreta] |
```

IMPORTANT: Never include actual secret values in findings. Reference file:line only.
Use plain PT-BR language — the reader may be a vibe coder, not a security specialist.

## Kill-Chain Section (for Crítico and Alto findings)

After each Crítico or Alto finding, include the kill-chain analysis results from kill-chain.md:

```markdown
**Análise Kill-Chain:**
- Camadas encontradas: [lista]
- Teste de isolamento: [resultado por camada]
- Veredicto: [🪨 Protegido / 🪵 Ponto-único-de-falha / 💨 Sem-defesa]
```

## Summary Table

After all findings, include:

```markdown
## Resumo

| Severidade | Quantidade |
|------------|-----------|
| 🔴 Crítico | [N] |
| 🟠 Alto | [N] |
| 🟡 Médio | [N] |
| 🟢 Baixo | [N] |
| **Total** | **[N]** |

## Próximos Passos

1. [Fix mais urgente — título + arquivo]
2. [Segundo mais urgente]
3. [Terceiro mais urgente]
```

## Empty Report

When no vector modules are loaded or no findings are detected:

```markdown
# 🏠 Relatório de Auditoria de Segurança — Rock House

**Projeto:** [nome]
**Data:** [YYYY-MM-DD]
**Stack detectada:** [stack]

## Status

[Se nenhum módulo carregado:]
Nenhum módulo de vetor está disponível ainda. Os módulos serão adicionados nas próximas fases do Rock House.

[Se nenhuma vulnerabilidade encontrada:]
Nenhuma vulnerabilidade foi encontrada com os módulos de vetor disponíveis. Isso não garante que o projeto está livre de vulnerabilidades — apenas que os vetores testados não encontraram problemas.

**Avaliação:** A ser determinada quando módulos estiverem disponíveis.
```

## Score Calculation

The overall score is 0-10, calculated as:
- Start at 10 (perfect project)
- Each Crítico finding: -2 points
- Each Alto finding: -1 point
- Each Médio finding: -0.5 points
- Each Baixo finding: -0.25 points
- Bonus: +1 for each critical risk with 3+ independent defense layers (fortaleza)
- Minimum score: 0

Score to metaphor mapping:
- 0-3: 🏠💨 Casa de palha — o lobo derruba com um sopro
- 4-6: 🏠🪵 Casa de madeira — aguenta um pouco, mas cai
- 7-8: 🏠🪨 Casa de pedra — o lobo não derruba
- 9-10: 🏠🪨🔒 Fortaleza — nem com dinamite
