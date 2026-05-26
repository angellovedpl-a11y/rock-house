<!-- GSD:project-start source:PROJECT.md -->
## Project

**Rock House**

Skill global do Claude Code que aplica defesa em profundidade em todo projeto de código, usando a metáfora dos 3 porquinhos: construir casa de pedra que o lobo (atacante) não derruba. Voltada para vibe coders que usam IA pra gerar código e precisam garantir segurança antes de ir pra produção. Evolui de skill local → plugin npm → SaaS comercial.

**Core Value:** Todo projeto passa por auditoria de segurança com camadas independentes de defesa antes de ir pra produção — se uma camada cair, a próxima segura sozinha.

### Constraints

- **Stack:** Markdown + PowerShell/Bash scripts — sem dependências externas (a skill precisa funcionar em qualquer máquina com Claude Code)
- **Tamanho:** SKILL.md ≤150 linhas (disclosure progressivo — economizar tokens)
- **Compatibilidade:** Windows (PowerShell) + Linux/Mac (Bash) — scripts em ambos
- **Idioma código:** Inglês (compartilhável no GitHub)
- **Idioma relatórios:** Português BR (público inicial é brasileiro)
- **Tempo:** Angelo tem tempo limitado (trabalha na ferrovia) — fases curtas e práticas
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Recommended Stack
| Component | Choice | Rationale |
|-----------|--------|-----------|
| **Skill format** | Claude Code Skill (Markdown + YAML frontmatter) | Native format, no dependencies, progressive disclosure built-in |
| **Entry point** | `SKILL.md` (~150 lines) | Routes to modes, detects context, economizes tokens |
| **Sub-modules** | `.md` files in subdirectories | Loaded on-demand via skill's internal references |
| **Secret scanning** | `gitleaks` patterns (regex in script) | Best regex patterns, MIT license, no binary dependency |
| **Dependency audit** | `npm audit` / `pip audit` (native) | Zero install — comes with the package managers |
| **Header checking** | `curl -I` + regex parsing | Universal, no dependencies |
| **Script runtime** | PowerShell (.ps1) + Bash (.sh) | Windows + Linux/Mac coverage |
## Alternatives Considered
| Tool | Why NOT |
|------|---------|
| Semgrep | Requires install, too heavy for a skill |
| ESLint security plugins | Only JavaScript, needs config |
| SonarQube | Enterprise tool, overkill for vibe coders |
| Snyk CLI | Requires account/API key |
| OWASP ZAP | Runtime scanner, not static analysis skill |
## Key Decisions
## Confidence Levels
- Skill format: ✅ High (this is how Claude Code skills work)
- No external deps: ✅ High (core constraint from PROJECT.md)
- Regex-based secret scan: 🟡 Medium (gitleaks patterns are battle-tested but regex has limits)
- Script duality: ✅ High (necessary for cross-platform)
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
