# Stack Research — Rock House

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

1. **No external dependencies** — the skill must work on any machine with Claude Code installed
2. **Scripts are helpers, not requirements** — the skill's core analysis is done by Claude reading code, scripts augment with automated checks
3. **Dual scripts** (.ps1 + .sh) — Angelo uses Windows, target audience may use Mac/Linux
4. **Claude IS the analysis engine** — the markdown modules tell Claude what to look for, Claude reads the code and applies the rules

## Confidence Levels

- Skill format: ✅ High (this is how Claude Code skills work)
- No external deps: ✅ High (core constraint from PROJECT.md)
- Regex-based secret scan: 🟡 Medium (gitleaks patterns are battle-tested but regex has limits)
- Script duality: ✅ High (necessary for cross-platform)
