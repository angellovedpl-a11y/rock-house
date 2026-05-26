# Architecture Research — Rock House

## Component Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ SKILL.md (Entry Point — ~150 lines)                         │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ • Detect context (stack, trigger, mode)                 │ │
│ │ • Route to appropriate mode                             │ │
│ │ • Define gatilhos (auto-activation rules)               │ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ MODES (what to do)                                          │
│ ┌───────────┐ ┌───────────┐ ┌───────────┐                  │
│ │  audit    │ │ checklist │ │preventive │                  │
│ │ (scan)    │ │ (gate)    │ │ (guide)   │                  │
│ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘                  │
├───────┼──────────────┼──────────────┼───────────────────────┤
│ VECTORS (what to check)             │                       │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│ │injection │ │auth-     │ │secrets-  │ │upload-   │ ...    │
│ │          │ │access    │ │exposure  │ │network   │        │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
├─────────────────────────────────────────────────────────────┤
│ STACKS (how to check — stack-specific rules)                │
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐              │
│ │ html │ │nextjs│ │supa- │ │flask │ │infra │              │
│ │      │ │      │ │base  │ │      │ │      │              │
│ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘              │
├─────────────────────────────────────────────────────────────┤
│ REFERENCES (knowledge base — loaded when needed)            │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│ │owasp-10  │ │owasp-api │ │ defense  │ │operation │        │
│ │          │ │          │ │ depth    │ │ guide    │        │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
├─────────────────────────────────────────────────────────────┤
│ SCRIPTS (automated checks — optional, augment analysis)     │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│ │scan-secrets  │ │audit-deps    │ │check-headers │         │
│ │(.ps1 + .sh)  │ │(.ps1 + .sh)  │ │(.ps1 + .sh)  │         │
│ └──────────────┘ └──────────────┘ └──────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Input → Analysis → Output

1. TRIGGER (user invokes or context detected)
       ↓
2. SKILL.md detects stack (package.json? requirements.txt? .html?)
       ↓
3. SKILL.md selects MODE (audit/checklist/preventive)
       ↓
4. MODE loads relevant VECTORS (based on stack)
       ↓
5. MODE loads relevant STACK rules (stack-specific checks)
       ↓
6. Claude reads project code + applies vector/stack rules
       ↓
7. Scripts run (scan-secrets, audit-deps, check-headers)
       ↓
8. KILL-CHAIN ANALYSIS (test layer independence)
       ↓
9. OUTPUT: Report with score, severity, fixes
```

## Token Management

| Strategy | How |
|----------|-----|
| Progressive disclosure | SKILL.md is tiny; sub-files load on demand |
| Stack filtering | Only load vectors/stacks relevant to detected stack |
| Vector filtering | Only load vectors that apply (no upload checks if no upload feature) |
| Reference on-demand | OWASP refs loaded only when a specific vulnerability is found |
| Report is output | Report goes to user, not consumed by skill |

**Budget estimate per invocation:**
- SKILL.md: ~2K tokens
- Mode file: ~3K tokens
- 2-3 vector files: ~4K tokens
- 1-2 stack files: ~3K tokens
- Total: ~12K tokens loaded (well within budget)

## Suggested Build Order

1. **SKILL.md** — entry point, routing, stack detection
2. **modes/audit.md** — most complex, most value
3. **vectors/** — one at a time, starting with secrets (easiest to validate)
4. **stacks/nextjs.md** — most used by target audience
5. **scripts/scan-secrets** — immediate value
6. **modes/checklist.md** — simpler (just yes/no checks)
7. **modes/preventive.md** — needs vectors done first
8. **stacks/** — remaining stacks
9. **references/** — knowledge base
10. **scripts/** — remaining scripts
11. **README.md** — for GitHub
12. **Score system** — gamification layer
