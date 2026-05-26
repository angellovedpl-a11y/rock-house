# Features Research — Rock House

## Table Stakes (must-have or users leave)

| Feature | Why essential |
|---------|--------------|
| Code audit against OWASP Top 10 | Bare minimum for a security tool |
| Secret detection | #1 vibe coding mistake |
| Dependency vulnerability check | Low-hanging fruit, high impact |
| Clear severity levels | User needs to know what to fix first |
| Actionable fix suggestions | "You have a problem" without "here's the fix" is useless |
| Multi-stack support | Vibe coders use Next.js, Supabase, Flask interchangeably |
| Pre-deploy checklist | The "gate" before going live |

## Differentiators (competitive advantage)

| Feature | Why it stands out |
|---------|-------------------|
| Kill-chain analysis (independent layers) | No other tool does this — tests if defenses work ALONE |
| Gamified score (palha→pedra→fortaleza) | Makes security tangible and motivating |
| PT-BR reports | Brazilian vibe coder market is underserved |
| Preventive mode (before coding) | Most tools are reactive — this is proactive |
| Vibe-coding-specific vectors | NEXT_PUBLIC_ leaks, RLS bypass, mass assignment — what AI generates wrong |
| Progressive disclosure | Doesn't overwhelm with everything at once |
| Zero dependencies | Works immediately, no setup friction |

## Anti-features (things NOT to build)

| What | Why not |
|------|---------|
| Real-time monitoring | That's a WAF/SIEM, not a skill |
| Auto-fix code | Too risky — security fixes need human review |
| CI/CD integration | Phase 2/3 (plugin/SaaS), not now |
| Binary/mobile scanning | Out of scope — focus on web apps |
| Network scanning | Requires runtime access to deployed app |
| Custom rule editor | Complexity explosion, do later |

## Complexity Notes

- **Lowest complexity:** Checklist mode (static markdown, just checks yes/no)
- **Medium complexity:** Audit mode (needs to read code + apply vector rules)
- **Highest complexity:** Preventive mode (needs to understand feature type + generate defense tables)
- **Script complexity:** Low (regex patterns, CLI commands)
