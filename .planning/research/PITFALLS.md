# Pitfalls Research — Rock House

## Critical Pitfalls

### 1. False Positive Overload (crying wolf)
**Warning signs:** User starts ignoring reports because too many findings are wrong
**Prevention:** Start conservative — only flag what you're SURE about. Better to miss a low-severity issue than false-alarm on everything.
**Phase:** All phases — calibrate severity carefully in vectors/

### 2. Token Bloat
**Warning signs:** Skill takes 30+ seconds to load, Claude runs out of context
**Prevention:** Progressive disclosure is non-negotiable. Never load all vectors/stacks at once. SKILL.md stays under 150 lines.
**Phase:** Phase 1 (SKILL.md) — get this right from the start

### 3. Security Theater
**Warning signs:** Checks that "feel secure" but don't actually protect (e.g., checking if HTTPS exists without verifying it's enforced)
**Prevention:** Every check must answer: "If this passes, is the user ACTUALLY protected?" Apply Kerckhoffs principle to the skill itself.
**Phase:** All vector modules — each check needs to be meaningful

### 4. Checklist Fatigue
**Warning signs:** 50+ items in checklist, user starts clicking "skip all"
**Prevention:** Max 30 items in checklist mode. Group by risk, show only relevant items for detected stack. Highlight critical-only mode.
**Phase:** modes/checklist.md

### 5. Platform-Specific Script Failures
**Warning signs:** Scripts work on Windows but fail on Mac/Linux or vice versa
**Prevention:** Test both .ps1 and .sh versions. Keep scripts simple — no complex logic, just regex and CLI calls. Scripts are OPTIONAL augmentation, not core.
**Phase:** scripts/ phase

### 6. Maintenance Burden (OWASP rot)
**Warning signs:** 6 months later, new CVEs exist but skill still checks old ones
**Prevention:** Version the vector modules. Add a "last updated" header. Design so updates are one-file changes, not cascading rewrites.
**Phase:** All — design for update-ability from day 1

### 7. Over-Engineering v1
**Warning signs:** Spending weeks on architecture before shipping anything useful
**Prevention:** Ship SKILL.md + audit mode + 2 vectors first. Get real feedback. Iterate.
**Phase:** Phase 1 — resist the urge to build everything

### 8. Reporting for Experts (not beginners)
**Warning signs:** Report says "IDOR vulnerability in /api/users/:id" and vibe coder has no idea what to do
**Prevention:** Every finding needs: what's wrong (simple language), why it matters (impact), how to fix (code example). PT-BR.
**Phase:** Reporting/score system

## Prevention Strategies Summary

| Pitfall | Strategy | Metric |
|---------|----------|--------|
| False positives | Conservative severity, validate assumptions | <10% false positive rate |
| Token bloat | Progressive disclosure, stack filtering | <15K tokens per invocation |
| Security theater | Each check must be meaningful per Kerckhoffs | Every check answers "actually protected?" |
| Checklist fatigue | Max 30 items, risk-grouped, stack-filtered | User completes checklist in <5 minutes |
| Script failures | Dual platform, simple logic, scripts optional | Works on Win + Linux without errors |
| Maintenance | Versioned modules, one-file updates | Update takes <30 minutes |
| Over-engineering | Ship early, iterate with feedback | v1 ships in ≤4 sessions |
| Expert reporting | Simple language, impact, code fix, PT-BR | Vibe coder understands without Googling |
