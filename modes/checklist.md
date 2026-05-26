# Checklist Mode

Pre-deploy gate that validates defense-in-depth across all relevant risks before shipping.

## What This Mode Does

1. Presents items organized by risk category (not by technology)
2. Each risk requires at least 2 independent defense layers to pass
3. Filters items to max ~30 relevant to the detected stack
4. Marks each item as pass / fail / warning
5. Generates a final summary report with overall readiness assessment

## When Loaded

Expects from SKILL.md:
- Detected stack(s) for filtering relevant checklist items
- User context confirming pre-deploy intent

## Status

Full implementation in Phase 7 (Checklist Mode).
