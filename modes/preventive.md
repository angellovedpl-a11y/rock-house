# Preventive Mode

Generates defense-in-depth planning tables BEFORE writing code for a new feature.

## What This Mode Does

1. User describes a feature type: auth, form, api, payment, upload, session, webhook, chatbot
2. Identifies applicable risks for that feature type
3. Generates a defense table showing at least 2 independent layers per risk
4. Code examples use the project's detected stack (not generic pseudo-code)
5. Each layer must hold on its own — independence is mandatory

## When Loaded

Expects from SKILL.md:
- Detected stack(s) for generating stack-specific code examples
- Feature type from user's description

## Status

Full implementation in Phase 8 (Preventive Mode).
