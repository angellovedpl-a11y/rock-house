# Security Policy

## Supported Versions

This repository is maintained on the `master` branch and the latest tagged release.

## Reporting a Vulnerability

Do not open a public issue for a suspected security problem.

Preferred report path:

1. Use GitHub's private vulnerability reporting for this repository if it is available.
2. If private reporting is not available, contact the repository maintainer through the GitHub profile linked in the repository metadata.

Include:

- a short summary of the issue
- affected file paths or commands
- reproduction steps
- impact and severity
- any proof-of-concept data needed to verify the issue

Please avoid posting secrets, access tokens, private URLs, or customer data in the report unless they are required to reproduce the problem. Redact sensitive values where possible.

## Response Expectations

We aim to:

- acknowledge reports within 2 business days
- provide an initial triage within 5 business days
- keep the reporter updated until the issue is resolved or fully understood

Critical issues that affect confidentiality, integrity, or release safety will be prioritized first.

## Scope

The policy covers:

- the Rock House skill files
- the dependency-free CI scanner in `scripts/`
- the GitHub Action entry point in `action.yml`
- documentation that ships in this repository

The following are out of scope unless they introduce an unexpected regression:

- intentional vulnerabilities in `examples/vulnerable-next-supabase/`
- test fixtures and mock data
- issues already documented in the README or release notes

## Safe Disclosure

If you are unsure whether something is a real vulnerability, report it anyway with the details you have. We will triage it privately and confirm the next step.
