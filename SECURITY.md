# Security policy

This repository is a university lab project (ULBS Cybersecurity Master, Module 4). It is not a product and has no supported releases.

## Reporting a problem

Open a private security advisory on this repository (Security tab, "Report a vulnerability"). Do not open a public issue for a leaked credential or an exploitable flaw. A leaked secret is rotated first and reported second.

## Scope

- Controls described in `RISK-REGISTER.md`.
- Pipeline and workflow definitions under `.github/`.
- AI configuration files (`CLAUDE.md`, `.claude/`, `memory/`), which are treated as code.

Out of scope: the intentionally vulnerable Juice Shop container and any third-party service the lab only reads from.

## What happens to a leaked secret

1. Revoke or rotate it at the provider.
2. Remove it from the working tree and add the pattern to the review notes.
3. Rewriting history is a last resort and is done only by the owner, never by an agent. See R-03.
