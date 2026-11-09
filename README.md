# un_repo: governed security platform for the lab network

ULBS Cybersecurity Master, Module 4: Risk and Damage Management, AI-Driven Security Engineering.

The project turns an existing pfSense, Snort and Juice Shop home lab into a small detection platform: alerts are normalised, enriched with MISP and Shodan data, stored in OpenSearch and monitored. Every control in the repository answers a row of the risk register.

## Start here

- `RISK-REGISTER.md` (text) and `RISK-REGISTER.xlsx` (scored): ten risks in the three registers, written before any code.
- `CONTRIBUTING.md`: workflow, Git CLI risks and the control for each.
- `SECURITY.md`: reporting and scope.
- `docs/evidence/`: proof for each control.

## Status by session

| Session | Content | State |
|---|---|---|
| 1 | Risk register, governed repository | in progress |
| 2 | CLAUDE.md, memory, skills, guard hook | in review |
| 3 | Compose, SOPS/age, lab PKI | in review, needs local run |
| 4 | CI/CD, SBOM, signing | planned |
| 5 | Sigma rules and tests | planned |
| 6 | MISP and Shodan enrichment | planned |
| 7 | Observability, automated review | planned |

## Run the stack

See `docs/lab3-runbook.md`. Short form: `scripts/init-secrets.sh`, `make pin-digests`, `make up`, `make health`.

## GitHub plan route

Evidence-based governance on GitHub Free (route 4 of the module syllabus), unless the repository moves to the ULBS organisation. See `CONTRIBUTING.md`.
