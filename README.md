# un_repo: governed security platform for the lab network

ULBS Cybersecurity Master, Module 4: Risk and Damage Management, AI-Driven Security Engineering.

The project turns an existing pfSense, Snort and Juice Shop home lab into a small detection platform: alerts are normalised, enriched with MISP and Shodan data, stored in OpenSearch and monitored. Every control in the repository answers a row of the risk register.

## Evidence (look here first)

Each control has a proof file in [`docs/evidence/`](docs/evidence/). The [index](docs/evidence/README.md) says what every file shows and how it was produced. A risk moves to `Implemented` in `RISK-REGISTER.md` only when its files exist.

| Risk | Control | Proof |
|---|---|---|
| R-01 | main protected, PR and `ci-gate` required | [`s1-direct-push-refused.png`](docs/evidence/s1-direct-push-refused.png), [`s1-pr-blocked.png`](docs/evidence/s1-pr-blocked.png), [`s4-pr-blocked-by-ci.png`](docs/evidence/s4-pr-blocked-by-ci.png) |
| R-02 | secret scan, SOPS/age ciphertext | [`s1-gitleaks-blocked.png`](docs/evidence/s1-gitleaks-blocked.png), [`s3-git-show-ciphertext.txt`](docs/evidence/s3-git-show-ciphertext.txt) |
| R-03 | no force push | [`s1-force-push-refused.png`](docs/evidence/s1-force-push-refused.png), [`s2-hook-blocks-force-push.png`](docs/evidence/s2-hook-blocks-force-push.png) |
| R-04 | fine-grained token, one repository, 30-day expiry | [`s1-token-scope.png`](docs/evidence/s1-token-scope.png) |
| R-05 | guard hook for the AI configuration | [`s2-hook-loaded.png`](docs/evidence/s2-hook-loaded.png), [`s2-guard-tests.png`](docs/evidence/s2-guard-tests.png), [`s2-poisoning-blocked.png`](docs/evidence/s2-poisoning-blocked.png) |
| R-06 | pinned actions, signed release | [`s4-ci-green.png`](docs/evidence/s4-ci-green.png), [`s4-actions-settings.png`](docs/evidence/s4-actions-settings.png), [`s4-release-verify.txt`](docs/evidence/s4-release-verify.txt) |
| R-07 | Sigma rules, pipeline tests, parse failures kept | [`s5-sigma-query.txt`](docs/evidence/s5-sigma-query.txt), [`s5-dashboards-hit.png`](docs/evidence/s5-dashboards-hit.png), [`s5-ci-green.png`](docs/evidence/s5-ci-green.png) |
| R-08 | TLS front door, pinned images | [`s3-health-up1.txt`](docs/evidence/s3-health-up1.txt), [`s3-health-up2.txt`](docs/evidence/s3-health-up2.txt), [`s3-cert-chain.txt`](docs/evidence/s3-cert-chain.txt) |

Partial proof, row stays `Open`: R-09 (the Dashboards hit uses the seed dictionary, a live MISP capture is still to do) and R-10 (the Shodan output exists, taken from the free InternetDB service; the alert on a container stop exists; the scheduled run and the alert on a new port or banner are not built).

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
| 3 | Compose, SOPS/age, lab PKI | merged, evidence added |
| 4 | CI/CD, SBOM, signing | merged, release `v0.1.0` signed, evidence in this branch |
| 5 | Sigma rules and tests | in review (#18) |
| 6 | MISP and Shodan enrichment | in review (#19) |
| 7 | Observability, automated review, project document | in review (#20) |

## Run the stack

See `docs/lab3-runbook.md`. Short form: `scripts/init-secrets.sh`, `make pin-digests`, `make up`, `make health`.

## GitHub plan route

The owner's account has GitHub Pro (student plan), so the ruleset `main-protection` is enforced by GitHub on this private repository. The `no-commit-to-branch` hook and the `main-only-via-pr` job stay as the second and third layers, and are the fallback on a plan without rulesets. See `CONTRIBUTING.md`.
