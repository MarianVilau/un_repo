# Demo script (about 6 minutes)

Record the screen with the terminal and a browser side by side. Say what each step proves. Stop and cut if a step fails; do not retry on camera.

| Min | Show | Say | Proves |
|---|---|---|---|
| 0:00 | `RISK-REGISTER.md`, rows R-01, R-05, R-09 | Ten risks, each with a control and an evidence file | Governed risk project |
| 0:45 | Ruleset in Settings, Rules; `git push origin main` refused | The agent cannot push to main, the ruleset and the hook both say no | R-01, R-03 |
| 1:30 | Open PR #19: `pr-cites-risk-id` and `ci-gate` | A PR must cite a risk and pass CI. The agent review comment is advice, not a gate | R-01, R-06, agent review |
| 2:30 | `.claude/hooks/guard.py`, run `pytest tests/test_guard_hook.py -q` | Prose rules can be argued with. This one is code | R-05, AI configuration |
| 3:15 | `cat docs/evidence/s6-enrichment-outcome.txt` | Same alert, no rule before enrichment, one rule after | R-09, enrichment |
| 4:00 | MISP event, then Discover with `threat.indicator.matched:true` | The listed address is tagged in OpenSearch | R-09 |
| 4:45 | `docker compose stop opensearch-dashboards`, Prometheus Alerts, Grafana Alerting | Stopping a container fires `LabServiceDown` | R-10 |
| 5:30 | `make exposure-check` output | Shodan sees only the expected ports | R-10 |
| 5:50 | `pytest -q` | One command re-checks the rules | all |

Before recording: stack up, MISP running with one listed address, `make load-samples` done, `ci-gate` green on the PR.
