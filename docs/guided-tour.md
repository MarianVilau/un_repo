# Guided tour

A reading order for someone who clones the repository and wants to check each claim. Each row says what to open, what it shows and which risk it covers. Nothing here needs a running stack except the rows marked "live".

| Order | Open | What it shows | Risk |
|---|---|---|---|
| 1 | `RISK-REGISTER.md`, rows R-01, R-05, R-09 | Ten risks, each with a control, a score and an evidence cell | all |
| 2 | Settings, Rules, `main-protection`; `docs/evidence/s1-direct-push-refused.png` | A push to `main` is refused by the ruleset. The hook refuses it as well | R-01, R-03 |
| 3 | A recent pull request, for example #28: checks `pr-cites-risk-id` and `ci-gate` | A pull request must cite a risk and pass CI. The agent review comment is advice, not a gate | R-01, R-06 |
| 4 | `.claude/hooks/guard.py`; run `pytest tests/test_guard_hook.py -q` | Prose rules can be argued with. This one is code | R-05 |
| 5 | `docs/evidence/s2-poisoning-blocked.png` | A poisoned memory file is shown to the guard: force push blocked, memory write needs confirmation | R-05 |
| 6 | `docs/evidence/s6-enrichment-outcome.txt` | Same alert: no rule before enrichment, one rule after | R-09 |
| 7 | `docs/evidence/s6-dashboards-misp-hit.png` | The listed address is tagged `threat.indicator.matched` in OpenSearch | R-09 |
| 8 | `docs/evidence/s7-alert-firing.png`, `s7-grafana-alert.png` | Stopping a container fires `LabServiceDown` | R-10 |
| 9 | `docs/evidence/s6-shodan-exposure.txt` | The exposure check ran through InternetDB (keyless). An empty result does not prove the address is clean | R-10 |
| 10 | `bash scripts/check.sh` | One command re-runs lint, secret scan and tests | all |

Live (needs `make up` and a running MISP): the Discover query `threat.indicator.matched:true` in OpenSearch Dashboards, and `docker compose stop opensearch-dashboards` followed by the Prometheus Alerts page.

What is not proven is listed in `docs/project-document.md`, under open items, and in the register rows that still say `Open`.
