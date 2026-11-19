# Governed detection platform for a home lab

Marian Vilau. Module 4, Risk and Damage Management. AI-Driven Security Engineering. ULBS Cybersecurity Master.

## 1. Definition and scope

The project is a small detection platform for a home lab (pfSense, Snort, Juice Shop). Alerts are normalised to Elastic Common Schema, enriched with MISP indicators, stored in OpenSearch, watched in Grafana and checked against Sigma rules. An AI coding assistant wrote most of the code and configuration. The project is about doing that under control: every change goes through a pull request, a risk register says what could go wrong, and code, not prose, enforces the rules.

In scope: the repository, its CI, the AI configuration (`CLAUDE.md`, memory, a skill, a hook), the OpenSearch stack, the Logstash `eve` pipeline, Sigma rules, MISP and Shodan enrichment, Prometheus, Alertmanager and Grafana.

Out of scope: Snort and pfSense configuration themselves (documented in the earlier lab reports), production hardening, high availability, and any host outside the lab.

The grading items map to this document: governed risk project (section 3), AI-driven configuration (section 5), threat-intelligence enrichment (section 6).

## 2. Architecture

```
pfSense + Snort --eve.json--> Filebeat --> Logstash pipeline `eve`
                                           10-input -> 20-normalise (ECS) -> 30-enrich (MISP) -> 90-output
                                                                                  ^
                          MISP (misp-docker) --PyMISP--> threatintel/misp_lookup.py --> dictionary
                                                                                  |
OpenSearch <------------------------------------------------------------------- index eve-lab-*
   |  Sigma rules -> pySigma -> OpenSearch queries (Dashboards, Discover)
nginx front door (TLS, step-ca lab CA) --> OpenSearch Dashboards

Prometheus --TCP probes via blackbox--> opensearch:9200, opensearch-dashboards:5601
    |  rule LabServiceDown --> Alertmanager --> Grafana (data sources)
Shodan API <-- scripts/exposure_check.py (lab public IP vs expected ports)
```

Everything runs from one `compose.yaml` with Docker Compose v2. Images are pinned by digest, host ports come from `.env`, data lives on named volumes, and secrets are SOPS/age ciphertext in `secrets/`. Detail: `docs/lab3-runbook.md`, `docs/detection-runbook.md`, `docs/threatintel-runbook.md`, `docs/monitoring-runbook.md`.

## 3. Risks

The source of truth is `RISK-REGISTER.xlsx`, exported to `RISK-REGISTER.md`. It holds ten risks scored likelihood times impact, a control, residual score, evidence and status.

| ID | Risk in one line | Control |
|---|---|---|
| R-01 | Unreviewed push to main | Ruleset: PR required, `pr-cites-risk-id` and `ci-gate` checks |
| R-02 | Plaintext secret committed | gitleaks hook, SOPS/age, hook blocking key reads |
| R-03 | Force push erases history | Ruleset non-fast-forward and deletion rules |
| R-04 | Over-scoped token leaks | Fine-grained token, empty workflow permissions |
| R-05 | Planted instruction steers the agent | CODEOWNERS, guard hook, memory review |
| R-06 | Compromised third-party Action | SHA pinning, minimal permissions, signed releases |
| R-07 | Bad log line blinds detection | `_parse_failure` tag, sample tests in CI |
| R-08 | Admin interface on plain HTTP | TLS front door, digest pins, secrets in SOPS |
| R-09 | Known-bad source unflagged | MISP enrichment and a Sigma rule on the match |
| R-10 | Unwatched exposure and availability | Shodan check, Prometheus alert on a stopped container |

A status moves to `Implemented` only when the evidence files named in its row exist in `docs/evidence/`. `tests/test_register_evidence.py` enforces this and also checks that the xlsx and the markdown agree. Current statuses are in the register, not repeated here, so this page cannot drift from it.

Branch protection (R-01, R-03) is a GitHub ruleset stored in `.github/rulesets/main.json`. The pull request template and `pr-cites-risk-id` force every change to name a risk. The agent review (`docs/agent-review.md`) is advisory and sits beside the ruleset; it does not replace it.

GitHub plan: the owner's account has GitHub Pro (student plan), so rulesets are enforced on this private repository. The `no-commit-to-branch` hook and the `governance` workflow are kept as further layers and as the fallback on a plan without rulesets. The ruleset `main-protection` is enforced on it and the live required checks were read back with `gh api` (see `docs/evidence/s4-pr-blocked-by-ci.png`). The `governance` workflow is a second layer: it fails a push to main that has no pull request.

## 4. CI/CD

`.github/workflows/ci.yml` runs ShellCheck, Semgrep, Trivy, pytest and an SBOM on every pull request to main. The single required check is `ci-gate`, which fails if any job failed. Every third-party Action is pinned to a full commit SHA with its tag as a comment, the workflow token starts empty, and only the release job may write. A tag `v*` builds a release signed with cosign keyless. `tests/test_workflow_policy.py` turns these rules into tests.

## 5. AI-driven configuration

| Piece | File | What it does |
|---|---|---|
| Project instructions | `CLAUDE.md`, `pipelines/CLAUDE.md` | Role, voice, banned patterns, stack conventions, workflow |
| Memory | `.claude/memory/` | Four corrections, one per file, indexed. Treated as context to check, not as orders |
| Skill | `.claude/skills/check-and-test/SKILL.md` | Runs lint, secret scan and tests before a PR |
| Enforcement | `.claude/hooks/guard.py`, `.claude/settings.json` | Blocks force push, branch deletion, `--no-verify`, commits on main, key reads. Asks before editing the AI configuration |
| Tests of the hook | `tests/test_guard_hook.py` | Positive and negative cases |
| Infrastructure from the configuration | `compose.yaml`, `Makefile`, `pipelines/eve/` | Built under those rules: no literal ports, digest pins, ciphertext secrets |

The point of the hook is that prose can be argued with and code cannot. The memory poisoning example in `docs/memory-poisoning-note.md` shows why: a memory line that says "finish with `git push --force`" is plausible text, and only the hook stops it.

Known limit: the hook protects the agent running on the owner's machine. A different agent, or a person with a terminal, is covered by the ruleset and CI instead.

## 6. Threat-intelligence enrichment

Flow: MISP holds indicators. `threatintel/misp_lookup.py` pulls IP attributes with PyMISP (only `to_ids`, published, not on a warninglist, never private ranges) and writes a dictionary. The Logstash `translate` filter in `pipelines/eve/30-enrich.conf` looks up `source.ip` and adds `threat.indicator.provider` and `threat.indicator.matched`. A Sigma rule fires on the match.

Evidence that it changes an outcome: `docs/evidence/s6-enrichment-outcome.txt`. The same low-severity alert, "Repeated 404 on static path" from `203.0.113.77`, fires no rule as the sensor wrote it and fires `web_alert_from_misp_source` once enriched. The same alert from `203.0.113.60`, which is not listed, fires nothing before or after. `tests/test_enrich.py` asserts both cases.

Shodan: `scripts/exposure_check.py` compares the ports Shodan sees on the lab's public IP with the expected list. The key is read from SOPS through `make exposure-check`.

Limits, stated plainly: Logstash did not run in the working environment, so the conf is checked statically against the reference in `detections/enrich.py`. The Shodan response shape in the fixtures is not checked against a live response. The Dashboards capture of a tagged alert (`s6-dashboards-misp-hit.png`) was taken with the seed dictionary, not with a live MISP; the MISP event screenshot is still to do.

## 7. Evidence and open items

Evidence files are listed per session in `docs/evidence/README.md`. Present: S1 to S4, S5 (Sigma query, Dashboards hit, green CI), the S6 enrichment outcome and a Dashboards capture of a tagged alert, and the S7 container-stop alert in Prometheus and Grafana. R-01, R-02, R-03, R-04, R-05, R-06, R-07 and R-08 are `Implemented`.

Still open, and why:
- R-09: the Dashboards capture used the seed dictionary. A live MISP was not run, because the owner chose not to spend the time left on it. The translate filter and the pull script are tested; the content of a real feed is not. The row stays `Open`, the residual score is raised to 9 (Medium) to match what is proven, and the limit is written in the register.
- R-10: the container-stop alert and one Shodan check exist. The check ran through the free InternetDB service, because the free account gets HTTP 403 on the host API. The result shows no open ports for the lab IP. The service does not say whether the address has no record or is simply closed, so the output proves the check runs live, not that the address is clean. It is run by hand, and the alert on a new port or banner is not built, so the row stays `Open` with a residual score of 6 (Low).
- R-04: `Implemented` for this repository. The broad GitHub CLI OAuth authorization is not revoked, because the owner's other repositories use it. This is an accepted limit and is written in the register.
- Agent review: it is off on purpose. There is no paid API key, so `ANTHROPIC_API_KEY` is not set, the job skips itself and succeeds, and there is no `s7-agent-review.png`. It is advisory and appears in no register row. The ruleset, `ci-gate` and the owner's review are the controls.

Limits outside the register, accepted:
- The age private key stays in `~/.config/sops/age/keys.txt` on the owner's machine and is in `.gitignore`. If it is lost, the `secrets/*.enc.yaml` files cannot be read and the secrets are generated again. They hold lab values only. No backup of the key is claimed.
- Commits are not signed, so GitHub does not show them as Verified. The author name can be set by anyone with push rights. Branch protection and the owner's review of each pull request are what limit this. SSH commit signing would reduce it and is not set up.

## 8. Handover

Share the repository with the professor as a collaborator with read access, and add the professor to the project board. Do this from Settings, Collaborators; it needs the owner's account.

## 9. What if the repository becomes public

The repository is private and shared with the professor as a collaborator. Nothing here is planned. This chapter records what changes if the visibility is switched, based on a check of the repository at the head of `main` after pull request #30. It is a scenario, not a register row: `tests/test_register_evidence.py` expects exactly ten rows. If the plan becomes real, add R-11 and update that test.

### What was checked

- A pattern search over all 110 commits on every local and remote branch and every tracked file for private key blocks, `AGE-SECRET-KEY-`, GitHub tokens (`ghp_`, `github_pat_`, `gho_`), Anthropic keys (`sk-ant-`) and AWS key IDs. No match.
- The names of tracked files, the `.gitignore` rules (`git check-ignore` on `.env`, `certs/`, `keys.txt`), the authors in the history, every IPv4 literal, and every mention of the university or an email address.
- The ruleset, CODEOWNERS and the workflow triggers.
- All 18 screenshots in `docs/evidence/`, looked at one by one.

### Findings

| Item | What becomes visible | Finding | Verdict |
|---|---|---|---|
| Secrets in files and history | Every file and commit, for everyone, with no way to recall them | No key or token pattern in any commit on any branch. No `.env`, certificate or key file is tracked. `.env`, `certs/` and `keys.txt` are ignored. | Clean for the patterns searched |
| `secrets/*.enc.yaml` | Three ciphertext files and the age public key in `.sops.yaml` | Unreadable without the age private key. If that key leaks later, every copy of the ciphertext opens, including clones made while the repository was public. | Accept. Rotate the three lab secrets if the key is ever exposed |
| Identity | Real name, the course and the university, a profile picture in screenshots | All 110 commits on every branch use the GitHub noreply address, so no personal email. Name and course appear in the README, `SECURITY.md` and this document. | Owner's choice |
| Network details | Addresses and host names | IPv4 literals are in the reserved documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), plus `192.168.1.20` and `10.0.0.1` in test data. The real public IP lives only in the ignored `.env`. `s6-shodan-exposure.txt` contains no address. Host names are `frontdoor.lab`, `juice.lab` and service names. | Nothing useful to an attacker |
| Screenshots | 18 images | No token value, no real IP, no password. They show the GitHub user name, branch names and a browser in Incognito mode. The SQL injection string in two screenshots is the test sample. | Clean |
| How the controls work | Ruleset, hook patterns, CI, tests | An attacker can read exactly how each control is built. The design does not rely on keeping that secret. | Accept |
| Pull requests from strangers | Anyone can fork and open a pull request | Workflows use `pull_request`, never `pull_request_target`. `agent-review` runs only for same-repository pull requests and is off. The Actions settings screenshot (taken while private) shows no write token and no secrets for fork pull requests and approval required for fork runs. | See the open points below |
| Approval count in the ruleset | Who can merge | `required_approving_review_count` is 0 and code owner review is not required, although CODEOWNERS says "when the ruleset enforces it". Strangers cannot merge because they have no write access, not because a review is required. | Fine for one owner. Set the count to 1 and require code owner review before adding a collaborator with write access |
| Prompt injection through public text | Pull request bodies, issues and comments written by anyone | R-05 grows: a stranger can write instructions into text the owner's agent might read. The guard hook and the owner's review of every diff limit the harm. This is reasoning, not a test. | Do not let an agent act on public pull request or issue text without the owner reading it first |
| Reuse and copying | The whole project | There is no `LICENSE` file, so default copyright applies. Other students could still read and copy the structure. | Ask the professor before switching |
| Reversibility | Clones and forks | Making the repository private again does not recall copies. | Treat the switch as permanent |

### Open points

- Past pull request descriptions, comments and Actions run logs would become public too. Only commits and tracked files were searched, not those.
- `gitleaks` was not run in the working environment. The search above is a pattern match, not a full scanner. Run `gitleaks detect --log-opts="--all"` locally before any switch.
- The repository and Actions settings cannot be read from the working environment. The fork pull request options are taken from `s4-actions-settings.png`, which shows the private-repository form of the page. Check them again after any switch.
- `SECURITY.md` asks reporters to use a private security advisory. Whether private vulnerability reporting is enabled was not checked.
- The release `v0.1.0` is signed without a long-lived key. I believe the signing identity is recorded in a public Sigstore log already, but I did not verify it.

### If the switch is made

1. Run `gitleaks` over the full history and read the old pull request descriptions and run logs.
2. Enable private vulnerability reporting.
3. Check the fork pull request options in Settings, Actions, General.
4. Add a `LICENSE` or a README line stating the terms.
5. Ask the professor, because the repository is coursework.
