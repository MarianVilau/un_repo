# Evidence for Session 1

Each file below backs one row of `RISK-REGISTER.md`. A row moves from `Open` to `Implemented` when its file exists here.

| File | How to produce it | Risk |
|---|---|---|
| `s1-gitleaks-blocked.png` | On a branch: `printf 'GITHUB_TOKEN=ghp_%s\n' "$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)" > leak.txt && git add leak.txt && git commit -m test`. Screenshot the refusal, then `git rm -f leak.txt`. | R-02 |
| `s1-direct-push-refused.png` | `git switch main && git commit --allow-empty -m test` (hook refuses). With the ruleset active also try `git push origin main`. | R-01 |
| `s1-force-push-refused.png` | `git push --force origin main` rejected by the ruleset. On Free: the `main-only-via-pr` run that fails on a commit with no PR. | R-03 |
| `s1-token-scope.png` | Settings, Developer settings, fine-grained token: one repository, Contents and Pull requests, 7-day expiry. Hide the token value. | R-04 |
| `s1-pr-blocked.png` | A pull request opened from a Claude Code or Gemini CLI session with a failing check, merge button disabled. | R-01 |

## Session 2

| File | How to produce it | Risk |
|---|---|---|
| `s2-memory-persists.png` | Correct the assistant once ("never hardcode ports"), show the new file in `.claude/memory/` and the line in `MEMORY.md`, open a new session and show the rule applied. | R-05 |
| `s2-hook-blocks-force-push.png` | Ask the assistant to run `git push --force origin HEAD`. Screenshot the `R-03` refusal from the hook. | R-03 |
| `s2-poisoning-blocked.png` | Steps in `docs/memory-poisoning-note.md`. | R-05 |
| `s2-guard-tests.png` | `pytest -q tests/test_guard_hook.py` passing. | R-05 |

## Session 3

| File | How to produce it | Risk |
|---|---|---|
| `s3-health-up1.txt` | `make up && make health > docs/evidence/s3-health-up1.txt` | R-08 |
| `s3-health-up2.txt` | `make down && make up && make health > docs/evidence/s3-health-up2.txt` (reproducible from zero) | R-08 |
| `s3-git-show-ciphertext.txt` | `git show HEAD:secrets/opensearch.enc.yaml > docs/evidence/s3-git-show-ciphertext.txt` (ciphertext only) | R-02 |
| `s3-cert-chain.txt` | `openssl s_client` and `curl --cacert` against `https://frontdoor.lab`: issuer, TLS 1.3, verify code 0, HTTP 302 from Dashboards. | R-08 |
| `s3-cert-chain.png` | Browser padlock on `https://frontdoor.lab`, certificate valid, Dashboards login behind it. The lab root was removed from the OS store afterwards. | R-08 |

## Session 4

| File | How to produce it | Risk |
|---|---|---|
| `s4-ci-green.png` | The `ci` run on the pull request: all jobs green, `ci-gate` included. | R-07, R-06 |
| `s4-pr-blocked-by-ci.png` | A pull request with a deliberate failure (for example a tag-pinned action), merge button disabled by the required `ci-gate` check. Close it afterwards. | R-01 |
| `s4-actions-settings.png` | Settings, Actions, General: SHA pinning required, workflow permissions read only, approval for outside contributors. | R-06 |
| `s4-release-verify.txt` | Output of the `cosign verify-blob` commands in `docs/ci-runbook.md`, run on the downloaded release files. | R-06 |

## Session 5

| File | How to produce it | Risk |
|---|---|---|
| `s5-sigma-query.txt` | `make sigma-query \| tee docs/evidence/s5-sigma-query.txt` | R-07 |
| `s5-dashboards-hit.png` | After `make load-samples`: Discover on `eve-lab*`, paste the SQL injection query, one document matches. See `docs/detection-runbook.md`. | R-07 |
| `s5-ci-green.png` | The `ci` run on the S5 pull request, `pytest` and `ci-gate` green. | R-07 |
