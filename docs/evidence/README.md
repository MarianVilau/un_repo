# Evidence for Session 1

Each file below backs one row of `RISK-REGISTER.md`. A row moves from `Open` to `Implemented` when its file exists here.

| File | How to produce it | Risk |
|---|---|---|
| `s1-gitleaks-blocked.png` | On a branch: `printf 'GITHUB_TOKEN=ghp_%s\n' "$(head -c 300 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 36)" > leak.txt && git add leak.txt && git commit -m test`. Screenshot the refusal, then `git rm -f leak.txt`. | R-02 |
| `s1-direct-push-refused.png` | `git switch main && git commit --allow-empty -m test` (hook refuses). With the ruleset active also try `git push origin main`. | R-01 |
| `s1-force-push-refused.png` | `git push --force origin main` rejected by the ruleset. On Free: the `main-only-via-pr` run that fails on a commit with no PR. | R-03 |
| `s1-token-scope.png` | Settings, Developer settings, fine-grained token: one repository, Contents and Pull requests, 7-day expiry. Hide the token value. | R-04 |
| `s1-pr-blocked.png` | A pull request opened from a Claude Code or Gemini CLI session with a failing check, merge button disabled. | R-01 |
