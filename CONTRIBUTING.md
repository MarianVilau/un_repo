# Contributing

Every change, from a person or from an AI agent, arrives as a pull request that cites the risk it addresses.

## Setup once per clone

```bash
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

## Workflow

1. Create a branch: `git switch -c <session>/<topic>` (for example `lab3/iaas`).
2. Commit with a short message that names the risk: `feat: encrypt admin password with SOPS (R-02)`.
3. Push the branch and open a pull request. The description must contain at least one ID from `RISK-REGISTER.md`; the `pr-cites-risk-id` check fails otherwise.
4. Merge only when required checks are green. Delete the branch afterwards.

## Git CLI risks and their controls

Pushing from the command line, by hand or through an agent, carries four named risks.

| Risk | ID | Technical control | Where to see it |
|---|---|---|---|
| Secret leaked in a commit | R-02 | gitleaks pre-commit hook, SOPS/age for secrets | `.pre-commit-config.yaml`, `.gitleaks.toml` |
| Force push rewrites history | R-03 | `non_fast_forward` and `deletion` rules on main | `.github/rulesets/main.json` |
| Unreviewed code lands on main | R-01 | PR required, status checks required, `no-commit-to-branch` hook, `main-only-via-pr` workflow | ruleset, hook, `.github/workflows/governance.yml` |
| Over-scoped credential | R-04 | Fine-grained token limited to this repository, 30-day expiry, `permissions:` read by default in workflows | token settings screenshot, workflow files |

## Rules for agents

- An agent works on a branch and never on main.
- `--force`, `--no-verify` and edits to `.github/` or the AI configuration need explicit owner approval.
- Memory, skill and CLAUDE.md changes are reviewed line by line (R-05).

## Branch protection on a personal GitHub Free account

Rulesets on private repositories need a paid plan or the ULBS organisation. Without one, the evidence-based route applies: the `no-commit-to-branch` hook blocks local commits on main, and the `main-only-via-pr` job fails whenever a commit reaches main without a merged pull request. The ruleset in `.github/rulesets/main.json` sets `required_approving_review_count` to 0 because a single maintainer cannot approve their own pull request. Raise it to 1 and turn on `require_code_owner_review` when a second reviewer has access.
