---
name: check-and-test
description: Run lint, secret scan and tests in one command before opening a pull request. Use when asked to verify, check, test or prepare a PR.
---

# check-and-test

Runs the same checks the pipeline will run, so a pull request does not fail on something found locally in ten seconds.

## Steps

1. Run `bash scripts/check.sh` from the repository root.
2. Read the output. Fix the first failure and rerun; do not stack fixes.
3. If a hook or test fails on a file you did not change, say so instead of editing it.
4. When everything passes, list the risk IDs the change addresses (see `RISK-REGISTER.md`) and put them in the PR description.

## What the script runs

- `yamllint` on workflow and config files when installed
- `pre-commit run --all-files` (gitleaks, no-commit-to-branch, yaml and whitespace checks)
- `pytest -q` when a `tests/` folder exists

## Rules

- Never pass `--no-verify` or skip a hook to get a green result.
- A failing secret scan means rotate the secret, not rewrite the file to hide it.
