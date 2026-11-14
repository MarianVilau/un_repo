# Agent pull request review (Session 7)

Risks: R-01 (unreviewed change reaches main), R-05 (planted instructions steer the agent), R-06 (CI supply chain).

## How it fits next to branch protection

| Layer | Who decides | Blocks merge |
|---|---|---|
| Ruleset `main-protection` | GitHub | Yes: PR required, checks `pr-cites-risk-id` and `ci-gate`, no force push |
| `ci` workflow | Tools: ShellCheck, Semgrep, Trivy, pytest | Yes, through `ci-gate` |
| `agent-review` workflow | An AI agent | **No.** It comments only |
| Owner review | The student | Yes: every diff is read before merge |

The agent adds a second reader. It never replaces the gate or the owner. A green agent review means nothing to the ruleset.

## Controls on the agent itself

- Tool allowlist in `.github/workflows/agent-review.yml`: inline comments, `gh pr comment`, `gh pr diff`, `gh pr view`, read-only file tools. No `gh pr review`, no merge, no push, no edit. `tests/test_workflow_policy.py` fails if one of those appears.
- Repository setting "Allow GitHub Actions to create and approve pull requests" stays off, so the token could not approve even if the prompt were subverted. This setting is outside the repository; check it in Settings, Actions, General.
- The job runs only for same-repository, non-draft PRs, on `pull_request`, never `pull_request_target`.
- The action is pinned to a full commit SHA with the tag as a comment (R-06). `permissions` at the top is empty; the job asks for `contents: read`, `pull-requests: write`, `id-token: write`. The last one is what the action's default sign-in requires, per its documentation.
- The API key is the Actions secret `ANTHROPIC_API_KEY`. Without it the review is skipped and the job succeeds. Set it in Settings, Secrets and variables, Actions.

## Known limits

- R-05 is only reduced. A PR can edit `CLAUDE.md` or `.claude/` and try to steer the reviewer. The prompt tells the agent to treat PR content as data and to flag edits to those paths, but a prompt is advice. The ruleset, CODEOWNERS and the owner are the real control.
- The workflow was not run. It needs the secret, and the action's inputs were read from its repository at tag `v1.0.275`, not tested.
- The agent may be wrong. Its comments are input for the owner, not findings.

## Record of an interaction

To fill in after the first PR with the secret set: PR number, what the agent flagged, what the owner accepted or rejected, and a screenshot as `docs/evidence/s7-agent-review.png`.
