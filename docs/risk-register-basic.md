# Basic risk register

A first-exercise register for any small repository. Likelihood and impact are scored 1 to 3; score = likelihood x impact (1-2 Low, 3-5 Medium, 6-9 High).

Two controls per risk: **prevent** (lower the likelihood) and **limit the damage** (lower the impact, make recovery quick). The score after assumes both are in place. The full table with owners and status is in `risk-register-basic.xlsx`; the main project register is `RISK-REGISTER.md`.

| ID | Asset | What can go wrong | L | I | Score | Prevent it | Limit the damage | Score after |
|---|---|---|---|---|---|---|---|---|
| B-01 | Secrets (API keys, passwords) | A secret is committed and pushed | 2 | 3 | 6 High | gitleaks pre-commit hook, .gitignore for .env, secrets in a secret store | Rotate the key at once, turn on push protection, read the provider's access log | 2 Low |
| B-02 | Third-party dependencies | A library has a known vulnerability | 3 | 2 | 6 High | Dependabot alerts, dependency scan in CI | Pinned versions and a bill of materials show what is affected; patch release plan | 4 Medium |
| B-03 | main branch | Bad code (bug or backdoor) is merged without review | 2 | 3 | 6 High | Branch protection: pull request, required review, required checks | Small pull requests and tests make a revert quick (git revert) | 2 Low |
| B-04 | Git history | A force push erases history | 2 | 3 | 6 High | Block force push and deletion on main | Other clones and a mirror copy hold the old history | 2 Low |
| B-05 | Maintainer GitHub account | Account taken over (stolen password or token) | 2 | 3 | 6 High | 2FA, short-lived fine-grained tokens limited to one repo | Revoke tokens and sessions, read the audit log, rotate secrets | 3 Medium |
| B-06 | CI pipeline (GitHub Actions) | A third-party action is hijacked and steals secrets | 2 | 3 | 6 High | Pin actions to a full commit SHA, read-only permissions by default | Secrets scoped per environment so a leak reaches little; rotate after an incident | 2 Low |
| B-07 | Repository and local copy | Repo or laptop is lost or deleted | 1 | 3 | 3 Medium | Push often, keep a second remote or mirror | Written restore steps, tested once | 1 Low |
| B-08 | Test data and logs in the repo | Personal or private data ends up in git | 2 | 2 | 4 Medium | Fake sample data, .gitignore for logs, look at the diff before pushing | Remove the data from history (owner only), tell affected people, rotate anything exposed | 2 Low |

## Why it can happen and what it costs

- **B-01**: Secrets kept in code or .env files; no check before commit. Damage: Anyone with repo access can use the key; a public repo means the whole internet.
- **B-02**: Old versions never updated; nobody watches advisories. Damage: Attacker uses a public exploit against the app.
- **B-03**: Anyone can push to main; no required checks. Damage: Broken or malicious code reaches users.
- **B-04**: Force push is allowed on main. Damage: Lost commits, no audit trail of who changed what.
- **B-05**: No 2FA; long-lived personal tokens. Damage: Attacker can change code, secrets and settings as the owner.
- **B-06**: Actions referenced by moving tag; workflows can write everywhere. Damage: Secrets leak and builds are tampered with.
- **B-07**: Only one copy, no restore steps written down. Damage: Work is lost.
- **B-08**: Real data used as samples; no review before first push. Damage: Privacy problem; removing it needs a history rewrite.

## Notes

- All rows are `Open` until a control exists and has been checked.
- Likelihood after a control is a judgement, not a measurement. Each drop should be defended in one sentence.
