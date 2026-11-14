---
name: pr-cites-risk-ids
type: correction
---

Commit messages and pull request descriptions name the risk IDs they address, for example `(R-02)`.

**Why:** the history is supposed to read as the register closing row by row, and the `pr-cites-risk-id` check fails the pull request without an ID.

**How to apply:** find the row in `RISK-REGISTER.md` first. If none fits, propose a new row before writing code.
