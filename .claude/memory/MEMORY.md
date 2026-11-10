# Memory index

One correction per file. Each file says what happened, why it matters and when it applies. Review every change here like code (R-05).

- [Never hardcode ports](never-hardcode-ports.md): every port is a variable from `.env`.
- [Pin images by digest](pin-images-by-digest.md): no floating tags in Compose or Dockerfiles.
- [Secrets stay encrypted](secrets-stay-encrypted.md): SOPS/age only, decrypt in a Make target.
- [PRs cite risk IDs](pr-cites-risk-ids.md): the governance check fails without one.
