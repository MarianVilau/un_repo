# CI runbook (Session 4)

Risks: R-06 (pipeline supply chain), R-07 (tests on every pull request), R-01 (required check).

## What `ci.yml` does

| Job | Tool | Fails when |
|---|---|---|
| `shellcheck` | ShellCheck from the runner image | any tracked `*.sh` has a finding |
| `hadolint` | hadolint-action | the root `Dockerfile` has a finding. There is no Dockerfile yet, so it only prints a notice |
| `semgrep` | Semgrep 1.182.1, packs `p/github-actions`, `p/python`, `p/secrets` | any finding |
| `trivy` | Trivy v0.76.1, filesystem scan: vulnerabilities, secrets, misconfigurations | HIGH or CRITICAL with a fix available |
| `pytest` | pytest with `STRICT_DIGESTS=1` | any test fails, or a digest is still a placeholder |
| `sbom` | Syft through anchore/sbom-action, SPDX JSON | no SBOM produced. The file is kept as an artifact |
| `ci-gate` | none | any job above did not succeed. This is the check the ruleset requires |
| `release` | cosign v3.1.4, keyless | only for a pushed `v*` tag. Signs the SBOM and the source archive, verifies them, then creates the release |

## How pinning works

Every `uses:` line is `owner/repo@<40 hex> # vX.Y.Z`. `tests/test_workflow_policy.py` fails on a tag, a short SHA or a missing tag comment. The SHAs were read with `git ls-remote` on the day of writing and each commit date was checked. Versions younger than two weeks were not used.

To update an action: read the new tag's commit with `git ls-remote --tags https://github.com/<owner>/<repo>`, check the commit date and the project's security advisories, change both the SHA and the comment, run `pytest`.

## Permissions

The workflow starts with `permissions: {}`. Check jobs get `contents: read`. Only `release` gets `contents: write` and `id-token: write`. `tests/test_workflow_policy.py` enforces that.

## First release

After this pull request is merged:

```bash
git switch main && git pull
git tag -a v0.1.0 -m "S4: CI, SBOM, signed release"
git push origin v0.1.0
```

The tag run builds the SBOM, signs and verifies, and publishes the release.

## Verify a release by hand

Download `sbom.spdx.json`, `sbom.spdx.json.sigstore.json`, the source archive and its `.sigstore.json` bundle into an empty folder, then:

```bash
cosign verify-blob \
  --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity "https://github.com/MarianVilau/un_repo/.github/workflows/ci.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom.spdx.json
```

Do the same for the source archive. Save the output as `docs/evidence/s4-release-verify.txt`.

## Repository settings to apply by hand

These cannot be committed. Set them under Settings, Actions, General, then screenshot for `s4-actions-settings.png`:

- Require actions to be pinned to a full-length commit SHA.
- Workflow permissions: read repository contents only.
- Approval for all outside collaborators and first-time contributors.

To make `ci-gate` required, edit the existing ruleset after the first `ci` run has completed once, so GitHub knows the check name: Settings, Rules, Rulesets, `main-protection`, Require status checks, Add checks, `ci-gate`, Save. Importing the JSON again can create a second ruleset. `.github/rulesets/main.json` records the intended state. Check the live one with `gh api repos/MarianVilau/un_repo/rulesets/<id> --jq '.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context'`.

## Known limits

- Nothing here ran on GitHub when this was written. The workflow was checked with yamllint and the policy tests only. The first real run may need small fixes.
- `actionlint` was not available, so expression syntax is unchecked beyond YAML.
- Semgrep registry packs are fetched at run time. The Semgrep version is pinned, the rule content is not.
- The `--bundle` flag spelling for cosign v3 was not run here. The release job fails at the sign step if it differs.
- Python packages are pinned by version, not by hash.
- There is no Dockerfile, so Hadolint is inert until one exists.
