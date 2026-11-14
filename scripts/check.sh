#!/usr/bin/env bash
# One command for the local checks. Used by the check-and-test skill and by hand.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if command -v yamllint >/dev/null 2>&1; then
  echo "== yamllint"
  yamllint -d '{extends: relaxed, rules: {line-length: disable}}' .github .pre-commit-config.yaml
else
  echo "== yamllint not installed, skipped"
fi

echo "== pre-commit"
pre-commit run --all-files

if [ -d tests ]; then
  echo "== pytest"
  python3 -m pytest -q
fi

echo "All checks passed."
