#!/usr/bin/env bash
# Create the eve-lab index template and load the ECS-normalised EVE samples (R-07, R-08).
# The admin password goes to curl through a config on stdin, never as an argument.
set -euo pipefail

cd "$(dirname "$0")/.."

for f in .env .env.secrets; do
  [ -f "$f" ] || { echo "missing $f (run make up first)" >&2; exit 1; }
done

set -a
# shellcheck disable=SC1091
. ./.env
# shellcheck disable=SC1091
. ./.env.secrets
set +a

base="https://localhost:${OPENSEARCH_PORT}"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

os() {
  printf 'user = "admin:%s"\n' "$OPENSEARCH_INITIAL_ADMIN_PASSWORD" | curl -sk -K - "$@"
}

python3 scripts/load_samples.py >"$tmp"

echo "== index template"
os -X PUT -H 'Content-Type: application/json' \
  --data-binary @detections/opensearch/eve-lab-template.json "$base/_index_template/eve-lab"
echo
echo "== reload the sample index"
os -X DELETE "$base/eve-lab-samples" >/dev/null || true
os -X POST -H 'Content-Type: application/x-ndjson' \
  --data-binary @"$tmp" "$base/_bulk?refresh=true" |
  python3 -c 'import json, sys; r = json.load(sys.stdin); print("errors:", r["errors"], "documents:", len(r["items"]))'
