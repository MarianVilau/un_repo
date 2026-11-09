#!/usr/bin/env bash
# Poll OpenSearch and Dashboards until both answer, then print the health output (R-02, R-08).
# Reads ports from .env and the admin password from .env.secrets. The password goes to curl
# through a config on stdin, so it never appears in the process list.
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

tries="${HEALTH_TRIES:-30}"

echo "== OpenSearch cluster health"
for ((i = 1; i <= tries; i++)); do
  if out=$(printf 'user = "admin:%s"\n' "$OPENSEARCH_INITIAL_ADMIN_PASSWORD" |
    curl -sk -K - "https://localhost:${OPENSEARCH_PORT}/_cluster/health?pretty") &&
    grep -Eq '"status" : "(green|yellow)"' <<<"$out"; then
    echo "$out"
    break
  fi
  if [ "$i" -eq "$tries" ]; then
    echo "OpenSearch not healthy after $tries tries" >&2
    exit 1
  fi
  sleep 5
done

echo "== Dashboards status"
for ((i = 1; i <= tries; i++)); do
  if out=$(curl -s "http://localhost:${DASHBOARDS_PORT}/api/status") &&
    grep -q '"state":"green"' <<<"$out"; then
    echo "$out" | head -c 400
    echo
    exit 0
  fi
  if [ "$i" -eq "$tries" ]; then
    echo "Dashboards not green after $tries tries" >&2
    exit 1
  fi
  sleep 5
done
