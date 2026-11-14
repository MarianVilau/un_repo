#!/usr/bin/env bash
# Store one API key as a SOPS/age ciphertext under secrets/ (R-02).
# Usage: bash scripts/add-secret.sh misp MISP_KEY
#        bash scripts/add-secret.sh shodan SHODAN_API_KEY
# The value is typed at a hidden prompt and travels through a pipe. It is never an
# argument, never in shell history and never written unencrypted.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <name> <VARIABLE_NAME>" >&2
  exit 2
fi
name=$1
var=$2
[[ "$name" =~ ^[a-z][a-z0-9-]*$ ]] || { echo "name must be lowercase letters, digits, dashes" >&2; exit 2; }
[[ "$var" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "variable must be UPPER_SNAKE_CASE" >&2; exit 2; }
command -v sops >/dev/null || { echo "missing tool: sops" >&2; exit 1; }

target="secrets/${name}.enc.yaml"
[ ! -e "$target" ] || { echo "$target exists; delete it deliberately to replace it" >&2; exit 1; }

read -r -s -p "${var}: " value
echo >&2
[ -n "$value" ] || { echo "empty value, nothing written" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s: %s\n' "$var" "$value" |
  sops --encrypt --input-type yaml --output-type yaml --filename-override "$target" /dev/stdin >"$tmp"
unset value
mv "$tmp" "$target"
echo "created $target (ciphertext)"
