#!/usr/bin/env bash
# One-time setup of the OpenSearch admin password as a SOPS/age ciphertext (R-02).
# Creates an age key outside the repository, writes .sops.yaml with the public key only,
# generates a random password and encrypts it. The plaintext never touches a file or
# a command argument; it travels through a pipe.
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in age-keygen sops openssl; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

key_dir="${SOPS_AGE_KEY_DIR:-$HOME/.config/sops/age}"
key_file="$key_dir/keys.txt"
secret_file="secrets/opensearch.enc.yaml"

if [ -f "$secret_file" ]; then
  echo "$secret_file already exists, nothing to do" >&2
  exit 0
fi

if [ ! -f "$key_file" ]; then
  mkdir -p "$key_dir"
  chmod 700 "$key_dir"
  (umask 077 && age-keygen -o "$key_file" 2>/dev/null)
fi

pub=$(age-keygen -y "$key_file")

cat >.sops.yaml <<EOF
creation_rules:
  - path_regex: secrets/.*\.enc\.yaml$
    age: ${pub}
EOF

mkdir -p secrets
# OpenSearch 2.12+ rejects weak admin passwords: fixed prefix guarantees upper, lower,
# digit and symbol, the random part supplies length.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf 'OPENSEARCH_INITIAL_ADMIN_PASSWORD: Lab-%s-9!\n' "$(openssl rand -hex 12)" |
  sops --encrypt --input-type yaml --output-type yaml --filename-override "$secret_file" /dev/stdin >"$tmp"
mv "$tmp" "$secret_file"

echo "created $secret_file (ciphertext) and .sops.yaml (public key)"
echo "private key stays in $key_file, back it up outside the repository"
