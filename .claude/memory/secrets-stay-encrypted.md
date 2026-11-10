---
name: secrets-stay-encrypted
type: correction
---

Passwords and keys exist in the repository only as SOPS/age ciphertext under `secrets/*.enc.yaml`.

**Why:** a plaintext secret in a commit is permanent once pushed (R-02).

**How to apply:** encrypt with `sops`, decrypt in the `make secrets` target with `umask 077` into an ignored file. Never print a secret, put it in a command argument or paste it into a prompt.
