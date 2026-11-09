# Lab 3 runbook (R-02, R-08)

Run these in WSL Ubuntu with Docker Desktop integration on. Nothing here was run in the
authoring sandbox: the digests, sops and the stack are unchecked until you run them.

## Prerequisites

- `docker compose version` works.
- `sops` and `age` installed (release binaries from their GitHub pages), plus `step` and `step-ca` for the PKI part.
- `sudo sysctl -w vm.max_map_count=262144` if OpenSearch exits at start. On Docker Desktop with WSL, run it in the `docker-desktop` distro.

## One-time

1. `scripts/init-secrets.sh` creates the age key in `~/.config/sops/age/keys.txt`, writes `.sops.yaml` (public key) and `secrets/opensearch.enc.yaml` (ciphertext). Commit both. Never commit the key.
2. `make pin-digests` pulls the three images and writes their digests into `compose.yaml`. Commit the result.
3. `make verify` must pass.

## Start, check, stop

- `make up` creates `.env` from `.env.example`, decrypts the secret into `.env.secrets` (mode 600) and starts the stack. Compose waits for health.
- `make health` prints the cluster health and the Dashboards status. Save it for the evidence folder.
- `make down` removes containers, the data volume and `.env.secrets`.

Run `make up` twice from zero (`make down` between) to show the stack is reproducible.

## Front door with the lab CA

1. `step ca init --name "Lab Root" --dns localhost --address :8443 --provisioner lab` (the password prompt is interactive, do not pass it as an argument).
2. In a second terminal: `step-ca $(step path)/config/ca.json`.
3. Add `127.0.0.1 frontdoor.lab` to your hosts file.
4. `make cert`, then `make up` again: the `frontdoor` profile starts because `certs/frontdoor.crt` now exists.
5. Trust `$(step path)/certs/root_ca.crt` in the browser or OS store, open `https://frontdoor.lab`, screenshot the certificate chain.

`certs/` and the age key are in `.gitignore`.

## Known limits

- The front door proxies Dashboards to plain HTTP inside the Compose network. Dashboards itself is not TLS.
- Dashboards runs with the default security plugin settings of the image. It is not hardened beyond that.
- `make cert` uses the step-ca provisioner prompt, so it asks for the provisioner password.
- `make cert` sets `certs/` to 700 and the leaf files to 644. The nginx container drops all capabilities, so it cannot read a 600 key owned by another user. The key is a lab key on a single-user machine, and `certs/` stays out of git.
- `make health` sends the admin password to Dashboards over plain HTTP on the loopback address, through curl's stdin, because `/api/status` needs authentication.
- The lab root is named `Lab Root Root CA`. Trust it only while testing and remove it from the OS store afterwards: its key lives on this disk and it has no name constraints.
