# Deploy targets for the lab stack. Based on the Makefile that ships with Lab 3.
# Ports come from .env, the admin password from .env.secrets, which `make secrets`
# decrypts from SOPS ciphertext and `make down` deletes (R-02).
SHELL := /bin/bash

# Recursive variables: they are expanded when a recipe runs, after .env.secrets exists.
ENV_FILES = --env-file .env $(if $(wildcard .env.secrets),--env-file .env.secrets)
PROFILE   = $(if $(wildcard certs/frontdoor.crt),--profile frontdoor) $(if $(wildcard secrets/grafana.enc.yaml),--profile monitoring)

.PHONY: secrets up down health cert reload pin-digests verify test lint sigma-query load-samples misp-dictionary exposure-check

.env:
	cp .env.example .env

# Decrypt the SOPS secret for compose; owner-only file, deleted by make down.
secrets:
	umask 077 && sops -d secrets/opensearch.enc.yaml | sed 's/: /=/' > .env.secrets
	[ ! -f secrets/grafana.enc.yaml ] || sops -d secrets/grafana.enc.yaml | sed 's/: /=/' >> .env.secrets

up: .env secrets
	docker compose $(ENV_FILES) $(PROFILE) up -d --wait --wait-timeout 240

down: .env
	docker compose $(ENV_FILES) --profile frontdoor --profile monitoring down -v
	rm -f .env.secrets

# Poll the cluster health until green or yellow (output goes to docs/evidence).
health:
	bash scripts/health.sh

# Issue or renew the front door certificate. Needs step-ca running in another terminal.
cert:
	mkdir -p certs
	step ca certificate frontdoor.lab certs/frontdoor.crt certs/frontdoor.key \
	  --san frontdoor.lab --san localhost \
	  --ca-url https://localhost:8443 --root "$$(step path)/certs/root_ca.crt" --force
	chmod 700 certs
	chmod 644 certs/frontdoor.crt certs/frontdoor.key

reload:
	docker compose $(ENV_FILES) exec frontdoor nginx -s reload

# Replace the placeholder digests in compose.yaml with the ones Docker resolves.
pin-digests:
	python3 scripts/pin_digests.py compose.yaml

# The Lab 3 checklist as tests: pinned digests, variable ports, ciphertext only.
verify:
	STRICT_DIGESTS=1 python3 -m pytest -q tests/test_compose_policy.py

test:
	python3 -m pytest -q tests/

lint:
	pre-commit run --all-files

# Print the OpenSearch query pySigma generates from each Sigma rule.
sigma-query:
	python3 scripts/sigma_query.py

# Create the index template and load the EVE samples into the running stack.
load-samples:
	bash scripts/load-samples.sh

# Rebuild the MISP indicator dictionary. The key is decrypted into this one command only (R-02, R-09).
misp-dictionary: .env
	set -a; . ./.env; set +a; \
	eval "$$(sops -d secrets/misp.enc.yaml | sed 's/: /=/')"; \
	python3 threatintel/misp_lookup.py

# Ask Shodan what it sees on the lab IP; exit 1 on an unexpected port (R-02, R-10).
exposure-check: .env
	set -a; . ./.env; set +a; \
	eval "$$(sops -d secrets/shodan.enc.yaml | sed 's/: /=/')"; \
	python3 scripts/exposure_check.py
