"""Lab 3 checklist as tests (R-02, R-08).

Static checks on compose.yaml and the secrets folder. Nothing here needs Docker.
`test_digests_are_resolved` is skipped while compose.yaml holds placeholder digests, unless
STRICT_DIGESTS=1 is set. `make verify` sets it, so it fails until `make pin-digests` has run.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_TEXT = (ROOT / "compose.yaml").read_text()
COMPOSE = yaml.safe_load(COMPOSE_TEXT)
SERVICES = COMPOSE["services"]
DIGEST = re.compile(r"@sha256:([0-9a-f]{64})$")


def test_required_services_exist() -> None:
    assert {"opensearch", "opensearch-dashboards", "frontdoor"} <= set(SERVICES)


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_image_pinned_by_digest(name: str) -> None:
    image = SERVICES[name]["image"]
    assert DIGEST.search(image), f"{name}: {image} is not pinned by @sha256 digest"


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_digests_are_resolved(name: str) -> None:
    m = DIGEST.search(SERVICES[name]["image"])
    placeholder = bool(m) and set(m.group(1)) == {"0"}
    if placeholder and os.environ.get("STRICT_DIGESTS") != "1":
        pytest.skip("placeholder digest, run make pin-digests")
    assert m and not placeholder, f"{name}: placeholder digest, run make pin-digests"


def test_ports_are_variables() -> None:
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            assert re.fullmatch(r"127\.0\.0\.1:\$\{[A-Z_]+\}:\d+", port), f"{name}: {port}"


def test_password_only_as_variable() -> None:
    env = SERVICES["opensearch"]["environment"]
    pw = [e for e in env if e.startswith("OPENSEARCH_INITIAL_ADMIN_PASSWORD")]
    assert pw == ["OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_INITIAL_ADMIN_PASSWORD}"]


def test_single_node_and_named_volume() -> None:
    assert "discovery.type=single-node" in SERVICES["opensearch"]["environment"]
    assert "opensearch-data" in COMPOSE["volumes"]
    assert any(v.startswith("opensearch-data:") for v in SERVICES["opensearch"]["volumes"])


def test_no_floating_tags() -> None:
    for line in COMPOSE_TEXT.splitlines():
        if line.strip().startswith("image:"):
            ref = line.split("image:", 1)[1].split("#", 1)[0].strip()
            assert "@sha256:" in ref and not ref.endswith(":latest")


def test_env_example_covers_every_port_variable() -> None:
    used = set(re.findall(r"\$\{([A-Z_]+PORT)\}", COMPOSE_TEXT))
    defined = {
        line.split("=", 1)[0]
        for line in (ROOT / ".env.example").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    }
    assert used <= defined


def test_env_example_has_no_secret() -> None:
    text = (ROOT / ".env.example").read_text().lower()
    assert "password=" not in text


def test_secret_file_is_ciphertext_when_present() -> None:
    f = ROOT / "secrets" / "opensearch.enc.yaml"
    if not f.exists():
        pytest.skip("run scripts/init-secrets.sh first")
    data = yaml.safe_load(f.read_text())
    assert "sops" in data
    assert str(data["OPENSEARCH_INITIAL_ADMIN_PASSWORD"]).startswith("ENC[")


def test_plain_secret_files_are_ignored() -> None:
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    for pattern in (".env", ".env.secrets", "certs/", "keys.txt"):
        assert pattern in ignore
