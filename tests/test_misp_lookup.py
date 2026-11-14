"""MISP lookup (R-09): pure functions only, PyMISP and the network are not touched."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from detections import enrich
from threatintel import misp_lookup

FIXTURE = json.loads((Path(__file__).parent / "samples" / "misp" / "attributes.json").read_text())


def test_extract_keeps_only_detection_ips() -> None:
    assert misp_lookup.extract_ips(FIXTURE["Attribute"]) == {"203.0.113.77", "192.0.2.44"}


def test_private_and_garbage_values_are_refused() -> None:
    for value in ("192.168.1.20", "10.0.0.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "x", "", None):
        assert misp_lookup.public_ip(value) is None
    assert misp_lookup.public_ip(" 203.0.113.5 ") == "203.0.113.5"


def test_ips_without_to_ids_are_refused() -> None:
    assert "203.0.113.99" not in misp_lookup.extract_ips(FIXTURE["Attribute"])


def test_dictionary_is_sorted_yaml_read_back_by_enrich(tmp_path: Path) -> None:
    path = tmp_path / "d.yml"
    assert misp_lookup.write_dictionary({"203.0.113.77", "192.0.2.44"}, path) == 2
    assert list(yaml.safe_load(path.read_text())) == ["192.0.2.44", "203.0.113.77"]
    assert enrich.load_dictionary(path) == {"192.0.2.44": "misp", "203.0.113.77": "misp"}
    assert not list(tmp_path.glob("*.tmp"))


def test_main_needs_its_settings(monkeypatch, capsys) -> None:
    for name in ("MISP_KEY", "MISP_URL", "MISP_DICTIONARY_PATH"):
        monkeypatch.delenv(name, raising=False)
    assert misp_lookup.main() == 2
    assert "MISP_KEY" in capsys.readouterr().err


def test_main_writes_dictionary(monkeypatch, tmp_path, capsys) -> None:
    out = tmp_path / "d.yml"
    monkeypatch.setenv("MISP_KEY", "dummy")
    monkeypatch.setenv("MISP_URL", "https://misp.invalid")
    monkeypatch.setenv("MISP_DICTIONARY_PATH", str(out))
    monkeypatch.setattr(misp_lookup, "fetch_attributes", lambda *a, **k: FIXTURE["Attribute"])
    assert misp_lookup.main() == 0
    assert "dummy" not in capsys.readouterr().out
    assert set(yaml.safe_load(out.read_text())) == {"203.0.113.77", "192.0.2.44"}
