"""Shodan exposure check (R-10). Fixtures only; the live response shape is unverified."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import exposure_check  # noqa: E402

DIR = Path(__file__).parent / "samples" / "shodan"


def load(name: str) -> dict:
    return json.loads((DIR / name).read_text())


def test_expected_ports_only_is_ok() -> None:
    result = exposure_check.compare({443}, load("host_expected.json"))
    assert result["ok"] and result["unexpected_ports"] == [] and result["vulns"] == []


def test_unexpected_port_and_vuln_fail() -> None:
    result = exposure_check.compare({443}, load("host_unexpected.json"))
    assert not result["ok"]
    assert result["unexpected_ports"] == [22, 3000]
    assert result["vulns"] == ["CVE-2099-0001"]


def test_no_record_means_nothing_seen() -> None:
    result = exposure_check.compare({443}, None)
    assert result["ok"] and result["expected_not_seen"] == [443]


def test_parse_ports() -> None:
    assert exposure_check.parse_ports("443, 8443") == {443, 8443}


def test_main_reports_missing_settings(monkeypatch, capsys) -> None:
    for n in ("SHODAN_API_KEY", "SHODAN_API_HOST", "SHODAN_TARGET_IP", "SHODAN_EXPECTED_PORTS"):
        monkeypatch.delenv(n, raising=False)
    assert exposure_check.main() == 2
    assert "SHODAN_API_KEY" in capsys.readouterr().err


def _env(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "dummy-key")
    monkeypatch.setenv("SHODAN_API_HOST", "shodan.invalid")
    monkeypatch.setenv("SHODAN_TARGET_IP", "198.51.100.10")
    monkeypatch.setenv("SHODAN_EXPECTED_PORTS", "443")


def test_main_exit_codes_and_no_key_in_output(monkeypatch, capsys) -> None:
    _env(monkeypatch)
    monkeypatch.setattr(exposure_check, "fetch_host", lambda *a: load("host_unexpected.json"))
    assert exposure_check.main() == 1
    monkeypatch.setattr(exposure_check, "fetch_host", lambda *a: load("host_expected.json"))
    assert exposure_check.main() == 0
    captured = capsys.readouterr()
    assert "dummy-key" not in captured.out + captured.err


def test_api_failure_does_not_leak_the_key(monkeypatch, capsys) -> None:
    _env(monkeypatch)

    def boom(*a):
        raise OSError("failed for https://x/?key=dummy-key")

    monkeypatch.setattr(exposure_check, "fetch_host", boom)
    assert exposure_check.main() == 2
    captured = capsys.readouterr()
    assert "dummy-key" not in captured.out + captured.err


def test_http_status_is_shown_without_the_key(monkeypatch, capsys) -> None:
    _env(monkeypatch)

    def refused(*a):
        raise RuntimeError("Shodan answered HTTP 403")

    monkeypatch.setattr(exposure_check, "fetch_host", refused)
    assert exposure_check.main() == 2
    err = capsys.readouterr().err
    assert "HTTP 403" in err and "dummy-key" not in err


def test_internetdb_mode_needs_no_key_and_names_its_source(monkeypatch, capsys) -> None:
    for name, value in (("SHODAN_MODE", "internetdb"), ("SHODAN_API_HOST", "internetdb.shodan.io"),
                        ("SHODAN_TARGET_IP", "203.0.113.5"), ("SHODAN_EXPECTED_PORTS", "443")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    seen = {}

    def fake(host, ip, key, mode):
        seen["mode"] = mode
        return {"ports": [443], "vulns": []}

    monkeypatch.setattr(exposure_check, "fetch_host", fake)
    assert exposure_check.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert seen["mode"] == "internetdb" and out["source"] == "internetdb.shodan.io"


def test_unknown_mode_is_refused(monkeypatch) -> None:
    _env(monkeypatch)
    monkeypatch.setenv("SHODAN_MODE", "other")
    assert exposure_check.main() == 2
