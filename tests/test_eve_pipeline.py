"""Logstash eve pipeline checks (R-07). Logstash is not run here, so these are static.

The conf files are compared with the reference mapping in detections/ecs_eve.py, which the rule
tests use. Whether Logstash itself accepts the files is checked only when the stack runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from detections import ecs_eve

ROOT = Path(__file__).resolve().parent.parent
PIPE = ROOT / "pipelines" / "eve"
CONF = {p.name: p.read_text() for p in sorted(PIPE.glob("*.conf"))}
ALL = "\n".join(CONF.values())
SAMPLES = ROOT / "tests" / "samples" / "eve"
SECRET_VARS = {"OPENSEARCH_INITIAL_ADMIN_PASSWORD"}


def test_stage_files_exist_in_order() -> None:
    assert list(CONF) == ["10-input.conf", "20-normalise.conf", "30-enrich.conf", "90-output.conf"]


def test_no_literal_ports_hosts_or_ips() -> None:
    assert not re.search(r"port\s*=>\s*\"?\d", ALL)
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", ALL)
    assert not re.search(r"hosts\s*=>\s*\[\"https?://(?!\$\{)", ALL)


def test_every_variable_is_documented_or_a_secret() -> None:
    env_example = (ROOT / ".env.example").read_text()
    defined = {line.split("=", 1)[0] for line in env_example.splitlines() if "=" in line and not line.startswith("#")}
    used = set(re.findall(r"\$\{([A-Z_]+)\}", ALL)) | set(re.findall(r'ENV\["([A-Z_]+)"\]', ALL))
    assert used - SECRET_VARS <= defined, used - SECRET_VARS - defined


def test_failed_lines_are_tagged_and_never_dropped() -> None:
    assert ALL.count("_parse_failure") >= 2
    assert "_oversized" in CONF["20-normalise.conf"]
    assert not re.search(r"\bdrop\s*\{", ALL)


def test_mapping_matches_the_reference() -> None:
    block = re.search(r"rename\s*=>\s*\{(.*?)\}", CONF["20-normalise.conf"], re.S).group(1)
    pair = re.compile(r'"((?:\[[\w@]+\])+)"\s*=>\s*"((?:\[[\w@]+\])+)"')

    def dotted(brackets: str) -> str:
        return ".".join(re.findall(r"\[([\w@]+)\]", brackets))

    in_conf = {dotted(src).removeprefix("eve."): dotted(dst) for src, dst in pair.findall(block)}
    assert in_conf == ecs_eve.RENAMES


def test_conf_sets_timestamp_dataset_and_lowercases_proto() -> None:
    text = CONF["20-normalise.conf"]
    assert re.search(r'target\s*=>\s*"@timestamp"', text)
    assert '"[event][dataset]" => "eve.%{[eve][event_type]}"' in text
    assert 'lowercase => ["[eve][proto]"]' in text


def test_default_max_line_bytes_matches_the_reference() -> None:
    match = re.search(r'ENV\["EVE_MAX_LINE_BYTES"\] \|\| "(\d+)"', CONF["20-normalise.conf"])
    env = re.search(r"^EVE_MAX_LINE_BYTES=(\d+)$", (ROOT / ".env.example").read_text(), re.M)
    assert int(match.group(1)) == ecs_eve.DEFAULT_MAX_LINE_BYTES == int(env.group(1))


def test_alert_sample_maps_to_ecs() -> None:
    event = ecs_eve.normalise((SAMPLES / "sqli_positive.json").read_text().strip())
    assert event["source"]["ip"] == "203.0.113.50"
    assert event["destination"]["port"] == 3000
    assert event["network"]["transport"] == "tcp"
    assert event["rule"]["id"] == 1000001
    assert event["event"] == {
        "module": "eve", "dataset": "eve.alert", "kind": "alert", "category": "network", "severity": 1,
    }
    assert event["@timestamp"] == "2026-11-12T10:15:03.123456Z"
    assert "UNION SELECT" in event["url"]["original"]


def test_malformed_line_is_kept_and_tagged() -> None:
    line = (SAMPLES / "malformed_line.txt").read_text().strip()
    event = ecs_eve.normalise(line)
    assert event["message"] == line
    assert event["tags"] == ["_parse_failure"]
    assert "source" not in event


def test_oversized_line_is_kept_and_tagged() -> None:
    line = json.dumps({"event_type": "alert", "http": {"url": "/" + "a" * 20000}})
    event = ecs_eve.normalise(line)
    assert event["tags"] == ["_parse_failure", "_oversized"]
    assert event["message"] == line


def test_json_that_is_not_an_object_is_tagged() -> None:
    for line in ("[1, 2]", "42", "null", ""):
        assert "_parse_failure" in ecs_eve.normalise(line)["tags"]


def test_other_event_types_are_normalised_without_alert_fields() -> None:
    event = ecs_eve.normalise(json.dumps({"event_type": "flow", "src_ip": "192.0.2.1"}))
    assert event["event"]["dataset"] == "eve.flow"
    assert "kind" not in event["event"]
    assert event["source"]["ip"] == "192.0.2.1"


def test_index_template_makes_matching_fields_case_insensitive_keywords() -> None:
    template = json.loads((ROOT / "detections/opensearch/eve-lab-template.json").read_text())
    props = template["template"]["mappings"]["properties"]
    for field in (props["url"]["properties"]["original"], props["user_agent"]["properties"]["original"]):
        assert field == {"type": "keyword", "normalizer": "lowercase_normalizer"}
    assert "lowercase_normalizer" in template["template"]["settings"]["analysis"]["normalizer"]
