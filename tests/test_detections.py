"""Sigma rules as tests (R-07): structure, ATT&CK mapping, ECS fields, match and no-match.

Every rule needs one positive and one negative sample under tests/samples/eve. The samples are
raw EVE lines. They go through the reference normaliser, then the rule is evaluated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from detections import ecs_eve, sigma_match

ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = sorted((ROOT / "detections" / "sigma").glob("*.yml"))
SAMPLES = ROOT / "tests" / "samples" / "eve"

# rule file stem -> sample prefix. A new rule without an entry here fails the first test.
PREFIX = {
    "web_sql_injection_alert": "sqli",
    "web_scanner_user_agent": "scanner",
}
ECS_FIELDS = set(ecs_eve.RENAMES.values()) | {"event.module", "event.dataset", "event.kind", "event.category"}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def sample_event(name: str) -> dict:
    return ecs_eve.normalise((SAMPLES / name).read_text().strip())


def rule_of(path: Path) -> dict:
    return sigma_match.load_rule(path)


def test_every_rule_has_a_sample_prefix_and_both_samples() -> None:
    assert {p.stem for p in RULE_FILES} == set(PREFIX)
    for prefix in PREFIX.values():
        assert (SAMPLES / f"{prefix}_positive.json").exists()
        assert (SAMPLES / f"{prefix}_negative.json").exists()


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_is_mapped_to_attack(path: Path) -> None:
    rule = rule_of(path)
    tags = rule["tags"]
    assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in tags), "no technique tag"
    assert any(re.fullmatch(r"attack\.[a-z-]+", t) and not re.search(r"\.t\d", t) for t in tags), "no tactic tag"
    assert any("attack.mitre.org" in ref for ref in rule["references"])


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_metadata(path: Path) -> None:
    rule = rule_of(path)
    assert UUID.match(rule["id"])
    assert rule["level"] in {"low", "medium", "high", "critical"}
    assert rule["status"] in {"experimental", "test", "stable"}
    assert rule["falsepositives"]


def test_rule_ids_are_unique() -> None:
    ids = [rule_of(p)["id"] for p in RULE_FILES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_uses_ecs_fields_only(path: Path) -> None:
    detection = dict(rule_of(path)["detection"])
    detection.pop("condition")
    for selection in detection.values():
        for key in selection:
            assert key.split("|")[0] in ECS_FIELDS, f"{key} is not an ECS field the pipeline produces"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_positive_sample_matches_and_negative_does_not(path: Path) -> None:
    rule, prefix = rule_of(path), PREFIX[path.stem]
    assert sigma_match.matches(rule, sample_event(f"{prefix}_positive.json"))
    assert not sigma_match.matches(rule, sample_event(f"{prefix}_negative.json"))


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_a_rule_does_not_match_the_other_rules_samples(path: Path) -> None:
    rule, own = rule_of(path), PREFIX[path.stem]
    for prefix in set(PREFIX.values()) - {own}:
        assert not sigma_match.matches(rule, sample_event(f"{prefix}_positive.json"))


def test_malformed_line_is_never_a_match() -> None:
    event = ecs_eve.normalise((SAMPLES / "malformed_line.txt").read_text().strip())
    assert all(not sigma_match.matches(rule_of(p), event) for p in RULE_FILES)


def test_match_is_case_insensitive() -> None:
    rule = rule_of(ROOT / "detections/sigma/web_scanner_user_agent.yml")
    event = {"event": {"dataset": "eve.alert"}, "user_agent": {"original": "SQLMAP/1.8"}}
    assert sigma_match.matches(rule, event)


def test_other_dataset_is_not_a_match() -> None:
    rule = rule_of(ROOT / "detections/sigma/web_scanner_user_agent.yml")
    event = {"event": {"dataset": "eve.flow"}, "user_agent": {"original": "sqlmap"}}
    assert not sigma_match.matches(rule, event)


def test_evaluator_refuses_what_it_cannot_evaluate() -> None:
    base = {"detection": {"a": {"x|windash": "1"}, "condition": "a"}}
    with pytest.raises(NotImplementedError):
        sigma_match.matches(base, {"x": "1"})
    with pytest.raises(NotImplementedError):
        sigma_match.matches({"detection": {"a": {"x": 1}, "b": {"x": 2}, "condition": "1 of a*"}}, {"x": 1})


def test_condition_operators() -> None:
    rule = {"detection": {"a": {"x": 1}, "b": {"y": 2}, "condition": "a and not b or (b and not a)"}}
    assert sigma_match.matches(rule, {"x": 1})
    assert sigma_match.matches(rule, {"y": 2})
    assert not sigma_match.matches(rule, {"x": 1, "y": 2})
    assert not sigma_match.matches(rule, {})


def test_pysigma_parses_and_converts_every_rule() -> None:
    pytest.importorskip("sigma.backends.opensearch")
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.collection import SigmaCollection

    for path in RULE_FILES:
        collection = SigmaCollection.from_yaml(path.read_text())
        assert not collection.errors, collection.errors
        queries = OpensearchLuceneBackend().convert(collection)
        assert len(queries) == 1 and "event.dataset:eve.alert" in queries[0]
