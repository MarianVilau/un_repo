"""MISP enrichment (R-09): conf matches the reference, and enrichment changes a verdict."""

from __future__ import annotations

import re
from pathlib import Path

from detections import ecs_eve, enrich, sigma_match

ROOT = Path(__file__).resolve().parent.parent
CONF = (ROOT / "pipelines" / "eve" / "30-enrich.conf").read_text()
DICT = ROOT / "pipelines" / "eve" / "dictionaries" / "misp_ip.yml"
SAMPLES = ROOT / "tests" / "samples" / "eve"
RULE = sigma_match.load_rule(ROOT / "detections" / "sigma" / "web_alert_from_misp_source.yml")
OTHER_RULES = [
    sigma_match.load_rule(p)
    for p in sorted((ROOT / "detections" / "sigma").glob("*.yml"))
    if p.name != "web_alert_from_misp_source.yml"
]


def _event(name: str) -> dict:
    return ecs_eve.normalise((SAMPLES / name).read_text().strip())


def _fires(rules: list, event: dict) -> bool:
    return any(sigma_match.matches(r, event) for r in rules)


def test_conf_reads_ecs_and_only_adds_fields() -> None:
    assert '"[source][ip]"' in CONF
    assert "[threat][indicator][provider]" in CONF
    assert "[threat][indicator][matched]" in CONF
    assert not re.search(r"\b(drop|remove_field)\b", CONF)
    assert "overwrite" not in CONF


def test_conf_skips_parse_failures_and_uses_env_path() -> None:
    assert '"_parse_failure" not in [tags]' in CONF
    assert 'dictionary_path => "${MISP_DICTIONARY_PATH}"' in CONF
    assert not re.search(r"dictionary_path\s*=>\s*\"[./\w]", CONF)


def test_conf_and_reference_use_the_same_fields() -> None:
    assert enrich.LOOKUP_FIELD == "source.ip"
    for field in (enrich.PROVIDER_FIELD, enrich.MATCHED_FIELD):
        assert "[" + "][".join(field.split(".")) + "]" in CONF


def test_listed_source_is_tagged() -> None:
    out = enrich.enrich(_event("listed_positive.json"), enrich.load_dictionary(DICT))
    assert out["threat"]["indicator"] == {"provider": "misp", "matched": True}


def test_clean_source_is_not_tagged() -> None:
    event = _event("listed_negative.json")
    out = enrich.enrich(event, enrich.load_dictionary(DICT))
    assert "threat" not in out
    assert out == event


def test_enrichment_never_changes_source_fields() -> None:
    event = _event("listed_positive.json")
    out = enrich.enrich(event, enrich.load_dictionary(DICT))
    out.pop("threat")
    assert out == event


def test_enrichment_does_not_mutate_its_input() -> None:
    event = _event("listed_positive.json")
    enrich.enrich(event, {"203.0.113.77": "misp"})
    assert "threat" not in event


def test_rule_positive_and_negative() -> None:
    d = enrich.load_dictionary(DICT)
    assert sigma_match.matches(RULE, enrich.enrich(_event("listed_positive.json"), d))
    assert not sigma_match.matches(RULE, enrich.enrich(_event("listed_negative.json"), d))


def test_rule_needs_enrichment() -> None:
    assert not sigma_match.matches(RULE, _event("listed_positive.json"))


def test_enrichment_changes_the_outcome() -> None:
    """The same alert raises nothing without enrichment and a high alert with it (R-09)."""
    raw = _event("listed_positive.json")
    rich = enrich.enrich(raw, enrich.load_dictionary(DICT))
    assert not _fires(OTHER_RULES + [RULE], raw)
    assert _fires(OTHER_RULES + [RULE], rich)


def test_other_rules_do_not_fire_on_the_listed_sample() -> None:
    assert not _fires(OTHER_RULES, _event("listed_positive.json"))


def test_only_the_listed_sample_is_tagged_by_the_seed_dictionary() -> None:
    """A sample that shares a source with the dictionary would give two hits in Discover."""
    d = enrich.load_dictionary(DICT)
    tagged = {
        p.name
        for p in sorted(SAMPLES.glob("*.json"))
        if "threat" in enrich.enrich(ecs_eve.normalise(p.read_text().strip()), d)
    }
    assert tagged == {"listed_positive.json"}
