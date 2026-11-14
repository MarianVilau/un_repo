"""Reference for pipelines/eve/30-enrich.conf (R-09).

Same rule as the translate filter: look up source.ip in the MISP dictionary and, on a hit,
add threat.indicator.provider and threat.indicator.matched. Source fields are never changed.
tests/test_enrich.py checks that the conf and this module agree.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from detections.ecs_eve import get_path, set_path

LOOKUP_FIELD = "source.ip"
PROVIDER_FIELD = "threat.indicator.provider"
MATCHED_FIELD = "threat.indicator.matched"


def load_dictionary(path: Path) -> dict[str, str]:
    data = yaml.safe_load(path.read_text()) or {}
    return {str(k): str(v) for k, v in data.items()}


def enrich(event: dict[str, Any], dictionary: dict[str, str]) -> dict[str, Any]:
    """Return a copy of the event with indicator fields added on a match."""
    out = copy.deepcopy(event)
    ip = get_path(out, LOOKUP_FIELD)
    provider = dictionary.get(str(ip)) if ip is not None else None
    if provider:
        set_path(out, PROVIDER_FIELD, provider)
        set_path(out, MATCHED_FIELD, True)
    return out
