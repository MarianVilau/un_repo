"""Show that MISP enrichment changes a verdict (R-09). Output goes to docs/evidence.

The same EVE alert is judged twice by every Sigma rule: as the sensor wrote it, and after
the enrichment stage. Run: python3 scripts/enrichment_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detections import ecs_eve, enrich, sigma_match

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "detections" / "sigma").glob("*.yml"))
DICT = enrich.load_dictionary(ROOT / "pipelines" / "eve" / "dictionaries" / "misp_ip.yml")


def verdict(event: dict) -> list[str]:
    return [r.stem for r in RULES if sigma_match.matches(sigma_match.load_rule(r), event)]


def main() -> int:
    for name in ("listed_positive.json", "listed_negative.json"):
        event = ecs_eve.normalise((ROOT / "tests" / "samples" / "eve" / name).read_text().strip())
        print(f"{name}  source.ip={event['source']['ip']}")
        print(f"  before enrichment: {verdict(event) or 'no rule fires'}")
        print(f"  after enrichment:  {verdict(enrich.enrich(event, DICT)) or 'no rule fires'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
