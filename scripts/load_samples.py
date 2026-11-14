"""Print the EVE samples as an OpenSearch bulk body, normalised to ECS and enriched from the MISP dictionary (R-07, R-09).

Reads tests/samples/eve/*.json and malformed_line.txt, applies the reference mapping in
detections/ecs_eve.py and writes NDJSON to stdout. Timestamps are set to the load time so the
default Discover time range shows the documents. The bulk request itself is made by
scripts/load-samples.sh, which keeps the password out of arguments.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detections import ecs_eve, enrich  # noqa: E402

INDEX = "eve-lab-samples"
MISP = enrich.load_dictionary(ROOT / "pipelines" / "eve" / "dictionaries" / "misp_ip.yml")


def main() -> int:
    files = sorted((ROOT / "tests" / "samples" / "eve").glob("*.json"))
    files += sorted((ROOT / "tests" / "samples" / "eve").glob("*.txt"))
    now = datetime.now(timezone.utc)
    for i, path in enumerate(files):
        doc = enrich.enrich(ecs_eve.normalise(path.read_text().strip()), MISP)
        stamp = now - timedelta(seconds=len(files) - i)
        doc["@timestamp"] = stamp.isoformat().replace("+00:00", "Z")
        doc["sample"] = path.name
        print(json.dumps({"index": {"_index": INDEX}}))
        print(json.dumps(doc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
