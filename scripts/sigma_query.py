"""Print the OpenSearch (Lucene) query pySigma generates for each rule (R-07)."""

from __future__ import annotations

from pathlib import Path

from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection

RULES = Path(__file__).resolve().parent.parent / "detections" / "sigma"


def main() -> int:
    backend = OpensearchLuceneBackend()
    for path in sorted(RULES.glob("*.yml")):
        rules = SigmaCollection.from_yaml(path.read_text())
        for query in backend.convert(rules):
            print(f"# {path.name}")
            print(query)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
