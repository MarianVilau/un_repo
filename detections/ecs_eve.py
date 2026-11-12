"""Reference mapping from an EVE JSON line to Elastic Common Schema fields (R-07).

This mirrors pipelines/eve/20-normalise.conf for the fields below. It exists so the rules can
be tested without a running Logstash, and so scripts/load_samples.py can load samples into
OpenSearch. tests/test_eve_pipeline.py fails if the two mappings drift apart.

Only mapped fields are modelled. Logstash also keeps the unmapped rest under [eve].
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

# EVE path (without the leading [eve]) -> ECS path. Keep in sync with 20-normalise.conf.
RENAMES: dict[str, str] = {
    "src_ip": "source.ip",
    "src_port": "source.port",
    "dest_ip": "destination.ip",
    "dest_port": "destination.port",
    "proto": "network.transport",
    "alert.signature_id": "rule.id",
    "alert.signature": "rule.name",
    "alert.category": "rule.category",
    "alert.severity": "event.severity",
    "http.hostname": "url.domain",
    "http.url": "url.original",
    "http.http_user_agent": "user_agent.original",
    "http.http_method": "http.request.method",
    "http.status": "http.response.status_code",
}

DEFAULT_MAX_LINE_BYTES = 16384


def get_path(data: dict[str, Any], path: str) -> Any:
    """Return the value at a dotted path, or None when any part is missing."""
    node: Any = data
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def set_path(data: dict[str, Any], path: str, value: Any) -> None:
    node = data
    parts = path.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def _failure(line: str, *tags: str) -> dict[str, Any]:
    return {"message": line, "tags": ["_parse_failure", *tags]}


def normalise(line: str, max_bytes: int = DEFAULT_MAX_LINE_BYTES) -> dict[str, Any]:
    """Turn one EVE line into an ECS event. A bad line is kept and tagged, never dropped."""
    if len(line.encode("utf-8")) > max_bytes:
        return _failure(line, "_oversized")
    try:
        raw = json.loads(line)
    except ValueError:
        return _failure(line)
    if not isinstance(raw, dict):
        return _failure(line)

    event: dict[str, Any] = {"message": line}
    stamp = raw.get("timestamp")
    if isinstance(stamp, str):
        try:
            parsed = datetime.fromisoformat(stamp).astimezone(timezone.utc)
            event["@timestamp"] = parsed.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    if isinstance(raw.get("proto"), str):
        raw["proto"] = raw["proto"].lower()
    for source, target in RENAMES.items():
        value = get_path(raw, source)
        if value is not None:
            set_path(event, target, value)

    event_type = raw.get("event_type", "unknown")
    set_path(event, "event.module", "eve")
    set_path(event, "event.dataset", f"eve.{event_type}")
    if event_type == "alert":
        set_path(event, "event.kind", "alert")
        set_path(event, "event.category", "network")
    return event
