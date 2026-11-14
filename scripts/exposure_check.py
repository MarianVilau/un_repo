"""Compare what Shodan sees on the lab's public IP with the ports the lab means to expose (R-10).

Exit codes: 0 nothing unexpected, 1 unexpected port or known vulnerability, 2 setup or API error.
Settings come from the environment. The API key (SHODAN_API_KEY) is supplied by
`make exposure-check` from the SOPS file and is never printed, logged or put in an argument.

Response shape (ip_str, ports, vulns, data[].port) is taken from the Shodan host API
documentation as I remember it; it has not been checked against a live response yet.
A 404 means Shodan has no record of the address, which is reported as no exposure seen.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import urllib.parse
from typing import Any


def parse_ports(text: str) -> set[int]:
    return {int(p) for p in text.replace(" ", "").split(",") if p}


def observed(host: dict[str, Any]) -> tuple[set[int], set[str]]:
    ports = {int(p) for p in host.get("ports", [])}
    ports |= {int(d["port"]) for d in host.get("data", []) if "port" in d}
    vulns = set(host.get("vulns", []) or [])
    return ports, vulns


def compare(expected: set[int], host: dict[str, Any] | None) -> dict[str, Any]:
    ports, vulns = observed(host or {})
    return {
        "observed_ports": sorted(ports),
        "unexpected_ports": sorted(ports - expected),
        "expected_not_seen": sorted(expected - ports),
        "vulns": sorted(vulns),
        "ok": not (ports - expected) and not vulns,
    }


def fetch_host(api_host: str, ip: str, key: str) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"key": key, "minify": "false"})
    conn = http.client.HTTPSConnection(api_host, timeout=20)
    try:
        conn.request("GET", f"/shodan/host/{urllib.parse.quote(ip)}?{query}")
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    if resp.status == 404:
        return None
    if resp.status != 200:
        raise RuntimeError(f"Shodan answered HTTP {resp.status}")
    return json.loads(body)


def main() -> int:
    need = ("SHODAN_API_KEY", "SHODAN_API_HOST", "SHODAN_TARGET_IP", "SHODAN_EXPECTED_PORTS")
    missing = [n for n in need if not os.environ.get(n)]
    if missing:
        print("missing environment: " + ", ".join(missing), file=sys.stderr)
        return 2
    try:
        host = fetch_host(os.environ["SHODAN_API_HOST"], os.environ["SHODAN_TARGET_IP"], os.environ["SHODAN_API_KEY"])
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"lookup failed: {type(exc).__name__}", file=sys.stderr)  # no URL, it carries the key
        return 2
    result = compare(parse_ports(os.environ["SHODAN_EXPECTED_PORTS"]), host)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
