"""Build the Logstash translate dictionary from MISP indicators (R-09).

Pulls IP indicators from MISP with PyMISP and writes a YAML dictionary,
`<ip>: misp`, that pipelines/eve/30-enrich.conf reads. Only attributes flagged for
detection (to_ids), from published events, and not on a warninglist, are kept.
Private, loopback and unparsable addresses are dropped, so a feed mistake cannot tag
the lab's own hosts.

The API key is read from the environment (MISP_KEY). `make misp-dictionary` sets it from
the SOPS file for the duration of one command. It is never a command argument.

PyMISP is imported only when fetching, so the pure functions test without it.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

IP_TYPES = ["ip-src", "ip-dst"]
PROVIDER = "misp"


# Ranges that must never become indicators: the lab's own addresses and non-routable space.
# The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are deliberately
# allowed, because the test samples and the lab demo use them as stand-ins for attackers.
BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


def public_ip(value: object) -> str | None:
    """Return the normalised address if it may be an indicator, else None."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if any(addr.version == net.version and addr in net for net in BLOCKED):
        return None
    return str(addr)


def extract_ips(attributes: Iterable[dict[str, Any]]) -> set[str]:
    """Pick usable IPs from MISP attribute dicts (the `Attribute` list of a search)."""
    found: set[str] = set()
    for attr in attributes:
        if attr.get("type") not in IP_TYPES:
            continue
        if not attr.get("to_ids"):
            continue
        ip = public_ip(attr.get("value"))
        if ip:
            found.add(ip)
    return found


def dictionary_text(ips: Iterable[str]) -> str:
    """YAML for the translate filter. Sorted so a rerun gives a stable diff."""
    return yaml.safe_dump({ip: PROVIDER for ip in sorted(ips)}, default_flow_style=False, sort_keys=False)


def write_dictionary(ips: Iterable[str], path: Path) -> int:
    ips = list(ips)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(dictionary_text(ips))
    tmp.replace(path)  # Logstash never reads a half-written file
    return len(ips)


def fetch_attributes(url: str, key: str, verify: bool, last: str = "30d") -> list[dict[str, Any]]:
    from pymisp import PyMISP  # type: ignore[import-not-found]

    misp = PyMISP(url, key, ssl=verify)
    result = misp.search(
        controller="attributes",
        type_attribute=IP_TYPES,
        to_ids=True,
        published=True,
        last=last,
        enforce_warninglist=True,
        pythonify=False,
    )
    return result.get("Attribute", []) if isinstance(result, dict) else []


def main() -> int:
    key = os.environ.get("MISP_KEY", "")
    url = os.environ.get("MISP_URL", "")
    out = os.environ.get("MISP_DICTIONARY_PATH", "")
    if not (key and url and out):
        print("MISP_KEY, MISP_URL and MISP_DICTIONARY_PATH must be set", file=sys.stderr)
        return 2
    verify = os.environ.get("MISP_VERIFY_TLS", "true").lower() != "false"
    ips = extract_ips(fetch_attributes(url, key, verify, os.environ.get("MISP_LAST", "30d")))
    count = write_dictionary(ips, Path(out))
    print(f"wrote {count} indicators to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
