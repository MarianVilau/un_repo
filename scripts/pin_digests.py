"""Replace placeholder image digests in a Compose file with digests resolved by Docker.

Each image line must look like `image: repo@sha256:<64 hex>  # <tag>`. The trailing comment
is the tag to resolve. The script pulls repo:tag, reads the repo digest and rewrites the
line. Nothing is invented: if Docker cannot resolve a digest, the script stops (R-08).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

IMAGE_LINE = re.compile(
    r"^(?P<head>\s*image:\s*)(?P<repo>[^@\s]+)@sha256:(?P<digest>[0-9a-f]{64})"
    r"(?P<gap>\s+#\s*)(?P<tag>\S+)\s*$"
)


def resolve_digest(repo: str, tag: str) -> str:
    """Pull repo:tag and return the sha256 digest Docker recorded for it."""
    ref = f"{repo}:{tag}"
    subprocess.run(["docker", "pull", "--quiet", ref], check=True, stdout=subprocess.DEVNULL)
    out = subprocess.run(
        ["docker", "image", "inspect", ref, "--format", "{{range .RepoDigests}}{{println .}}{{end}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in out.splitlines():
        name, _, digest = line.partition("@sha256:")
        if digest and (name == repo or name.endswith("/" + repo) or repo.endswith("/" + name)):
            return digest
    raise RuntimeError(f"no repo digest for {ref}")


def pin_text(text: str, resolver=resolve_digest) -> str:
    """Return text with every matching image line rewritten to the resolved digest."""
    lines = []
    for line in text.splitlines():
        m = IMAGE_LINE.match(line)
        if m:
            digest = resolver(m["repo"], m["tag"])
            line = f"{m['head']}{m['repo']}@sha256:{digest}{m['gap']}{m['tag']}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: pin_digests.py compose.yaml", file=sys.stderr)
        return 2
    path = Path(argv[1])
    path.write_text(pin_text(path.read_text()))
    print(f"pinned digests in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
