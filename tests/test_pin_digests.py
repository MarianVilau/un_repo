"""Unit tests for scripts/pin_digests.py. The resolver is stubbed, Docker is not used."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import pin_digests  # noqa: E402

ZERO = "0" * 64
FAKE = "ab" * 32


def fake_resolver(repo: str, tag: str) -> str:
    return FAKE


def test_placeholder_is_replaced_and_tag_comment_kept() -> None:
    src = f"    image: nginx@sha256:{ZERO}  # 1.27-alpine\n"
    out = pin_digests.pin_text(src, fake_resolver)
    assert out == f"    image: nginx@sha256:{FAKE}  # 1.27-alpine\n"


def test_other_lines_are_untouched() -> None:
    src = "services:\n  a:\n    ports:\n      - \"127.0.0.1:${P}:80\"\n"
    assert pin_digests.pin_text(src, fake_resolver) == src


def test_resolver_gets_repo_and_tag() -> None:
    seen: list[tuple[str, str]] = []

    def spy(repo: str, tag: str) -> str:
        seen.append((repo, tag))
        return FAKE

    pin_digests.pin_text(f"image: opensearchproject/opensearch@sha256:{ZERO}  # 2.19.1\n", spy)
    assert seen == [("opensearchproject/opensearch", "2.19.1")]


def test_line_without_tag_comment_is_not_rewritten() -> None:
    src = f"image: nginx@sha256:{ZERO}\n"
    assert pin_digests.pin_text(src, fake_resolver) == src
