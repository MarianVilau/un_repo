"""The decrypted key must be exported to the child process (R-02, R-09, R-10).

`eval` of the decrypted line only sets a shell variable. With `set +a` before it, python
never sees the key and the target fails with "missing environment". Found on the first
live run of `make exposure-check`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("misp-dictionary", "exposure-check")


def recipe(target: str) -> str:
    text = (ROOT / "Makefile").read_text()
    match = re.search(rf"^{target}:.*?\n((?:\t.*\n)+)", text, re.M)
    assert match, target
    return match.group(1)


def test_set_plus_a_comes_after_the_eval_of_the_secret() -> None:
    for target in TARGETS:
        body = recipe(target)
        assert body.index("eval") < body.rindex("set +a"), target


def test_decrypted_value_reaches_the_child_process(tmp_path: Path) -> None:
    body = recipe("exposure-check").replace("$$", "$")
    body = body.replace("\\\n", "").replace("\t", " ")
    body = body.replace("python3 scripts/exposure_check.py", 'printenv SHODAN_API_KEY')
    body = re.sub(r"sops -d secrets/shodan\.enc\.yaml", "echo 'SHODAN_API_KEY: test-value'", body)
    (tmp_path / ".env").write_text("SHODAN_API_HOST=api.shodan.io\n")
    out = subprocess.run(["bash", "-c", body], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert out.stdout.strip() == "test-value", out.stderr
