"""CI rules from CLAUDE.md as tests (R-06, R-07).

Static checks on every file in .github/workflows. Nothing here needs GitHub or network.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
TAG_COMMENT = re.compile(r"@[0-9a-f]{40}\s+#\s*v?\d+(\.\d+)*\S*\s*$")
UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref|inputs\.)")


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def uses_lines(path: Path) -> list[str]:
    return [
        line.split("uses:", 1)[1].strip()
        for line in path.read_text().splitlines()
        if line.strip().lstrip("- ").startswith("uses:")
    ]


def test_ci_workflow_exists() -> None:
    assert ROOT.joinpath(".github/workflows/ci.yml") in WORKFLOWS


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_third_party_actions_pinned_to_full_sha(path: Path) -> None:
    for ref in uses_lines(path):
        action = ref.split("#", 1)[0].strip()
        if action.startswith("./"):
            continue
        assert SHA_PIN.match(action), f"{path.name}: {action} is not pinned to a 40-char SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_pinned_actions_keep_the_tag_as_comment(path: Path) -> None:
    for ref in uses_lines(path):
        if ref.startswith("./"):
            continue
        assert TAG_COMMENT.search(ref), f"{path.name}: {ref} has no trailing '# vX.Y.Z' comment"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_token_starts_empty(path: Path) -> None:
    assert load(path).get("permissions") == {}, f"{path.name}: top-level permissions must be {{}}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_job_uses_write_all_or_unset_permissions(path: Path) -> None:
    for name, job in load(path)["jobs"].items():
        perms = job.get("permissions")
        assert perms is not None, f"{path.name}/{name}: job has no permissions block"
        assert perms != "write-all", f"{path.name}/{name}: write-all"


def test_write_permissions_only_in_release_job() -> None:
    ci = load(ROOT / ".github/workflows/ci.yml")
    for name, job in ci["jobs"].items():
        perms = job["permissions"]
        writes = {k for k, v in perms.items() if v == "write"} if perms else set()
        if name != "release":
            assert not writes, f"{name}: unexpected write permissions {writes}"
    assert ci["jobs"]["release"]["permissions"] == {"contents": "write", "id-token": "write"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_target(path: Path) -> None:
    on = load(path).get(True) or load(path).get("on")
    assert "pull_request_target" not in on


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_run_blocks_do_not_expand_untrusted_input(path: Path) -> None:
    for name, job in load(path)["jobs"].items():
        for step in job.get("steps", []):
            run = step.get("run", "")
            assert not UNTRUSTED.search(run), f"{path.name}/{name}: untrusted expression in run"


def test_ci_runs_the_required_tools() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    for needle in ("shellcheck", "hadolint/hadolint-action", "semgrep scan", "trivy-action",
                   "pytest", "anchore/sbom-action", "cosign sign-blob", "cosign verify-blob"):
        assert needle in text, f"ci.yml is missing {needle}"


def test_ci_gate_depends_on_every_check_job() -> None:
    jobs = load(ROOT / ".github/workflows/ci.yml")["jobs"]
    checks = set(jobs) - {"ci-gate", "release"}
    assert set(jobs["ci-gate"]["needs"]) == checks


def test_requirements_are_pinned_exactly() -> None:
    for name in ("requirements-dev.txt", "requirements-semgrep.txt"):
        for line in (ROOT / name).read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                assert "==" in line, f"{name}: {line} is not pinned with =="
