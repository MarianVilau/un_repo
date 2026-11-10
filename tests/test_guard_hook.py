"""Positive and negative samples for the PreToolUse guard (R-01, R-02, R-03, R-05)."""
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

HOOK = pathlib.Path(__file__).resolve().parents[1] / ".claude" / "hooks" / "guard.py"
spec = importlib.util.spec_from_file_location("guard", HOOK)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def bash(cmd, branch="s2/ai-config"):
    return guard.decide("Bash", {"command": cmd}, branch)


@pytest.mark.parametrize("cmd", [
    "git push --force origin s2/ai-config",
    "git push -f",
    "git push --force-with-lease origin HEAD",
    "git push origin +HEAD:feature",
    "git push origin :old-branch",
    "git push --delete origin old-branch",
])
def test_force_push_and_deletion_are_denied(cmd):
    verdict, reason = bash(cmd)
    assert verdict == "deny" and "R-03" in reason


@pytest.mark.parametrize("cmd", [
    "git push origin main",
    "git push origin HEAD:main",
    "git push origin HEAD:refs/heads/master",
])
def test_push_to_protected_branch_is_denied(cmd):
    verdict, reason = bash(cmd)
    assert verdict == "deny" and "R-01" in reason


def test_bare_push_on_main_is_denied_but_fine_on_feature_branch():
    assert bash("git push", branch="main")[0] == "deny"
    assert bash("git push", branch="s2/ai-config") is None


def test_commit_on_protected_branch_is_denied():
    assert bash("git commit -m x", branch="main")[0] == "deny"
    assert bash("git commit -m x", branch="s2/ai-config") is None


@pytest.mark.parametrize("cmd", [
    "git commit --no-verify -m x",
    "git commit -n -m x",
    "git push --no-verify origin s2/ai-config",
])
def test_no_verify_is_denied(cmd):
    verdict, reason = bash(cmd)
    assert verdict == "deny" and "R-02" in reason


def test_chained_command_is_judged_per_part():
    assert bash("git add . && git push -f origin x")[0] == "deny"


@pytest.mark.parametrize("cmd", [
    "git status",
    "git switch -c s3/iaas",
    "git push -u origin s2/ai-config",
    "git commit -m 'feat: add hook (R-05)'",
    "pytest -n 2",
    "bash scripts/check.sh",
])
def test_ordinary_commands_pass(cmd):
    assert bash(cmd) is None


def test_secret_files_are_read_through_make_only():
    assert bash("cat .env.secrets")[0] == "deny"
    assert bash("cat ~/.config/sops/age/keys.txt")[0] == "deny"
    assert bash("make secrets") is None


@pytest.mark.parametrize("path", [".claude/settings.json", ".claude/hooks/guard.py",
                                  "/work/un_repo/.claude/hooks/guard.py"])
def test_guard_and_settings_cannot_be_edited_by_agent(path):
    assert guard.decide("Edit", {"file_path": path}, "x")[0] == "deny"


@pytest.mark.parametrize("path", ["CLAUDE.md", "pipelines/CLAUDE.md", ".claude/memory/MEMORY.md",
                                  ".claude/skills/check-and-test/SKILL.md",
                                  ".github/workflows/governance.yml", ".pre-commit-config.yaml"])
def test_ai_config_and_controls_need_human_confirmation(path):
    assert guard.decide("Write", {"file_path": path}, "x")[0] == "ask"


def test_ordinary_file_edit_passes():
    assert guard.decide("Edit", {"file_path": "pipelines/enrich.conf"}, "x") is None


def run_hook(payload):
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                          capture_output=True, text=True, check=False)


def test_hook_exit_code_2_blocks_with_reason_on_stderr():
    proc = run_hook({"tool_name": "Bash", "tool_input": {"command": "git push --force"}})
    assert proc.returncode == 2 and "R-03" in proc.stderr


def test_hook_asks_with_json_for_memory_edit():
    proc = run_hook({"tool_name": "Write", "tool_input": {"file_path": ".claude/memory/x.md"}})
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
