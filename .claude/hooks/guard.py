#!/usr/bin/env python3
"""PreToolUse guard for Claude Code (R-01, R-02, R-03, R-05).

Why a hook and not a line in CLAUDE.md: prose persuades the model, a hook
compels it. Exit code 2 blocks the tool call and shows the reason to the
agent. A JSON reply with permissionDecision "ask" makes the human confirm.
"""
import json
import re
import shlex
import subprocess
import sys

PROTECTED_BRANCHES = {"main", "master"}

# Edits here are refused outright: the agent must not weaken its own guard.
DENY_WRITE = (
    r"^\.claude/settings(\.local)?\.json$",
    r"^\.claude/hooks/",
)
# Edits here need a human to confirm: this is where context poisoning lands (R-05).
ASK_WRITE = (
    r"^CLAUDE\.md$",
    r"(^|/)CLAUDE\.md$",
    r"^\.claude/memory/",
    r"^\.claude/skills/",
    r"^\.github/",
    r"^\.pre-commit-config\.yaml$",
    r"^\.gitleaks\.toml$",
)
SECRET_PATHS = (".env.secrets", "age/keys.txt", "certs/")


def current_branch():
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def split_commands(command):
    """Split a shell line on ; && || | so each git call is judged on its own."""
    return [part.strip() for part in re.split(r"&&|\|\||;|\|", command) if part.strip()]


def check_git(tokens, branch):
    """Return a reason string when the git call must be blocked, else None."""
    if len(tokens) < 2 or tokens[0] != "git":
        return None
    sub = next((t for t in tokens[1:] if not t.startswith("-")), "")
    flags = [t for t in tokens if t.startswith("-")]
    args = [t for t in tokens[tokens.index(sub) + 1:] if not t.startswith("-")] if sub else []

    if "--no-verify" in flags or (
        sub == "commit" and any(re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", f) for f in flags)
    ):
        return "R-02: --no-verify skips the gitleaks hook."

    if sub == "push":
        if any(f in ("--force", "-f", "--force-with-lease", "--delete", "-d") or
               f.startswith("--force-with-lease=") for f in flags):
            return "R-03: force push or remote deletion rewrites history. Ask the owner."
        if any(a.startswith("+") for a in args):
            return "R-03: a '+' refspec is a force push."
        if any(a.startswith(":") for a in args):
            return "R-03: an empty-source refspec deletes the remote branch."
        targets = {a.split(":")[-1].replace("refs/heads/", "") for a in args}
        if targets & PROTECTED_BRANCHES:
            return "R-01: main only accepts pull requests."
        if not args and branch in PROTECTED_BRANCHES:
            return "R-01: current branch is protected, push a feature branch."

    if sub == "commit" and branch in PROTECTED_BRANCHES:
        return "R-01: do not commit on a protected branch, create a branch first."
    return None


def check_bash(command, branch):
    for part in split_commands(command):
        try:
            tokens = shlex.split(part)
        except ValueError:
            tokens = part.split()
        reason = check_git(tokens, branch)
        if reason:
            return "deny", reason
        if tokens and tokens[0] != "make" and any(p in part for p in SECRET_PATHS):
            return "deny", "R-02: secrets and key material are read by make targets only."
    return None


def check_write(path):
    rel = path.replace("\\", "/")
    marker = "/.claude/"
    if marker in rel:
        rel = ".claude/" + rel.split(marker, 1)[1]
    rel = re.sub(r"^\./", "", rel)
    for pattern in DENY_WRITE:
        if re.search(pattern, rel):
            return "deny", "R-05: the guard and its settings are edited by the owner, not the agent."
    for pattern in ASK_WRITE:
        if re.search(pattern, rel):
            return "ask", "R-05: AI configuration and controls change only after a human reads the diff."
    return None


def decide(tool_name, tool_input, branch):
    if tool_name == "Bash":
        return check_bash(tool_input.get("command", ""), branch)
    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        return check_write(tool_input.get("file_path", ""))
    return None


def main():
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    result = decide(event.get("tool_name", ""), event.get("tool_input", {}), current_branch())
    if not result:
        return 0
    verdict, reason = result
    if verdict == "deny":
        print(f"Blocked by .claude/hooks/guard.py. {reason}", file=sys.stderr)
        return 2
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
