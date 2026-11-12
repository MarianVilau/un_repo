"""A small evaluator for the Sigma subset these rules use (R-07).

It lets pytest assert match and no-match without OpenSearch. It supports field lists (OR),
several fields in one selection (AND), the modifiers contains, startswith, endswith and re,
and conditions built from selection names with and, or, not and parentheses.

Anything else raises NotImplementedError, so a rule that grows past this subset fails the
tests loudly instead of silently never matching. Sigma strings match case-insensitively.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from detections.ecs_eve import get_path

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re"}
TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def load_rule(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text())


def _match_value(modifier: str | None, actual: Any, expected: Any) -> bool:
    if actual is None:
        return False
    if modifier == "re":
        return re.search(str(expected), str(actual)) is not None
    if isinstance(expected, str) or isinstance(actual, str):
        a, e = str(actual).lower(), str(expected).lower()
        if modifier == "contains":
            return e in a
        if modifier == "startswith":
            return a.startswith(e)
        if modifier == "endswith":
            return a.endswith(e)
        return a == e
    return actual == expected


def _selection_matches(selection: Any, event: dict[str, Any]) -> bool:
    if not isinstance(selection, dict):
        raise NotImplementedError("only mapping selections are supported")
    for key, expected in selection.items():
        field, *modifiers = key.split("|")
        unknown = set(modifiers) - SUPPORTED_MODIFIERS
        if unknown or len(modifiers) > 1:
            raise NotImplementedError(f"modifier not supported: {modifiers}")
        modifier = modifiers[0] if modifiers else None
        values = expected if isinstance(expected, list) else [expected]
        actual = get_path(event, field)
        if not any(_match_value(modifier, actual, v) for v in values):
            return False
    return True


class _Condition:
    """Recursive descent parser for: or > and > not > name | ( or )."""

    def __init__(self, text: str, results: dict[str, bool]) -> None:
        self.tokens = TOKEN.findall(text)
        if "".join(self.tokens).replace("|", "") != re.sub(r"\s+", "", text):
            raise NotImplementedError(f"condition not supported: {text!r}")
        self.pos = 0
        self.results = results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self) -> bool:
        value = self._or()
        if self._peek() is not None:
            raise NotImplementedError("unexpected token in condition")
        return value

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._take()
            value = self._and() or value
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._take()
            value = self._not() and value
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._take()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._take()
        if token == "(":
            value = self._or()
            if self._take() != ")":
                raise NotImplementedError("missing closing parenthesis")
            return value
        if token in {"of", "all", "1"} or "*" in token:
            raise NotImplementedError(f"condition not supported: {token}")
        if token not in self.results:
            raise KeyError(f"condition names an unknown selection: {token}")
        return self.results[token]


def matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = dict(rule["detection"])
    condition = detection.pop("condition")
    detection.pop("timeframe", None)
    results = {name: _selection_matches(sel, event) for name, sel in detection.items()}
    return _Condition(condition, results).parse()
