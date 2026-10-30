"""A deliberately small, dependency-free DSL evaluator.

Nuclei's DSL is large. The runner supports the flat boolean subset that covers
most content checks and nothing else; anything outside it raises
``UnsupportedMatcher`` so the result is reported as an error instead of a
silent false pass. Parentheses are not supported.
"""
from __future__ import annotations

import re
import shlex
from typing import List

from ..schema import SUPPORTED_DSL_FUNCTIONS


class UnsupportedMatcher(Exception):
    """The engine cannot evaluate this matcher faithfully."""


_STATUS_RE = re.compile(r"^status_code\s*(==|!=)\s*(\d{3})$")
_LEN_RE = re.compile(r"^len\(body\)\s*(>=|<=|==|>|<)\s*(\d+)$")
_FUNC_RE = re.compile(r"^([a-z_]+)\s*\((.*)\)$", re.IGNORECASE)

_COMPARATORS = {
    "==": lambda left, right: left == right,
    "!=": lambda left, right: left != right,
    ">": lambda left, right: left > right,
    "<": lambda left, right: left < right,
    ">=": lambda left, right: left >= right,
    "<=": lambda left, right: left <= right,
}


def evaluate(expression: str, *, status: int, body: str) -> bool:
    """Evaluate ``expression`` against a response. Raises on unsupported syntax."""
    expression = expression.strip()
    if not expression:
        raise UnsupportedMatcher("empty DSL expression")
    for separator in ("||", "&&"):
        if separator in expression:
            parts = [part for part in expression.split(separator) if part.strip()]
            if not parts:
                raise UnsupportedMatcher(f"empty clause in DSL expression {expression!r}")
            results = [evaluate(part, status=status, body=body) for part in parts]
            return all(results) if separator == "&&" else any(results)
    return _atom(expression, status=status, body=body)


def _atom(expression: str, *, status: int, body: str) -> bool:
    if expression == "true":
        return True
    if expression == "false":
        return False

    match = _STATUS_RE.match(expression)
    if match:
        expected = int(match.group(2))
        return status == expected if match.group(1) == "==" else status != expected

    match = _LEN_RE.match(expression)
    if match:
        return _COMPARATORS[match.group(1)](len(body), int(match.group(2)))

    match = _FUNC_RE.match(expression)
    if not match:
        raise UnsupportedMatcher(f"unsupported DSL expression: {expression!r}")
    name = match.group(1).lower()
    if name not in SUPPORTED_DSL_FUNCTIONS:
        raise UnsupportedMatcher(f"unsupported DSL function: {name}()")
    arguments = _arguments(match.group(2))
    if not arguments:
        raise UnsupportedMatcher(f"{name}() needs at least one argument")
    target = arguments[-1].lower() if name != "regex" else ""
    if name in {"contains", "contains_all", "contains_any"}:
        if arguments[0].lower() != "body":
            raise UnsupportedMatcher(f"{name}() only supports body as its first argument")
        values = arguments[1:]
        if not values:
            raise UnsupportedMatcher(f"{name}() needs a value to look for")
        if name == "contains":
            return values[0] in body
        found = [value in body for value in values]
        return all(found) if name == "contains_all" else any(found)
    if name == "regex":
        if len(arguments) == 1:
            pattern, target = arguments[0], "body"
        elif len(arguments) == 2:
            pattern, target = arguments[0], arguments[1].lower()
        else:
            raise UnsupportedMatcher("regex() takes one or two arguments")
        if target != "body":
            raise UnsupportedMatcher("regex() only supports body")
        return re.search(pattern, body) is not None
    raise UnsupportedMatcher(f"unsupported DSL function: {name}()")


def _arguments(raw: str) -> List[str]:
    """Split ``body, 'a b', "c"`` on commas that are outside quotes."""
    parts: List[str] = []
    current: List[str] = []
    quote = ""
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            if char == "\\" and index + 1 < len(raw):
                current.append(char)
                current.append(raw[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
            current.append(char)
        elif char in "\"'":
            quote = char
            current.append(char)
        elif char == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    if quote:
        raise UnsupportedMatcher("unterminated quote in DSL arguments")
    parts.append("".join(current))

    arguments: List[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError as exc:
            raise UnsupportedMatcher(f"cannot parse DSL argument {part!r}: {exc}") from exc
        if len(tokens) > 1:
            raise UnsupportedMatcher(f"ambiguous DSL argument {part!r}")
        if tokens:
            arguments.append(tokens[0])
    return arguments
