"""Evaluate a request's matchers against a response.

The same normalized matcher objects produced by the loader are used here, so a
Nuclei template and a native template are judged by identical code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence, Tuple

from ..schema import SUPPORTED_MATCHER_TYPES, Matcher
from .dsl import UnsupportedMatcher
from .dsl import evaluate as evaluate_dsl

EVIDENCE_WINDOW = 100
MAX_EVIDENCE = 4000


@dataclass(frozen=True)
class MatchOutcome:
    matched: bool
    matched_by: str = ""
    evidence: str = ""


def evaluate(
    matchers: Sequence[Matcher],
    condition: str,
    *,
    status: int,
    body: str,
    headers: str,
) -> MatchOutcome:
    """Combine matchers with the request's and/or condition."""
    if not matchers:
        return MatchOutcome(False)

    outcomes = []
    for matcher in matchers:
        matched, evidence = _evaluate_one(matcher, status=status, body=body, headers=headers)
        if matcher.negative:
            matched = not matched
            evidence = "" if matched else evidence
        outcomes.append((matched, matcher.type, evidence))

    if condition == "and":
        if all(matched for matched, _, _ in outcomes):
            evidence = "\n---\n".join(text for matched, _, text in outcomes if text)
            return MatchOutcome(True, "and", _cap(evidence))
        return MatchOutcome(False)

    for matched, kind, evidence in outcomes:
        if matched:
            return MatchOutcome(True, kind, _cap(evidence))
    return MatchOutcome(False)


def _evaluate_one(
    matcher: Matcher,
    *,
    status: int,
    body: str,
    headers: str,
) -> Tuple[bool, str]:
    if matcher.type not in SUPPORTED_MATCHER_TYPES:
        raise UnsupportedMatcher(f"matcher type '{matcher.type}' is not supported")

    if matcher.type == "status":
        expected = set()
        for value in matcher.values:
            try:
                expected.add(int(str(value).strip()))
            except ValueError as exc:
                raise UnsupportedMatcher(f"status matcher value {value!r} is not an integer") from exc
        if not expected:
            raise UnsupportedMatcher("status matcher has no values")
        return status in expected, f"HTTP {status}"

    if matcher.type == "size":
        length = len(body)
        matched = False
        for value in matcher.values:
            matched = matched or _compare_size(str(value), length)
        return matched, f"body is {length} bytes"

    if matcher.type == "dsl":
        matched, evidence = _evaluate_dsl(matcher, status=status, body=body)
        return matched, evidence

    haystack = _haystack(matcher.part, body, headers)

    if matcher.type == "word":
        found = [(word, haystack.find(word)) for word in matcher.values]
        if matcher.condition == "and":
            if all(position >= 0 for _, position in found):
                evidence = "\n---\n".join(_snippet(haystack, position, len(word)) for word, position in found)
                return True, evidence
            return False, ""
        for word, position in found:
            if position >= 0:
                return True, _snippet(haystack, position, len(word))
        return False, ""

    if matcher.type == "regex":
        matches = []
        for pattern in matcher.values:
            try:
                regex = re.compile(pattern)
            except re.error as exc:
                raise UnsupportedMatcher(f"regex {pattern!r} does not compile: {exc}") from exc
            match = regex.search(haystack)
            if match is None:
                if matcher.condition == "and":
                    return False, ""
                continue
            matches.append(match.group(0))
        if not matches:
            return False, ""
        return True, "\n---\n".join(matches)

    raise UnsupportedMatcher(f"matcher type '{matcher.type}' is not supported")


def _evaluate_dsl(matcher: Matcher, *, status: int, body: str) -> Tuple[bool, str]:
    found = []
    for expression in matcher.values:
        matched = evaluate_dsl(expression, status=status, body=body)
        found.append((matched, expression))
    if matcher.condition == "and":
        if all(matched for matched, _ in found):
            return True, "\n---\n".join(expression for _, expression in found)
        return False, ""
    for matched, expression in found:
        if matched:
            return True, expression
    return False, ""


def _haystack(part: str, body: str, headers: str) -> str:
    if part in ("header", "headers"):
        return headers
    if part in ("all", "raw"):
        return body + "\r\n" + headers
    return body


def _compare_size(value: str, length: int) -> bool:
    value = value.strip()
    match = re.match(r"^(>=|<=|==|>|<)?\s*(\d+)$", value)
    if not match:
        raise UnsupportedMatcher(f"size matcher value {value!r} is not a size")
    operator = match.group(1) or "=="
    expected = int(match.group(2))
    if operator == "==":
        return length == expected
    if operator == ">":
        return length > expected
    if operator == "<":
        return length < expected
    if operator == ">=":
        return length >= expected
    return length <= expected


def _snippet(haystack: str, position: int, length: int) -> str:
    start = max(0, position - EVIDENCE_WINDOW)
    end = min(len(haystack), position + length + EVIDENCE_WINDOW)
    return haystack[start:end]


def _cap(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE else text[:MAX_EVIDENCE] + "\n... (evidence truncated)"
