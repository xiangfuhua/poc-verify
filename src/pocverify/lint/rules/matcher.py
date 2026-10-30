"""PG-005: weak matchers.

The most common cause of false positives is not a wrong payload, it is a
matcher that any healthy response satisfies: ``status: 200`` alone, ``.*`` as a
regex, a one-letter word, or only negative conditions.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Sequence, Set

from ...schema import (
    SUPPORTED_DSL_FUNCTIONS,
    SUPPORTED_MATCHER_TYPES,
    Finding,
    Matcher,
    RuleMeta,
    Severity,
    Template,
    make_finding,
)
from .base import Rule, request_line, request_prefix

RULE_ID = "PG-005"
MIN_WORD_LENGTH = 3
MIN_REGEX_LITERALS = 3
UBIQUITOUS_WORDS = {
    "error",
    "true",
    "false",
    "success",
    "admin",
    "root",
    "login",
    "welcome",
}
_STATUS_ONLY_DSL = re.compile(r"^status_code\s*==\s*200$", re.IGNORECASE)
_DSL_FUNCTION_RE = re.compile(r"([a-z_]+)\s*\(", re.IGNORECASE)


class MatcherRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Weak matchers",
        description=(
            "Rejects requests without matchers, status-only matches (especially 200), "
            "regexes with too few literals, one-character or ubiquitous words, "
            "negative-only conditions, mutually exclusive AND conditions, and matcher "
            "types the runner cannot evaluate."
        ),
        default_severity=Severity.HIGH,
        help_anchor="pg-005-weak-matchers",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        findings: List[Finding] = []

        def add(severity: Severity, message: str, line, hint: str = "") -> None:
            findings.append(make_finding(RULE_ID, severity, message, template, line, hint))

        if not template.requests:
            add(
                Severity.HIGH,
                "template defines no request, so it can never produce evidence",
                template.line_at("http") or template.line_at("requests") or 1,
            )
            return findings

        for request in template.requests:
            prefix = request_prefix(template, request.index)
            line = request_line(template, request.index)
            matchers = request.matchers
            if not matchers:
                add(
                    Severity.HIGH,
                    "request has no matchers; any response would be reported as a vulnerability",
                    line,
                    "add at least one content matcher (word or regex)",
                )
                continue

            for index, matcher in enumerate(matchers):
                matcher_line = template.line_at(*prefix, "matchers", index) or line
                self._check_matcher(matcher, matcher_line, add)
            block_line = template.line_at(*prefix, "matchers") or line
            self._check_status_only(matchers, block_line, add)
            self._check_negatives(matchers, block_line, add)
            self._check_and_condition(matchers, request.matcher_condition, block_line, add)
            self._check_size_only(matchers, block_line, add)
        return findings

    # -- individual checks -------------------------------------------------
    def _check_matcher(self, matcher: Matcher, line, add) -> None:
        if matcher.type not in SUPPORTED_MATCHER_TYPES:
            add(
                Severity.HIGH,
                f"matcher type '{matcher.type}' is not supported by the runner; "
                "a match would be unverified",
                line,
                "rewrite it with status/word/regex/size/dsl, or verify the template manually",
            )
            return
        if not matcher.values:
            add(Severity.HIGH, f"matcher type '{matcher.type}' has no values", line)
            return
        if matcher.type == "word":
            for word in matcher.values:
                stripped = word.strip()
                if len(stripped) < MIN_WORD_LENGTH:
                    add(
                        Severity.MEDIUM,
                        f"word matcher {stripped!r} is shorter than {MIN_WORD_LENGTH} characters",
                        line,
                        "short words match almost every page; include surrounding context",
                    )
                elif stripped.lower() in UBIQUITOUS_WORDS:
                    add(
                        Severity.MEDIUM,
                        f"word matcher {stripped!r} appears on most pages",
                        line,
                        "match a product-specific marker instead",
                    )
        elif matcher.type == "regex":
            for pattern in matcher.values:
                literals = _literal_characters(pattern)
                if literals < MIN_REGEX_LITERALS:
                    add(
                        Severity.HIGH,
                        f"regex {pattern!r} has only {literals} literal characters",
                        line,
                        "anchor the regex on a product-specific string",
                    )
                try:
                    re.compile(pattern)
                except re.error as exc:
                    add(Severity.HIGH, f"regex {pattern!r} does not compile: {exc}", line)
        elif matcher.type == "dsl":
            for expression in matcher.values:
                if _STATUS_ONLY_DSL.match(expression.strip()):
                    add(
                        Severity.HIGH,
                        "DSL matcher only checks for status 200",
                        line,
                        "add a content assertion such as contains(body, '...')",
                    )
                functions = {name.lower() for name in _DSL_FUNCTION_RE.findall(expression)}
                unknown = functions - SUPPORTED_DSL_FUNCTIONS - {"len"}
                if unknown:
                    add(
                        Severity.MEDIUM,
                        f"DSL function(s) {', '.join(sorted(unknown))} are not supported "
                        "by the runner",
                        line,
                        "use contains/contains_all/contains_any/regex or a word matcher",
                    )

    def _check_status_only(self, matchers: Sequence[Matcher], line, add) -> None:
        if any(matcher.type != "status" for matcher in matchers):
            return
        values = _status_values(matchers)
        if not values:
            add(Severity.HIGH, "status matcher declares no status codes", line)
        elif values == {"200"}:
            add(
                Severity.HIGH,
                "status-only matcher accepts every 200 response; this is a false positive generator",
                line,
                "require a body marker that only the vulnerable endpoint returns",
            )
        else:
            add(
                Severity.MEDIUM,
                f"request matches only on status code(s) {', '.join(sorted(values))}",
                line,
                "combine the status check with a content matcher",
            )

    def _check_negatives(self, matchers: Sequence[Matcher], line, add) -> None:
        if matchers and all(matcher.negative for matcher in matchers):
            add(
                Severity.HIGH,
                "every matcher is negative, so almost any response matches",
                line,
                "add a positive assertion that proves the vulnerability",
            )

    def _check_size_only(self, matchers: Sequence[Matcher], line, add) -> None:
        if len(matchers) == 1 and matchers[0].type == "size":
            add(
                Severity.LOW,
                "size-only matcher is brittle: unrelated pages can share the same length",
                line,
                "anchor on a content marker instead",
            )

    def _check_and_condition(
        self, matchers: Sequence[Matcher], condition: str, line, add
    ) -> None:
        status_matchers = [matcher for matcher in matchers if matcher.type == "status" and not matcher.negative]
        if condition != "and" or len(status_matchers) < 2:
            return
        value_sets = [_status_values([matcher]) for matcher in status_matchers]
        if any(len(values) != 1 for values in value_sets):
            return
        if len(set().union(*value_sets)) > 1:
            add(
                Severity.HIGH,
                "AND condition requires mutually exclusive status codes, so it cannot match",
                line,
            )


def _status_values(matchers: Sequence[Matcher]) -> Set[str]:
    values: Set[str] = set()
    for matcher in matchers:
        for value in matcher.values:
            values.add(value.strip())
    return values


def _literal_characters(pattern: str) -> int:
    """Count characters a regex must match literally (rough but useful)."""
    unescaped = re.sub(r"\\.", "x", pattern)
    return sum(1 for char in unescaped if char.isalnum())
