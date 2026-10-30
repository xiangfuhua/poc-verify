"""PG-006: cross-file duplicate detection.

A collection of thousands of templates accumulates near-copies: the same CVE
written three times, or the same endpoint checked with different regexes. Each
copy multiplies request volume and alert noise, so the fingerprint is computed
over the normalized request and matcher set, not over the file text.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple

from ...schema import Finding, RuleMeta, Severity, Template, make_finding
from .base import Rule

RULE_ID = "PG-006"
_VARIABLE_RE = re.compile(
    r"\{\{\s*(?:BaseURL|RootURL|Hostname|Host|Port)\s*\}\}", re.IGNORECASE
)
_RAW_TARGET_RE = re.compile(r"^\s*([A-Z]+)\s+(\S+)\s+HTTP/", re.IGNORECASE)

Endpoint = Tuple[str, Tuple[str, ...]]


class DuplicateRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Cross-file duplicates",
        description=(
            "Fingerprints method, normalized paths and matcher signatures across the "
            "whole scan; exact duplicates are high, same-endpoint variants medium and "
            "the same CVE in several templates low."
        ),
        default_severity=Severity.HIGH,
        help_anchor="pg-006-cross-file-duplicates",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        return ()

    def check_all(self, templates: Sequence[Template], context) -> Iterable[Finding]:
        by_fingerprint: Dict[str, List[Template]] = defaultdict(list)
        by_endpoint: Dict[Endpoint, List[Template]] = defaultdict(list)
        by_cve: Dict[str, List[Template]] = defaultdict(list)

        for template in templates:
            if template.requests:
                by_fingerprint[fingerprint(template)].append(template)
                endpoint = endpoint_key(template)
                if endpoint is not None:
                    by_endpoint[endpoint].append(template)
            for cve in template.cves:
                by_cve[cve.upper()].append(template)

        findings: List[Finding] = []
        for group in by_fingerprint.values():
            if len(group) < 2:
                continue
            canonical = group[0]
            for duplicate in group[1:]:
                findings.append(
                    make_finding(
                        RULE_ID,
                        Severity.HIGH,
                        f"duplicate of {canonical.rel_path}: identical request and matcher fingerprint",
                        duplicate,
                        template_line(duplicate),
                        "delete one of the copies; duplicates double request volume and alerts",
                    )
                )

        for group in by_endpoint.values():
            if len(group) < 2:
                continue
            canonical = group[0]
            canonical_fingerprint = fingerprint(canonical)
            for variant in group[1:]:
                if fingerprint(variant) == canonical_fingerprint:
                    continue  # already reported as an exact duplicate
                findings.append(
                    make_finding(
                        RULE_ID,
                        Severity.MEDIUM,
                        f"shares an endpoint with {canonical.rel_path} but uses different matchers",
                        variant,
                        template_line(variant),
                        "keep one template per endpoint, or state what the second check adds",
                    )
                )

        for cve, group in by_cve.items():
            if len(group) < 2:
                continue
            for duplicate in group[1:]:
                findings.append(
                    make_finding(
                        RULE_ID,
                        Severity.LOW,
                        f"{cve} is covered by {len(group)} templates in this scan",
                        duplicate,
                        template_line(duplicate),
                        "consolidate on the template with the strongest matcher",
                    )
                )
        return findings


def endpoint_key(template: Template) -> Endpoint | None:
    """Method plus normalized path, ignoring the matcher set."""
    endpoints = set()
    for request in template.requests:
        for path in _request_paths(request):
            endpoints.add((request.method.upper(), _normalize_path(path)))
    if not endpoints:
        return None
    return min(endpoints)


def fingerprint(template: Template) -> str:
    """Stable digest of method, paths and matchers across all requests."""
    parts = []
    for request in template.requests:
        paths = tuple(sorted(_normalize_path(path) for path in _request_paths(request)))
        matchers = tuple(sorted(matcher.signature() for matcher in request.matchers))
        parts.append((request.method.upper(), paths, matchers, request.matcher_condition))
    parts.sort()
    digest = hashlib.sha256(repr(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def template_line(template: Template) -> int:
    return template.line_at("info", "name") if template.name else (template.line_at("id") or 1)


def _request_paths(request) -> Tuple[str, ...]:
    if request.paths:
        return request.paths
    if request.raw:
        for line in request.raw.splitlines():
            match = _RAW_TARGET_RE.match(line)
            if match:
                return (match.group(2),)
    return ()


def _normalize_path(path: str) -> str:
    cleaned = _VARIABLE_RE.sub("", path).strip()
    if not cleaned:
        cleaned = "/"
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    cleaned = cleaned.rstrip("/")
    return cleaned or "/"
