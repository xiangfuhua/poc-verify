"""PG-001: the metadata contract.

A template without an id, an owner, a severity and a reference is not
maintainable: nobody can deduplicate it, triage it or contact whoever wrote it.
"""
from __future__ import annotations

import math
from typing import Iterable, List
from urllib.parse import urlparse

from ...schema import Finding, RuleMeta, Severity, Template, make_finding
from .base import Rule, metadata_line

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
MIN_DESCRIPTION_LENGTH = 20

RULE_ID = "PG-001"


class MetadataRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Metadata contract",
        description=(
            "Requires id, name, author, severity, description and reference; validates "
            "the severity enum, the CVSS range and that references are URLs."
        ),
        default_severity=Severity.HIGH,
        help_anchor="pg-001-metadata-contract",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        findings: List[Finding] = []

        def add(severity: Severity, message: str, line, hint: str = "") -> None:
            findings.append(make_finding(RULE_ID, severity, message, template, line, hint))

        if not template.id:
            add(
                Severity.HIGH,
                "missing required field 'id'",
                1,
                "give the template a stable lowercase id (for example 'cve-2024-1234')",
            )
        if not template.name:
            add(
                Severity.HIGH,
                "missing required field 'info.name'",
                metadata_line(template, "name"),
                "describe what the template detects, not which CVE it is",
            )
        if not template.authors:
            add(
                Severity.MEDIUM,
                "missing required field 'info.author'",
                metadata_line(template, "author"),
                "a template without an owner has no maintainer",
            )
        if not template.severity:
            add(
                Severity.HIGH,
                "missing required field 'info.severity'",
                metadata_line(template, "severity"),
                "one of: critical, high, medium, low, info",
            )
        elif template.severity.strip().lower() not in ALLOWED_SEVERITIES:
            add(
                Severity.HIGH,
                f"severity {template.severity!r} is not one of: "
                + ", ".join(sorted(ALLOWED_SEVERITIES)),
                metadata_line(template, "severity"),
            )
        if not template.description:
            add(
                Severity.MEDIUM,
                "missing required field 'info.description'",
                metadata_line(template, "description"),
                "explain the vulnerable condition and what a match means",
            )
        elif len(template.description.strip()) < MIN_DESCRIPTION_LENGTH:
            add(
                Severity.LOW,
                f"description is too short ({len(template.description.strip())} characters); "
                f"aim for at least {MIN_DESCRIPTION_LENGTH}",
                metadata_line(template, "description"),
            )
        if not template.references:
            add(
                Severity.MEDIUM,
                "missing required field 'info.reference'",
                metadata_line(template, "reference"),
                "link the advisory, changelog or commit that proves the vulnerability",
            )
        for reference in template.references:
            parsed = urlparse(reference)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                add(
                    Severity.MEDIUM,
                    f"reference is not an absolute http(s) URL: {reference!r}",
                    metadata_line(template, "reference"),
                )
        if not template.tags:
            add(
                Severity.LOW,
                "missing 'info.tags'; tags drive routing in most dashboards",
                metadata_line(template, "tags"),
                "add product, protocol and vuln-class tags, for example 'apache,http,rce'",
            )
        if template.cvss is not None:
            if math.isnan(template.cvss):
                add(
                    Severity.HIGH,
                    "cvss-score is not a number",
                    template.line_at("info", "classification", "cvss-score"),
                )
            elif not 0.0 <= template.cvss <= 10.0:
                add(
                    Severity.HIGH,
                    f"cvss-score {template.cvss} is outside the 0.0-10.0 range",
                    template.line_at("info", "classification", "cvss-score"),
                )
        return findings
