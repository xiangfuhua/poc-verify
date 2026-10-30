"""PG-002: identity and CVE consistency.

Two templates that claim the same id, or a template whose id says one CVE while
its metadata says another, poison every downstream dedupe and triage report.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Set

from ...schema import Finding, RuleMeta, Severity, Template, make_finding
from .base import Rule, metadata_line

RULE_ID = "PG-002"
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CVE_TAG_PATTERN = re.compile(r"^cve\d{4}$", re.IGNORECASE)


class IdentityRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Identity and CVE consistency",
        description=(
            "Validates the id format, that the file name matches the id, that ids are "
            "unique across the collection, that CVE metadata agrees with the id, and "
            "that YAML keys are not silently duplicated."
        ),
        default_severity=Severity.HIGH,
        help_anchor="pg-002-identity-and-cve-consistency",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        findings: List[Finding] = []

        def add(severity: Severity, message: str, line, hint: str = "") -> None:
            findings.append(make_finding(RULE_ID, severity, message, template, line, hint))

        if template.id:
            self._check_id_format(template, add)
            self._check_filename(template, add)
            self._check_duplicate_ids(template, context, add)
            self._check_cves(template, add)

        for dotted, line in template.duplicate_keys:
            add(
                Severity.HIGH,
                f"duplicate YAML key '{dotted}' silently overrides the earlier value",
                line,
                "remove the duplicate; YAML keeps only the last one",
            )
        return findings

    # -- individual checks -------------------------------------------------
    def _check_id_format(self, template: Template, add) -> None:
        template_id = template.id or ""
        line = metadata_line(template, "id")
        if ID_PATTERN.match(template_id):
            return
        if template_id != template_id.lower():
            add(Severity.MEDIUM, f"id {template_id!r} must be lowercase", line)
        elif " " in template_id or "\t" in template_id:
            add(Severity.MEDIUM, f"id {template_id!r} must not contain whitespace", line)
        elif len(template_id) > 80:
            add(Severity.MEDIUM, f"id is {len(template_id)} characters; keep it under 80", line)
        else:
            add(
                Severity.MEDIUM,
                f"id {template_id!r} must match [a-z0-9][a-z0-9._-]*",
                line,
                "use a stable slug such as 'cve-2024-1234' or 'apache-druid-rce'",
            )

    def _check_filename(self, template: Template, add) -> None:
        if not template.id or not template.path.name:
            return
        stem = Path(template.path).stem
        if stem != template.id:
            add(
                Severity.MEDIUM,
                f"id {template.id!r} does not match file name {template.path.name!r}",
                metadata_line(template, "id"),
                f"rename the file to {template.id}.yaml so searches and dedupe agree",
            )

    def _check_duplicate_ids(self, template: Template, context, add) -> None:
        if not template.id:
            return
        peers = [peer for peer in context.by_id.get(template.id, ()) if peer.path != template.path]
        # Report once, on every file after the canonical (lexicographically first) one.
        earlier = [peer for peer in peers if str(peer.path) < str(template.path)]
        if not earlier:
            return
        names = ", ".join(sorted(Path(peer.rel_path).name for peer in earlier))
        add(
            Severity.HIGH,
            f"duplicate id {template.id!r}; also used by {names}",
            metadata_line(template, "id"),
            "make ids unique; duplicates multiply scans and alerts",
        )

    def _check_cves(self, template: Template, add) -> None:
        declared: Set[str] = {cve.upper() for cve in template.cves}
        in_id: Set[str] = {match.upper() for match in CVE_PATTERN.findall(template.id or "")}
        line = metadata_line(template, "id")

        if declared and not in_id:
            add(
                Severity.MEDIUM,
                f"declares {', '.join(sorted(declared))} but id {template.id!r} has no CVE id",
                line,
                "either put the CVE in the id or drop the CVE metadata",
            )
        elif in_id and not declared:
            add(
                Severity.MEDIUM,
                f"id references {', '.join(sorted(in_id))} but "
                "info.classification.cve-id is empty",
                metadata_line(template, "classification"),
            )
        elif declared and in_id and declared != in_id:
            add(
                Severity.HIGH,
                f"CVE mismatch: id references {', '.join(sorted(in_id))} but metadata "
                f"declares {', '.join(sorted(declared))}",
                line,
            )

        if declared:
            tags = {tag.lower() for tag in template.tags}
            if not any(CVE_TAG_PATTERN.match(tag) for tag in tags):
                add(
                    Severity.LOW,
                    "CVE metadata without a 'cveYYYY' tag; most triage views filter on it",
                    metadata_line(template, "tags"),
                )
