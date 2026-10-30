"""Lint orchestration: run rules, apply waivers, score each template."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ..config import Config, IgnoreRule
from ..schema import Finding, Severity, Template
from .rules import RULES
from .rules.base import Rule

__all__ = ["LintContext", "TemplateReport", "LintReport", "lint"]


@dataclass(frozen=True)
class LintContext:
    """Read-only view of the whole scan, shared by every rule."""

    templates: Tuple[Template, ...]
    by_id: Mapping[str, Tuple[Template, ...]]
    config: Config


@dataclass(frozen=True)
class TemplateReport:
    template: Template
    findings: Tuple[Finding, ...] = ()

    @property
    def score(self) -> int:
        return self.template.score(self.findings)

    @property
    def counts(self) -> Dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            if not finding.waived:
                counts[finding.severity] += 1
        return counts

    @property
    def waived(self) -> Tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.waived)

    def blocking(self, fail_on: Severity) -> Tuple[Finding, ...]:
        return tuple(
            f for f in self.findings if not f.waived and f.severity.at_least(fail_on)
        )


@dataclass(frozen=True)
class LintReport:
    templates: Tuple[TemplateReport, ...] = ()
    unused_waivers: Tuple[IgnoreRule, ...] = ()
    unassigned: Tuple[Finding, ...] = ()

    @property
    def findings(self) -> Tuple[Finding, ...]:
        return tuple(f for report in self.templates for f in report.findings) + self.unassigned

    @property
    def score(self) -> int:
        """Worst template score: one bad template is enough to fail a gate."""
        if not self.templates:
            return 100
        return min(report.score for report in self.templates)

    @property
    def average_score(self) -> int:
        if not self.templates:
            return 100
        return round(sum(report.score for report in self.templates) / len(self.templates))

    @property
    def counts(self) -> Dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for report in self.templates:
            for severity, value in report.counts.items():
                counts[severity] += value
        for finding in self.unassigned:
            if not finding.waived:
                counts[finding.severity] += 1
        return counts

    @property
    def waived_count(self) -> int:
        return sum(len(report.waived) for report in self.templates)

    def failing(self, fail_on: Severity) -> Tuple[Finding, ...]:
        return tuple(
            f for f in self.findings if not f.waived and f.severity.at_least(fail_on)
        )

    def below(self, threshold: int) -> Tuple[TemplateReport, ...]:
        return tuple(report for report in self.templates if report.score < threshold)

    def for_path(self, rel_path: str) -> Optional[TemplateReport]:
        for report in self.templates:
            if report.template.rel_path == rel_path:
                return report
        return None


def lint(
    templates: Iterable[Template],
    *,
    config: Optional[Config] = None,
    rules: Optional[Sequence[Rule]] = None,
) -> LintReport:
    """Run every rule over every template and apply configured waivers."""
    ordered = tuple(sorted(templates, key=lambda t: t.rel_path.lower()))
    cfg = config or Config()
    context = LintContext(templates=ordered, by_id=_index_by_id(ordered), config=cfg)

    findings: List[Finding] = []
    for rule in rules if rules is not None else RULES:
        try:
            findings.extend(rule.check_all(ordered, context))
        except Exception as exc:  # a broken rule must not hide every other rule
            findings.append(
                Finding(
                    rule="PG-000",
                    severity=Severity.WARNING,
                    message=f"internal error while running {rule.meta.id}: {exc}",
                    path=ordered[0].rel_path if ordered else "",
                    line=1,
                )
            )

    buckets: Dict[str, List[Finding]] = {template.rel_path: [] for template in ordered}
    unassigned: List[Finding] = []
    for finding in findings:
        if finding.path in buckets:
            buckets[finding.path].append(finding)
        else:
            unassigned.append(finding)

    used_waivers: Set[int] = set()
    reports: List[TemplateReport] = []
    for template in ordered:
        resolved: List[Finding] = []
        for finding in buckets[template.rel_path]:
            waived = _apply_waiver(finding, cfg.ignore, used_waivers)
            resolved.append(waived)
        resolved.sort(key=lambda f: f.sort_key)
        reports.append(TemplateReport(template=template, findings=tuple(resolved)))

    unused = tuple(
        waiver for index, waiver in enumerate(cfg.ignore) if index not in used_waivers
    )
    return LintReport(
        templates=tuple(reports),
        unused_waivers=unused,
        unassigned=tuple(sorted(unassigned, key=lambda f: f.sort_key)),
    )


def _apply_waiver(finding: Finding, waivers: Sequence[IgnoreRule], used: Set[int]) -> Finding:
    for index, waiver in enumerate(waivers):
        if waiver.matches(finding.rule, finding.path):
            used.add(index)
            return finding.waive(waiver.reason)
    return finding


def _index_by_id(templates: Sequence[Template]) -> Dict[str, Tuple[Template, ...]]:
    index: Dict[str, List[Template]] = {}
    for template in templates:
        if template.id:
            index.setdefault(template.id, []).append(template)
    return {key: tuple(value) for key, value in index.items()}
