"""The gate: turn lint findings into a run/do-not-run decision.

This is the piece that makes the two halves one tool. Lint alone is advice; a
template that fails the gate is refused by the runner unless a human passes
``--allow-unsafe``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence, Tuple

from .lint.engine import LintReport, TemplateReport
from .schema import Finding, Severity


@dataclass(frozen=True)
class Decision:
    """One template's gate decision plus the findings that caused it."""

    report: TemplateReport
    blocked: bool
    reasons: Tuple[Finding, ...] = ()

    @property
    def template(self):
        return self.report.template


@dataclass(frozen=True)
class GateResult:
    decisions: Tuple[Decision, ...]
    allow_unsafe: bool = False

    @property
    def approved(self) -> Tuple[Decision, ...]:
        return tuple(d for d in self.decisions if not d.blocked)

    @property
    def blocked(self) -> Tuple[Decision, ...]:
        return tuple(d for d in self.decisions if d.blocked)

    def for_path(self, rel_path: str) -> Decision | None:
        for decision in self.decisions:
            if decision.template.rel_path == rel_path:
                return decision
        return None


def evaluate(
    report: LintReport,
    *,
    block_on: Severity = Severity.HIGH,
    allow_unsafe: bool = False,
) -> GateResult:
    """Block every template with a non-waived finding at or above ``block_on``."""
    decisions = []
    for template_report in report.templates:
        reasons = template_report.blocking(block_on)
        decisions.append(
            Decision(
                report=template_report,
                blocked=bool(reasons) and not allow_unsafe,
                reasons=reasons,
            )
        )
    return GateResult(decisions=tuple(decisions), allow_unsafe=allow_unsafe)


def summarize_reasons(decision: Decision, limit: int = 3) -> str:
    """Compact ``PG-003 critical, PG-004 high`` style summary for the console."""
    labels = [f"{finding.rule} {finding.severity}" for finding in decision.reasons[:limit]]
    if len(decision.reasons) > limit:
        labels.append(f"+{len(decision.reasons) - limit} more")
    return ", ".join(labels)
