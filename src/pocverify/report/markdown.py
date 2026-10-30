"""Unified Markdown evidence bundle.

One report answers three questions in order: what was linted, what the gate
allowed, and what the runner observed with evidence attached.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .. import __version__
from ..gate import GateResult, summarize_reasons
from ..lint.engine import LintReport
from ..runner.http import TemplateResult
from ..schema import Severity

REPORT_DIR = "reports"
_SENSITIVE = {"cookie", "authorization", "x-api-key", "x-auth-token"}


@dataclass(frozen=True)
class RunData:
    """Everything the report needs about one invocation."""

    target: str
    lint: LintReport
    gate: GateResult
    results: Sequence[TemplateResult] = ()
    plans: Dict[str, List[str]] = field(default_factory=dict)
    dry_run: bool = False
    started_at: Optional[datetime] = None
    duration_s: float = 0.0


def write_markdown(data: RunData, directory: str = REPORT_DIR) -> Path:
    """Render and write the report, returning its path."""
    started = data.started_at or datetime.now()
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"pocverify_{started:%Y%m%d_%H%M%S}.md"
    path.write_text(render(data), encoding="utf-8")
    return path


def render(data: RunData) -> str:
    started = data.started_at or datetime.now()
    lint = data.lint
    counts = lint.counts
    results = list(data.results)
    passed = sum(1 for result in results if result.status == "PASS")
    failed = sum(1 for result in results if result.status == "FAIL")
    errors = sum(1 for result in results if result.status == "ERROR")
    blocked = len(data.gate.blocked)
    executed = len([result for result in results if result.status != "BLOCKED"])

    lines = [
        "# PoCVerify report",
        "",
        f"- Target: `{data.target}`",
        f"- Generated: {started:%Y-%m-%d %H:%M:%S}",
        f"- Tool: pocverify {__version__}",
        f"- Mode: {'dry-run (no request sent)' if data.dry_run else 'execute'}",
        f"- Duration: {data.duration_s:.1f}s",
        "",
        "## Summary",
        "",
        "| Linted | Executed | Blocked | Pass | Fail | Error | Worst score |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        f"| {len(lint.templates)} | {executed} | {blocked} | {passed} | {failed} | {errors} | {lint.score}/100 |",
        "",
        f"Severity counts: {_counts_line(counts)}",
        "",
    ]

    lines.extend(_render_gate(data))
    lines.extend(_render_findings(lint, data))
    if data.dry_run:
        lines.extend(_render_plans(data.plans))
    else:
        lines.extend(_render_results(results))
    waived = [f for f in lint.findings if f.waived]
    if waived:
        lines += ["## Waivers", ""]
        for finding in waived:
            lines.append(
                f"- `{finding.rule}` {finding.location}: {finding.reason}"
            )
        lines.append("")

    lines += [
        "---",
        "",
        "Static analysis only: `pocverify` never executes template code. "
        "Requests were sent only to the target named above, and only for templates "
        "the gate approved.",
        "",
    ]
    return "\n".join(lines)


def _render_gate(data: RunData) -> List[str]:
    if not data.gate.decisions:
        return []
    lines = ["## Gate decisions", "", "| Template | Score | Decision | Findings |", "| --- | --- | --- | --- |"]
    for decision in data.gate.decisions:
        status = "blocked" if decision.blocked else "approved"
        reasons = summarize_reasons(decision, limit=4) or "-"
        lines.append(
            f"| `{decision.template.rel_path}` | {decision.report.score} | {status} | {_cell(reasons)} |"
        )
    lines.append("")
    return lines


def _render_findings(lint: LintReport, data: RunData) -> List[str]:
    lines = ["## Lint findings", ""]
    findings = [f for report in lint.templates for f in report.findings]
    if not findings:
        lines += ["No findings.", ""]
        return lines
    lines += ["| Location | Rule | Severity | Waived | Message |", "| --- | --- | --- | --- | --- |"]
    for finding in findings:
        waived = f"yes: {finding.reason}" if finding.waived else "no"
        lines.append(
            f"| `{_cell(finding.location)}` | {finding.rule} | {finding.severity} | "
            f"{_cell(waived)} | {_cell(finding.message)} |"
        )
    lines.append("")

    unused = lint.unused_waivers
    if unused:
        lines += ["### Unused waivers", ""]
        for waiver in unused:
            lines.append(f"- `{waiver.rule}` on `{waiver.file}`: {waiver.reason}")
        lines.append("")
    return lines


def _render_plans(plans: Dict[str, List[str]]) -> List[str]:
    lines = ["## Planned requests", ""]
    if not plans:
        lines += ["No approved template produced a request.", ""]
        return lines
    for path, previews in plans.items():
        lines += [f"### `{path}`", ""]
        lines += [f"- `{_cell(preview)}`" for preview in previews]
        lines.append("")
    return lines


def _render_results(results: Sequence[TemplateResult]) -> List[str]:
    lines = ["## Execution", ""]
    if not results:
        lines += ["No template was executed.", ""]
        return lines
    for result in results:
        lines += [f"### {result.template.display} — **{result.status}**", ""]
        lines.append(f"- File: `{result.template.rel_path}`")
        lines.append(f"- Template id: `{result.template.id or '-'}`")
        if result.status == "BLOCKED":
            for reason in result.blocked_reasons:
                lines.append(f"- Blocked: {reason}")
            lines.append("")
            continue
        for request in result.requests:
            lines.append(
                f"- Request: `{request.method} {request.url}` "
                f"(HTTP {request.http_status or '-'}, {request.elapsed_ms} ms)"
            )
            if request.status == "ERROR":
                lines.append(f"  - Error: {request.error}")
            elif request.matched_by:
                lines.append(f"  - Matched by: {request.matched_by}")
            if request.truncated:
                lines.append("  - Response body was truncated at the configured limit")
        if result.status == "ERROR" and result.failure:
            lines.append(f"- Error: {result.failure}")
        if result.evidence:
            lines += ["", "Evidence:", "", _fence(result.evidence), ""]
        else:
            lines.append("")
    return lines


def _counts_line(counts: Dict[Severity, int]) -> str:
    return ", ".join(
        f"{counts[severity]} {severity}" for severity in Severity if counts[severity]
    ) or "none"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _fence(text: str) -> str:
    ticks = "```"
    while ticks in text:
        ticks += "`"
    return f"{ticks}\n{text}\n{ticks}"
