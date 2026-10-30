"""Console rendering, built on rich.

Every renderer takes a ``rich.console.Console`` so tests can capture output and
the CLI can decide about colour once.
"""
from __future__ import annotations

import textwrap
from typing import Dict, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .gate import GateResult, summarize_reasons
from .lint.engine import LintReport
from .lint.rules import RULES
from .schema import Severity

SEVERITY_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.WARNING: "dim",
}
STATUS_STYLE = {
    "PASS": "bold green",
    "FAIL": "yellow",
    "ERROR": "bold red",
    "BLOCKED": "bold magenta",
}


def make_console(*, no_color: bool = False) -> Console:
    return Console(no_color=no_color, highlight=False, emoji=False)


def print_lint(
    console: Console,
    report: LintReport,
    *,
    fail_on: Severity,
    fail_under: int | None = None,
    show_hints: bool = True,
) -> None:
    console.print(
        f"pocverify {__version__} · {len(report.templates)} template(s) · {len(RULES)} rules",
        markup=False,
    )
    if not report.templates:
        console.print("no templates found", style="yellow", markup=False)
        return

    printed = False
    for template_report in report.templates:
        if not template_report.findings:
            continue
        printed = True
        console.print()
        console.print(
            f"{template_report.template.rel_path}  (score {template_report.score}/100)",
            style="bold",
            markup=False,
        )
        for finding in template_report.findings:
            prefix = f"  L{finding.line or 1:<4} {str(finding.severity):8} {finding.rule}  "
            message = textwrap.fill(
                finding.message,
                width=max(40, console.width),
                initial_indent=prefix,
                subsequent_indent=" " * len(prefix),
            )
            console.print(
                message,
                style=SEVERITY_STYLE[finding.severity],
                markup=False,
                highlight=False,
            )
            detail = ""
            if finding.waived:
                detail = f"waived: {finding.reason}"
            elif show_hints and finding.hint:
                detail = f"hint: {finding.hint}"
            if detail:
                console.print(
                    textwrap.fill(
                        detail,
                        width=max(40, console.width),
                        initial_indent=" " * (len(prefix)),
                        subsequent_indent=" " * (len(prefix) + 2),
                    ),
                    style="dim",
                    markup=False,
                )
    if not printed:
        console.print("no findings", style="green", markup=False)

    for finding in report.unassigned:
        console.print(f"warning: {finding.message}", style="yellow", markup=False)

    console.print()
    console.print(_summary_line(report, fail_on, fail_under))
    score_failures = report.below(fail_under) if fail_under is not None else ()
    for template_report in score_failures:
        console.print(
            f"score below {fail_under}: {template_report.template.rel_path} "
            f"({template_report.score}/100)",
            style="red",
            markup=False,
        )
    for waiver in report.unused_waivers:
        console.print(
            f"unused waiver {waiver.rule} on {waiver.file}: {waiver.reason}",
            style="yellow",
            markup=False,
        )


def print_lint_summary(console: Console, report: LintReport, fail_on: Severity) -> None:
    """One-line lint summary used by the ``run`` command."""
    counts = report.counts
    parts = [f"{counts[severity]} {severity}" for severity in Severity if counts[severity]]
    console.print(
        f"Lint: {len(report.templates)} template(s) · score {report.score}/100 · "
        + (", ".join(parts) if parts else "no findings")
        + f" · fail-on {fail_on}"
    )


def print_gate(console: Console, gate: GateResult, target: str) -> None:
    console.print(f"Target: {target}", markup=False)
    console.print(
        f"Gate: {len(gate.approved)} approved, {len(gate.blocked)} blocked"
        + (" (--allow-unsafe)" if gate.allow_unsafe else "")
    )
    for decision in gate.blocked:
        console.print(
            f"  BLOCKED {decision.template.rel_path} — {summarize_reasons(decision)}",
            style="magenta",
            markup=False,
        )


def print_dry_run(console: Console, plans: Dict[str, List[str]]) -> None:
    if not plans:
        console.print("nothing to preview", style="yellow", markup=False)
        return
    for path, previews in plans.items():
        console.print(path, style="bold", markup=False)
        for preview in previews:
            console.print(f"  {preview}", style="cyan", markup=False)


def print_rules(console: Console) -> None:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title", overflow="fold")
    table.add_column("What it catches", overflow="fold")
    for rule in RULES:
        table.add_row(
            rule.meta.id,
            Text(str(rule.meta.default_severity), style=SEVERITY_STYLE[rule.meta.default_severity]),
            rule.meta.title,
            rule.meta.description,
        )
    console.print(table)


def _summary_line(report: LintReport, fail_on: Severity, fail_under: int | None) -> Text:
    counts = report.counts
    parts = [f"{counts[severity]} {severity}" for severity in Severity if counts[severity]]
    summary = ", ".join(parts) if parts else "no findings"
    text = Text()
    text.append("Score: ", style="bold")
    text.append(f"{report.score}/100", style="bold green" if report.score >= 80 else "bold yellow")
    text.append(f" (worst template; average {report.average_score}) · ")
    text.append(summary)
    text.append(f" · fail-on {fail_on}")
    if fail_under is not None:
        text.append(f" · fail-under {fail_under}")
    return text
