"""Command line interface for ``pocverify``.

Subcommands:

* ``lint``  — static analysis only, never sends a request;
* ``run``   — lint, gate, then execute only the approved templates;
* ``rules`` — list the rules and what they catch.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .config import Config, ConfigError, load_config
from .console import (
    make_console,
    print_dry_run,
    print_gate,
    print_lint,
    print_lint_summary,
    print_rules,
)
from .gate import evaluate
from .lint import LintReport, TemplateReport, lint
from .lint.rules import RULES
from .loader import load_templates
from .report import json_report, markdown, sarif
from .runner.dsl import UnsupportedMatcher
from .runner.http import blocked, plan_request, preview, run_template
from .schema import Severity

DEFAULT_MAX_RESPONSE = 2 * 1024 * 1024


class CliError(Exception):
    """A usage or environment error that maps to exit code 2."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pocverify",
        description="Lint before you run: static gate plus evidence runner for PoC templates.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  pocverify lint pocs --fail-on high\n"
            "  pocverify lint pocs --format sarif -o pocverify.sarif\n"
            "  pocverify run pocs --target http://127.0.0.1:8080 --dry-run\n"
            "  pocverify run pocs --target http://127.0.0.1:8080\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"pocverify {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lint_parser = subparsers.add_parser("lint", help="statically check templates")
    _add_common(lint_parser)
    lint_parser.add_argument("paths", nargs="+", help="template files or directories")
    lint_parser.add_argument("--fail-on", choices=_severity_choices(), default=None)
    lint_parser.add_argument(
        "--fail-under", type=int, default=None, help="fail when any template scores below this"
    )
    lint_parser.add_argument("--strict-waivers", action="store_true")
    lint_parser.add_argument("--format", choices=("console", "json", "sarif"), default="console")
    lint_parser.add_argument("-o", "--output", help="write the report to this file")

    run_parser = subparsers.add_parser("run", help="lint, gate, then execute approved templates")
    _add_common(run_parser)
    run_parser.add_argument("paths", nargs="+", help="template files or directories")
    run_parser.add_argument("--target", required=True, help="authorized target root URL")
    run_parser.add_argument("--block-on", choices=_severity_choices(), default=None)
    run_parser.add_argument("--allow-unsafe", action="store_true", help="run blocked templates anyway")
    run_parser.add_argument("--no-lint", action="store_true", help="skip the static gate")
    run_parser.add_argument("--dry-run", action="store_true", help="print requests, send nothing")
    run_parser.add_argument("--delay", type=float, default=0.0, help="seconds between templates")
    run_parser.add_argument("--timeout", type=float, default=10.0)
    run_parser.add_argument("--retries", type=int, default=1)
    run_parser.add_argument("--max-response-size", type=int, default=DEFAULT_MAX_RESPONSE)
    run_parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    run_parser.add_argument("--report-dir", default=markdown.REPORT_DIR)
    run_parser.add_argument("--no-report", action="store_true")

    rules_parser = subparsers.add_parser("rules", help="list lint rules")
    rules_parser.add_argument("--format", choices=("console", "json"), default="console")
    rules_parser.add_argument("--no-color", action="store_true")
    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to .pocverify.yaml")
    parser.add_argument("--no-config", action="store_true", help="ignore .pocverify.yaml")
    parser.add_argument("--no-color", action="store_true")


def _severity_choices() -> List[str]:
    return ["critical", "high", "medium", "low", "warning"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = make_console(no_color=getattr(args, "no_color", False))
    try:
        if args.command == "lint":
            return _cmd_lint(args, console)
        if args.command == "run":
            return _cmd_run(args, console)
        return _cmd_rules(args, console)
    except ConfigError as exc:
        console.print(f"config error: {exc}", style="red", markup=False)
        return 2
    except CliError as exc:
        console.print(f"error: {exc}", style="red", markup=False)
        return 2
    except KeyboardInterrupt:
        console.print("interrupted", style="yellow", markup=False)
        return 130


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------
def _cmd_lint(args, console) -> int:
    config = _load_config(args)
    fail_on = Severity.coerce(args.fail_on) if args.fail_on else config.fail_on
    if fail_on is None:
        raise CliError(f"unknown severity {args.fail_on!r}")
    fail_under = args.fail_under if args.fail_under is not None else config.fail_under
    _validate_score_threshold(fail_under)
    strict = args.strict_waivers or config.strict_waivers

    loaded = load_templates(args.paths)
    for error in loaded.errors:
        console.print(f"load error: {error}", style="red", markup=False)
    if not loaded.templates:
        console.print("no templates found", style="yellow", markup=False)
        return 2

    report = lint(loaded.templates, config=config)

    if args.format == "console":
        print_lint(console, report, fail_on=fail_on, fail_under=fail_under)
        blocking = report.failing(fail_on)
        if blocking:
            console.print(
                f"gate failed: {len(blocking)} finding(s) at or above {fail_on}",
                style="red",
                markup=False,
            )
        else:
            console.print("gate passed", style="green", markup=False)
    elif args.format == "json":
        _emit(json.dumps(json_report.build(report), indent=2, ensure_ascii=False), args.output)
    else:
        _emit(
            json.dumps(sarif.build(report), indent=2, ensure_ascii=False),
            args.output,
        )

    if loaded.errors:
        return 2
    if strict and report.unused_waivers:
        return 1
    if report.failing(fail_on):
        return 1
    if fail_under is not None and report.below(fail_under):
        return 1
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
def _cmd_run(args, console) -> int:
    _validate_target(args.target)
    config = _load_config(args)
    allow_unsafe = args.allow_unsafe or config.allow_unsafe
    block_on = Severity.coerce(args.block_on) if args.block_on else config.block_on
    if block_on is None:
        raise CliError(f"unknown severity {args.block_on!r}")

    loaded = load_templates(args.paths)
    for error in loaded.errors:
        console.print(f"load error: {error}", style="red", markup=False)
    if loaded.errors:
        return 2
    if not loaded.templates:
        raise CliError("no templates found")

    started = datetime.now()
    clock = time.perf_counter()
    if args.no_lint:
        report = LintReport(templates=tuple(TemplateReport(t, ()) for t in loaded.templates))
        gate = evaluate(report, block_on=block_on, allow_unsafe=True)
        console.print("Lint: skipped (--no-lint)", style="yellow", markup=False)
    else:
        report = lint(loaded.templates, config=config)
        print_lint_summary(console, report, block_on)
        gate = evaluate(report, block_on=block_on, allow_unsafe=allow_unsafe)

    print_gate(console, gate, args.target)

    if args.dry_run:
        return _dry_run(args, console, gate, report, started, clock, allow_unsafe)

    results = []
    for index, decision in enumerate(gate.approved):
        if index and args.delay > 0:
            time.sleep(args.delay)
        result = run_template(
            decision.template,
            args.target,
            timeout=args.timeout,
            retries=args.retries,
            max_response_size=args.max_response_size,
            insecure=args.insecure,
            allowed_external=allow_unsafe,
        )
        results.append(result)
        _print_live(console, result)
    for decision in gate.blocked:
        reasons = [
            f"{finding.rule} {finding.severity}: {finding.message}"
            for finding in decision.reasons
        ]
        results.append(blocked(decision.template, reasons))

    duration = time.perf_counter() - clock
    _print_run_summary(console, results, duration)

    if not args.no_report:
        _write_report(
            console,
            markdown.RunData(
                target=args.target,
                lint=report,
                gate=gate,
                results=tuple(results),
                started_at=started,
                duration_s=duration,
            ),
            args.report_dir,
        )

    if any(result.status == "ERROR" for result in results):
        return 2
    if any(result.status in ("FAIL", "BLOCKED") for result in results):
        return 1
    return 0


def _dry_run(args, console, gate, report, started, clock, allow_unsafe: bool) -> int:
    plans = {}
    errors = 0
    for decision in gate.approved:
        template = decision.template
        previews: List[str] = []
        for request in template.requests:
            try:
                prepared = plan_request(
                    template, request, args.target, allowed_external=allow_unsafe
                )
                previews.extend(preview(prepared))
            except UnsupportedMatcher as exc:
                errors += 1
                console.print(
                    f"plan error: {template.rel_path}: {exc}",
                    style="red",
                    markup=False,
                )
        plans[template.rel_path] = previews

    print_dry_run(console, plans)
    duration = time.perf_counter() - clock
    if not args.no_report:
        _write_report(
            console,
            markdown.RunData(
                target=args.target,
                lint=report,
                gate=gate,
                results=(),
                plans=plans,
                dry_run=True,
                started_at=started,
                duration_s=duration,
            ),
            args.report_dir,
        )
    if errors:
        return 2
    if gate.blocked:
        return 1
    return 0


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------
def _cmd_rules(args, console) -> int:
    if args.format == "json":
        print(
            json.dumps(
                [
                    {
                        "id": rule.meta.id,
                        "title": rule.meta.title,
                        "severity": str(rule.meta.default_severity),
                        "description": rule.meta.description,
                        "help": rule.meta.help_uri,
                    }
                    for rule in RULES
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    print_rules(console)
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _load_config(args) -> Config:
    if getattr(args, "no_config", False):
        return Config()
    path = Path(args.config) if getattr(args, "config", None) else None
    return load_config(path)


def _validate_target(target: str) -> None:
    if not target.lower().startswith(("http://", "https://")):
        raise CliError("--target must start with http:// or https://")


def _validate_score_threshold(value: Optional[int]) -> None:
    if value is not None and not 0 <= value <= 100:
        raise CliError("--fail-under must be between 0 and 100")


def _emit(payload: str, output: Optional[str]) -> None:
    if output:
        path = Path(output)
        try:
            if path.parent and str(path.parent) not in ("", "."):
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            raise CliError(f"cannot write {path}: {exc}") from exc
        return
    print(payload)


def _write_report(console, data: markdown.RunData, directory: str) -> None:
    try:
        path = markdown.write_markdown(data, directory)
    except OSError as exc:
        console.print(
            f"warning: report not written ({exc}); use --no-report or a writable --report-dir",
            style="yellow",
            markup=False,
        )
        return
    console.print(f"Report: {path}", markup=False)


def _print_live(console, result) -> None:
    style = {"PASS": "green", "FAIL": "yellow", "ERROR": "red"}.get(result.status, "")
    line = (
        f"{result.status:5} {result.template.display}  "
        f"HTTP {result.http_status or '-'}  {result.duration_ms} ms"
    )
    if result.matched_by:
        line += f"  [{result.matched_by}]"
    if result.evidence:
        line += "  " + " ".join(result.evidence.split())[:90]
    console.print(line, style=style, markup=False)


def _print_run_summary(console, results, duration: float) -> None:
    counts = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    console.print(f"Done in {duration:.1f}s · {summary}", markup=False)


def legacy_main(argv: Optional[Sequence[str]] = None) -> int:
    """v1-compatible entry point: ``python main.py --target ... --poc-dir ...``.

    v1 ran every template it loaded. The shim keeps that behaviour by disabling
    the gate, and says so, so existing scripts keep working while users migrate.
    """
    console = make_console()
    console.print(
        "main.py is deprecated: use `pocverify run --target ... <dir>` (v1 behaviour "
        "maps to --no-lint --allow-unsafe).",
        style="yellow",
        markup=False,
    )
    parser = argparse.ArgumentParser(description="PoCVerify v1 compatible entry point")
    parser.add_argument("--target", required=True)
    parser.add_argument("--poc-dir", default="pocs")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--max-response-size", type=int, default=DEFAULT_MAX_RESPONSE)
    args = parser.parse_args(argv)
    return main(
        [
            "run",
            args.poc_dir,
            "--target",
            args.target,
            "--no-lint",
            "--allow-unsafe",
            "--delay",
            str(args.delay),
            "--timeout",
            str(args.timeout),
            "--retries",
            str(args.retries),
            "--max-response-size",
            str(args.max_response_size),
        ]
    )


def entry_point() -> None:
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
