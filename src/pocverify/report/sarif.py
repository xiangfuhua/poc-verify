"""SARIF 2.1.0 output for GitHub code scanning and any SARIF viewer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .. import __version__
from ..lint.engine import LintReport
from ..lint.rules import RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/xiangfuhua/poc-verify"


def build(report: LintReport) -> Dict[str, Any]:
    """Build a SARIF log for every finding, including waived ones."""
    rules = []
    rule_index = {}
    for index, rule in enumerate(RULES):
        rule_index[rule.meta.id] = index
        rules.append(
            {
                "id": rule.meta.id,
                "name": rule.meta.title.replace(" ", ""),
                "shortDescription": {"text": rule.meta.title},
                "fullDescription": {"text": rule.meta.description},
                "helpUri": rule.meta.help_uri,
                "defaultConfiguration": {"level": rule.meta.default_severity.sarif_level},
                "properties": {"severity": str(rule.meta.default_severity)},
            }
        )

    results: List[Dict[str, Any]] = []
    notifications: List[Dict[str, Any]] = []
    for finding in report.findings:
        if not finding.path:
            # Only an internal rule crash reaches this branch; SARIF requires a
            # real location, so it becomes an execution notification instead.
            notifications.append(
                {
                    "level": "warning",
                    "message": {"text": finding.message},
                }
            )
            continue
        result: Dict[str, Any] = {
            "ruleId": finding.rule,
            "level": finding.severity.sarif_level,
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": finding.line or 1},
                    }
                }
            ],
            "properties": {
                "severity": str(finding.severity),
                "hint": finding.hint,
            },
        }
        if finding.rule in rule_index:
            result["ruleIndex"] = rule_index[finding.rule]
        if finding.waived:
            result["suppressions"] = [
                {"kind": "external", "justification": finding.reason or "waived by config"}
            ]
        results.append(result)

    invocation: Dict[str, Any] = {"executionSuccessful": True}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pocverify",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": Path.cwd().as_uri() + "/"}},
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def write_sarif(path: str | Path, report: LintReport) -> Path:
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build(report), indent=2, ensure_ascii=False), encoding="utf-8")
    return target
