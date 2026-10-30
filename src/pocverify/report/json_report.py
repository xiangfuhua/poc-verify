"""Machine-readable lint output (``--format json``)."""
from __future__ import annotations

from typing import Any, Dict

from .. import __version__
from ..lint.engine import LintReport


def build(report: LintReport) -> Dict[str, Any]:
    return {
        "tool": "pocverify",
        "version": __version__,
        "summary": {
            "templates": len(report.templates),
            "score": report.score,
            "average_score": report.average_score,
            "counts": {str(severity): count for severity, count in report.counts.items()},
            "waived": report.waived_count,
            "unused_waivers": len(report.unused_waivers),
        },
        "templates": [
            {
                "path": template_report.template.rel_path,
                "id": template_report.template.id,
                "name": template_report.template.display,
                "dialect": str(template_report.template.dialect),
                "score": template_report.score,
                "findings": [
                    {
                        "rule": finding.rule,
                        "severity": str(finding.severity),
                        "message": finding.message,
                        "line": finding.line,
                        "hint": finding.hint,
                        "waived": finding.waived,
                        "reason": finding.reason,
                    }
                    for finding in template_report.findings
                ],
            }
            for template_report in report.templates
        ],
        "unused_waivers": [
            {"rule": waiver.rule, "file": waiver.file, "reason": waiver.reason}
            for waiver in report.unused_waivers
        ],
    }
