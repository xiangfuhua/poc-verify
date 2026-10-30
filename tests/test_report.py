"""Markdown, SARIF and JSON reporters."""
from __future__ import annotations

from datetime import datetime

from pocverify.config import Config, IgnoreRule
from pocverify.gate import evaluate
from pocverify.lint.engine import lint
from pocverify.report import json_report, markdown, sarif
from pocverify.runner.http import RequestResult, TemplateResult, blocked
from pocverify.schema import Severity

from conftest import load_template

BAD = """\
id: report-bad
info:
  name: Report bad
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /admin
payload:
  q: "'; DROP TABLE users; --"
matchers:
  - type: status
    status: [200]
"""

GOOD = """\
id: report-good
info:
  name: Report good
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /ok
matchers:
  - type: word
    words: ["unique-marker"]
"""

MEDIUM = """\
id: report-medium
info:
  name: Report medium
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /ok
matchers:
  - type: word
    words: ["ok"]
"""


def build(text: str, filename: str, config: Config | None = None):
    template = load_template(text, filename)
    report = lint([template], config=config)
    gate = evaluate(report)
    return template, report, gate


def test_markdown_contains_the_core_sections():
    template, report, gate = build(BAD, "report-bad.yaml")
    rendered = markdown.render(
        markdown.RunData(
            target="http://127.0.0.1:8080",
            lint=report,
            gate=gate,
            results=(blocked(template, ["PG-004 high: destructive"]),),
            started_at=datetime(2026, 1, 2, 3, 4, 5),
            duration_s=1.5,
        )
    )
    assert "# PoCVerify report" in rendered
    assert "http://127.0.0.1:8080" in rendered
    assert "## Gate decisions" in rendered
    assert "## Lint findings" in rendered
    assert "PG-004" in rendered
    assert "blocked" in rendered
    assert "## Execution" in rendered


def test_markdown_renders_evidence_with_a_safe_fence():
    template = load_template(GOOD, "report-good.yaml")
    report = lint([template])
    gate = evaluate(report)
    result = TemplateResult(
        template=template,
        status="PASS",
        requests=(
            RequestResult(
                label="GET /ok",
                method="GET",
                url="http://127.0.0.1:8080/ok",
                status="PASS",
                http_status=200,
                matched_by="word",
                evidence="prefix\n```\ninside fence\n```",
            ),
        ),
    )
    rendered = markdown.render(
        markdown.RunData(target="http://127.0.0.1:8080", lint=report, gate=gate, results=(result,))
    )
    assert "Evidence:" in rendered
    assert "````" in rendered
    assert "inside fence" in rendered


def test_markdown_dry_run_lists_plans():
    template, report, gate = build(GOOD, "report-good.yaml")
    rendered = markdown.render(
        markdown.RunData(
            target="http://127.0.0.1:8080",
            lint=report,
            gate=gate,
            plans={"report-good.yaml": ["GET http://127.0.0.1:8080/ok"]},
            dry_run=True,
        )
    )
    assert "## Planned requests" in rendered
    assert "GET http://127.0.0.1:8080/ok" in rendered
    assert "dry-run" in rendered


def test_markdown_lists_waivers():
    config = Config(
        ignore=(IgnoreRule(rule="PG-004", file="*", reason="disposable lab database only"),)
    )
    template, report, gate = build(BAD, "report-bad.yaml", config)
    rendered = markdown.render(
        markdown.RunData(target="http://127.0.0.1:8080", lint=report, gate=gate)
    )
    assert "## Waivers" in rendered
    assert "disposable lab database only" in rendered


def test_write_markdown_creates_a_file(tmp_path):
    template, report, gate = build(GOOD, "report-good.yaml")
    path = markdown.write_markdown(
        markdown.RunData(target="http://127.0.0.1:8080", lint=report, gate=gate),
        str(tmp_path / "reports"),
    )
    assert path.exists()
    assert path.name.startswith("pocverify_")
    assert path.suffix == ".md"


def test_sarif_levels_and_rule_index():
    template, report, gate = build(BAD, "report-bad.yaml")
    payload = sarif.build(report)
    run = payload["runs"][0]
    levels = {result["ruleId"]: result["level"] for result in run["results"]}
    assert levels["PG-004"] == "error"
    assert levels["PG-005"] == "error"
    for result in run["results"]:
        assert "ruleIndex" in result
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_medium_maps_to_warning():
    template, report, gate = build(MEDIUM, "report-medium.yaml")
    payload = sarif.build(report)
    result = next(r for r in payload["runs"][0]["results"] if r["ruleId"] == "PG-005")
    assert result["level"] == "warning"


def test_sarif_marks_waived_findings_as_suppressed():
    config = Config(
        ignore=(IgnoreRule(rule="PG-004", file="*", reason="disposable lab database only"),)
    )
    template, report, gate = build(BAD, "report-bad.yaml", config)
    payload = sarif.build(report)
    suppressed = [
        result
        for result in payload["runs"][0]["results"]
        if result["ruleId"] == "PG-004"
    ]
    assert suppressed
    assert suppressed[0]["suppressions"][0]["justification"] == "disposable lab database only"


def test_sarif_rules_describe_every_rule():
    template, report, gate = build(GOOD, "report-good.yaml")
    payload = sarif.build(report)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["PG-001", "PG-002", "PG-003", "PG-004", "PG-005", "PG-006"]


def test_json_report_summary_and_findings():
    template, report, gate = build(BAD, "report-bad.yaml")
    payload = json_report.build(report)
    assert payload["summary"]["templates"] == 1
    assert payload["summary"]["counts"]["high"] >= 1
    assert payload["templates"][0]["id"] == "report-bad"
    assert any(finding["rule"] == "PG-004" for finding in payload["templates"][0]["findings"])
