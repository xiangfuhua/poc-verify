"""Lint engine: scoring, waivers, isolation and report shape."""
from __future__ import annotations

from pocverify.config import Config, IgnoreRule
from pocverify.lint.engine import lint
from pocverify.schema import Finding, RuleMeta, Severity
from pocverify.lint.rules.base import Rule

from conftest import load_template

BAD = """\
id: demo-bad
info:
  name: Demo bad
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /admin
matchers:
  - type: status
    status: [200]
"""

GOOD = """\
id: demo-good
info:
  name: Demo good
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /health
matchers:
  - type: word
    words: ["unique-marker"]
"""


def test_score_penalties_are_weighted():
    report = lint([load_template(BAD, "demo-bad.yaml")])
    # one high (-10) and nothing else: PG-005.
    assert report.templates[0].score == 90


def test_worst_score_is_the_report_score():
    report = lint(
        [
            load_template(GOOD, "demo-good.yaml"),
            load_template(BAD, "demo-bad.yaml"),
        ]
    )
    assert report.score == 90
    assert report.average_score == 95


def test_waivers_mark_findings_and_restore_the_score():
    config = Config(
        ignore=(
            IgnoreRule(rule="PG-005", file="*", reason="accepted risk until the lab is rebuilt"),
        )
    )
    report = lint([load_template(BAD, "demo-bad.yaml")], config=config)
    template_report = report.templates[0]
    assert template_report.score == 100
    waived = [f for f in template_report.findings if f.waived]
    assert len(waived) == 1
    assert waived[0].reason == "accepted risk until the lab is rebuilt"
    assert report.unused_waivers == ()


def test_unused_waivers_are_reported():
    config = Config(ignore=(IgnoreRule(rule="PG-001", file="*", reason="not matched by this file"),))
    report = lint([load_template(GOOD, "demo-good.yaml")], config=config)
    assert len(report.unused_waivers) == 1
    assert report.unused_waivers[0].rule == "PG-001"


def test_waiver_scoped_to_a_path_glob():
    config = Config(ignore=(IgnoreRule(rule="PG-005", file="other/*.yaml", reason="different file only"),))
    report = lint([load_template(BAD, "demo-bad.yaml")], config=config)
    assert not report.findings[0].waived
    assert report.unused_waivers


def test_failing_filters_waived_and_low_severities():
    config = Config(ignore=(IgnoreRule(rule="PG-001", file="*", reason="metadata handled elsewhere"),))
    report = lint([load_template(BAD, "demo-bad.yaml")], config=config)
    assert all(f.rule != "PG-001" for f in report.failing(Severity.HIGH))
    assert len(report.failing(Severity.HIGH)) == 1


class _BrokenRule(Rule):
    meta = RuleMeta(
        id="PG-999",
        title="Broken rule",
        description="Always raises, used to prove rule isolation.",
        default_severity=Severity.WARNING,
    )

    def check(self, template, context):
        raise RuntimeError("boom")


def test_a_crashing_rule_does_not_hide_the_others():
    report = lint([load_template(GOOD, "demo-good.yaml")], rules=[_BrokenRule()])
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule == "PG-000"
    assert finding.severity is Severity.WARNING
    assert "boom" in finding.message


def test_findings_are_sorted_by_severity_then_line():
    report = lint([load_template(BAD, "demo-bad.yaml")])
    ranks = [finding.severity.rank for finding in report.templates[0].findings]
    assert ranks == sorted(ranks)


def test_templates_are_sorted_by_path():
    report = lint(
        [
            load_template(GOOD, "z-file.yaml"),
            load_template(GOOD, "a-file.yaml"),
        ]
    )
    paths = [template_report.template.rel_path for template_report in report.templates]
    assert paths == sorted(paths)


def test_below_threshold():
    report = lint([load_template(BAD, "demo-bad.yaml")])
    assert [r.template.rel_path for r in report.below(95)] == [report.templates[0].template.rel_path]
    assert report.below(90) == ()


def test_unassigned_findings_are_kept():
    class FloatingRule(Rule):
        meta = RuleMeta(
            id="PG-998",
            title="Floating",
            description="Reports against a path that does not exist.",
            default_severity=Severity.LOW,
        )

        def check(self, template, context):
            return [
                Finding(
                    rule=self.meta.id,
                    severity=Severity.LOW,
                    message="floating",
                    path="somewhere-else.yaml",
                    line=3,
                )
            ]

    report = lint([load_template(GOOD, "demo-good.yaml")], rules=[FloatingRule()])
    assert len(report.unassigned) == 1
    assert report.unassigned[0].message == "floating"
