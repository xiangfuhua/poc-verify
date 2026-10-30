"""Gate decisions: what may run without --allow-unsafe."""
from __future__ import annotations

from pocverify.config import Config, IgnoreRule
from pocverify.gate import evaluate, summarize_reasons
from pocverify.lint.engine import lint
from pocverify.schema import Severity

from conftest import load_template

HIGH_TEMPLATE = """\
id: gate-high
info:
  name: Gate high
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

MEDIUM_TEMPLATE = """\
id: gate-medium
info:
  name: Gate medium
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /admin
matchers:
  - type: word
    words: ["ok"]
"""


def report_for(text: str, filename: str, config: Config | None = None):
    return lint([load_template(text, filename)], config=config)


def test_high_finding_blocks_at_high():
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml"))
    assert len(gate.blocked) == 1
    assert gate.blocked[0].reasons[0].rule == "PG-005"


def test_medium_finding_does_not_block_at_high():
    gate = evaluate(report_for(MEDIUM_TEMPLATE, "gate-medium.yaml"))
    assert gate.blocked == ()
    assert len(gate.approved) == 1


def test_allow_unsafe_overrides_the_block():
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml"), allow_unsafe=True)
    assert gate.blocked == ()
    assert gate.approved[0].reasons  # the reasons are still visible


def test_block_on_critical_ignores_high_findings():
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml"), block_on=Severity.CRITICAL)
    assert gate.blocked == ()


def test_waived_findings_do_not_block():
    config = Config(
        ignore=(IgnoreRule(rule="PG-005", file="*", reason="accepted until the lab is rebuilt"),)
    )
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml", config))
    assert gate.blocked == ()


def test_summarize_reasons_is_compact():
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml"))
    summary = summarize_reasons(gate.blocked[0])
    assert summary == "PG-005 high"


def test_summarize_reasons_truncates():
    gate = evaluate(report_for(HIGH_TEMPLATE, "gate-high.yaml"))
    summary = summarize_reasons(gate.blocked[0], limit=0)
    assert summary.startswith("+1 more")
