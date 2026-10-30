"""PG-001 metadata contract."""
from __future__ import annotations

import pytest

VALID = """\
id: demo-template
info:
  name: Demo template
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference:
    - https://example.com/advisory
  tags: demo,http
method: GET
path: /demo
matchers:
  - type: word
    words: ["unique-marker"]
"""


def pg001(report):
    return [finding for finding in report.findings if finding.rule == "PG-001"]


def test_valid_template_has_no_findings(lint_one):
    report = lint_one(VALID, "demo-template.yaml")
    assert report.findings == ()
    assert report.score == 100


def test_missing_id(lint_one):
    text = VALID.replace("id: demo-template\n", "")
    report = lint_one(text, "demo-template.yaml")
    messages = [f.message for f in pg001(report)]
    assert any("missing required field 'id'" in message for message in messages)
    assert pg001(report)[0].severity.value == "high"


def test_missing_name(lint_one):
    text = VALID.replace("  name: Demo template\n", "")
    report = lint_one(text, "demo-template.yaml")
    assert any("info.name" in f.message for f in pg001(report))


def test_missing_author_is_medium(lint_one):
    text = VALID.replace("  author: xiangfuhua\n", "")
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "author" in f.message)
    assert finding.severity.value == "medium"
    assert finding.line == 2  # falls back to the info block


def test_missing_severity(lint_one):
    text = VALID.replace("  severity: medium\n", "")
    report = lint_one(text, "demo-template.yaml")
    assert any("info.severity" in f.message for f in pg001(report))


def test_invalid_severity(lint_one):
    text = VALID.replace("severity: medium", "severity: severe")
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "not one of" in f.message)
    assert finding.severity.value == "high"
    assert finding.line == 5


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info", "unknown"])
def test_known_severities_are_accepted(lint_one, severity):
    text = VALID.replace("severity: medium", f"severity: {severity}")
    report = lint_one(text, "demo-template.yaml")
    assert not any("not one of" in f.message for f in pg001(report))


def test_missing_description(lint_one):
    text = VALID.replace(
        "  description: A sufficiently detailed description of the vulnerable condition.\n", ""
    )
    report = lint_one(text, "demo-template.yaml")
    assert any("info.description" in f.message for f in pg001(report))


def test_short_description_is_low(lint_one):
    text = VALID.replace(
        "A sufficiently detailed description of the vulnerable condition.", "Too short."
    )
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "too short" in f.message)
    assert finding.severity.value == "low"


def test_missing_reference(lint_one):
    text = VALID.replace("  reference:\n    - https://example.com/advisory\n", "")
    report = lint_one(text, "demo-template.yaml")
    assert any("info.reference" in f.message for f in pg001(report))


def test_reference_must_be_a_url(lint_one):
    text = VALID.replace("https://example.com/advisory", "advisory-notes.txt")
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "absolute http(s) URL" in f.message)
    assert finding.severity.value == "medium"


def test_missing_tags_is_low(lint_one):
    text = VALID.replace("  tags: demo,http\n", "")
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "tags" in f.message)
    assert finding.severity.value == "low"


def test_cvss_out_of_range(lint_one):
    text = VALID.replace(
        "  tags: demo,http\n",
        "  tags: demo,http\n  classification:\n    cvss-score: 11.2\n",
    )
    report = lint_one(text, "demo-template.yaml")
    finding = next(f for f in pg001(report) if "0.0-10.0" in f.message)
    assert finding.severity.value == "high"


def test_cvss_not_a_number(lint_one):
    text = VALID.replace(
        "  tags: demo,http\n",
        '  tags: demo,http\n  classification:\n    cvss-score: "high"\n',
    )
    report = lint_one(text, "demo-template.yaml")
    assert any("not a number" in f.message for f in pg001(report))
