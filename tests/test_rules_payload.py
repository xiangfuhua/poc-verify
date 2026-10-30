"""PG-004 destructive or invasive payloads."""
from __future__ import annotations

BASE = """\
id: payload-demo
info:
  name: Payload demo
  author: xiangfuhua
  severity: high
  description: {description}
  reference: https://example.com/advisory
  tags: demo,sqli
method: POST
path: /submit
payload:
{payload}
matchers:
  - type: word
    words: ["unique-marker"]
"""

SAFE_DESCRIPTION = "A sufficiently detailed description of the vulnerable condition."


def template(payload_lines: str, description: str = SAFE_DESCRIPTION) -> str:
    indented = "\n".join(f"  {line}" for line in payload_lines.strip("\n").splitlines())
    return BASE.format(description=description, payload=indented)


def pg004(report):
    return [finding for finding in report.findings if finding.rule == "PG-004"]


def test_drop_table_is_high(lint_one):
    report = lint_one(template('q: "1; DROP TABLE users; --"'), "payload-demo.yaml")
    finding = next(f for f in pg004(report) if "DROP TABLE" in f.message)
    assert finding.severity.value == "high"
    assert "payload.q" in finding.message
    assert finding.line == 12


def test_delete_without_where_is_high(lint_one):
    report = lint_one(template('q: "DELETE FROM users"'), "payload-demo.yaml")
    assert any("DELETE without WHERE" in f.message for f in pg004(report))


def test_delete_with_where_is_not_flagged(lint_one):
    report = lint_one(template('q: "DELETE FROM users WHERE id = 1"'), "payload-demo.yaml")
    assert pg004(report) == []


def test_time_based_probe_is_medium(lint_one):
    report = lint_one(template('q: "1 AND SLEEP(5)"'), "payload-demo.yaml")
    finding = next(f for f in pg004(report) if "SLEEP()" in f.message)
    assert finding.severity.value == "medium"


def test_shell_payload_is_high(lint_one):
    report = lint_one(template('q: "&& rm -rf /tmp/data"'), "payload-demo.yaml")
    assert any("rm -r[f]" in f.message for f in pg004(report))


def test_into_outfile_is_high(lint_one):
    report = lint_one(template('q: "1 UNION SELECT 1 INTO OUTFILE \'/tmp/x\'"'), "payload-demo.yaml")
    assert any("INTO OUTFILE" in f.message for f in pg004(report))


def test_header_payload_is_scanned(lint_one):
    text = """\
id: payload-demo
info:
  name: Payload demo
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /submit
headers:
  X-Query: "'; TRUNCATE TABLE audit; --"
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "payload-demo.yaml")
    assert any("TRUNCATE TABLE" in f.message for f in pg004(report))


def test_description_mention_is_not_a_payload(lint_one):
    text = template(
        'q: "benign"',
        description="Checks for DROP TABLE statements without sending one.",
    )
    report = lint_one(text, "payload-demo.yaml")
    assert pg004(report) == []


def test_matcher_mention_is_not_a_payload(lint_one):
    text = """\
id: payload-demo
info:
  name: Payload demo
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: POST
path: /submit
payload:
  q: "benign"
matchers:
  - type: word
    words: ["DROP TABLE users"]
"""
    report = lint_one(text, "payload-demo.yaml")
    assert pg004(report) == []


def test_oversized_payload_is_medium(lint_one):
    report = lint_one(template('q: "' + "a" * 5000 + '"'), "payload-demo.yaml")
    finding = next(f for f in pg004(report) if "review limit" in f.message)
    assert finding.severity.value == "medium"


def test_opaque_base64_blob_is_a_warning(lint_one):
    blob = "QUJD" * 16  # 64 characters of base64 alphabet
    report = lint_one(template(f'q: "{blob}"'), "payload-demo.yaml")
    finding = next(f for f in pg004(report) if "opaque blob" in f.message)
    assert finding.severity.value == "warning"
