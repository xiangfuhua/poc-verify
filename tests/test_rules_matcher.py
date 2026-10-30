"""PG-005 weak matchers."""
from __future__ import annotations

BASE = """\
id: matcher-demo
info:
  name: Matcher demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /demo
matchers:
{matchers}
"""


def template(matchers: str) -> str:
    return BASE.format(matchers="\n".join(f"  {line}" for line in matchers.strip("\n").splitlines()))


def pg005(report):
    return [finding for finding in report.findings if finding.rule == "PG-005"]


def test_status_only_200_is_high(lint_one):
    report = lint_one(template("""\
- type: status
  status: [200]
"""), "matcher-demo.yaml")
    finding = next(f for f in pg005(report) if "every 200 response" in f.message)
    assert finding.severity.value == "high"


def test_status_only_other_codes_is_medium(lint_one):
    report = lint_one(template("""\
- type: status
  status: [401, 403]
"""), "matcher-demo.yaml")
    finding = next(f for f in pg005(report) if "only on status code" in f.message)
    assert finding.severity.value == "medium"


def test_status_plus_content_is_accepted(lint_one):
    report = lint_one(template("""\
- type: status
  status: [200]
- type: word
  words: ["unique-marker"]
"""), "matcher-demo.yaml")
    assert pg005(report) == []


def test_greedy_regex_is_high(lint_one):
    report = lint_one(template("""\
- type: regex
  regex: [".*"]
"""), "matcher-demo.yaml")
    finding = next(f for f in pg005(report) if "literal characters" in f.message)
    assert finding.severity.value == "high"


def test_specific_regex_is_accepted(lint_one):
    report = lint_one(template("""\
- type: regex
  regex: ["root:x:0:0"]
"""), "matcher-demo.yaml")
    assert pg005(report) == []


def test_short_word_is_medium(lint_one):
    report = lint_one(template("""\
- type: word
  words: ["ok"]
"""), "matcher-demo.yaml")
    assert any("shorter than" in f.message for f in pg005(report))


def test_ubiquitous_word_is_medium(lint_one):
    report = lint_one(template("""\
- type: word
  words: ["error"]
"""), "matcher-demo.yaml")
    assert any("most pages" in f.message for f in pg005(report))


def test_all_negative_matchers_is_high(lint_one):
    report = lint_one(template("""\
- type: word
  words: ["not found"]
  negative: true
- type: word
  words: ["access denied"]
  negative: true
"""), "matcher-demo.yaml")
    assert any("every matcher is negative" in f.message for f in pg005(report))


def test_negative_plus_positive_is_fine(lint_one):
    report = lint_one(template("""\
- type: word
  words: ["unique-marker"]
- type: word
  words: ["not found"]
  negative: true
"""), "matcher-demo.yaml")
    assert pg005(report) == []


def test_and_with_mutually_exclusive_status_is_high(lint_one):
    text = BASE.format(
        matchers="""\
  - type: status
    status: [200]
  - type: status
    status: [403]
"""
    ).replace("matchers:\n", "matchers-condition: and\nmatchers:\n", 1)
    report = lint_one(text, "matcher-demo.yaml")
    assert any("mutually exclusive" in f.message for f in pg005(report))


def test_unsupported_matcher_type_is_high(lint_one):
    report = lint_one(template("""\
- type: xpath
  xpath: ["//div"]
"""), "matcher-demo.yaml")
    finding = next(f for f in pg005(report) if "not supported by the runner" in f.message)
    assert finding.severity.value == "high"


def test_empty_matcher_values_is_high(lint_one):
    report = lint_one(template("""\
- type: word
  words: []
"""), "matcher-demo.yaml")
    assert any("has no values" in f.message for f in pg005(report))


def test_status_only_dsl_is_high(lint_one):
    report = lint_one(template("""\
- type: dsl
  dsl: ["status_code == 200"]
"""), "matcher-demo.yaml")
    assert any("only checks for status 200" in f.message for f in pg005(report))


def test_content_dsl_is_accepted(lint_one):
    report = lint_one(template("""\
- type: dsl
  dsl: ["contains(body, 'unique-marker')"]
"""), "matcher-demo.yaml")
    assert pg005(report) == []


def test_size_only_is_low(lint_one):
    report = lint_one(template("""\
- type: size
  size: [1024]
"""), "matcher-demo.yaml")
    finding = next(f for f in pg005(report) if "size-only" in f.message)
    assert finding.severity.value == "low"


def test_template_without_requests_is_high(lint_one):
    text = """\
id: no-requests
info:
  name: No requests
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
"""
    report = lint_one(text, "no-requests.yaml")
    assert any("defines no request" in f.message for f in pg005(report))


def test_request_without_matchers_is_high(lint_one):
    text = """\
id: no-matchers
info:
  name: No matchers
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /x
"""
    report = lint_one(text, "no-matchers.yaml")
    assert any("no matchers" in f.message for f in pg005(report))
