"""PG-002 identity and CVE consistency."""
from __future__ import annotations

from pocverify.lint.engine import lint

from conftest import load_template

NUCLEI = """\
id: cve-2024-1234
info:
  name: Example issue
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference:
    - https://example.com/advisory
  tags: cve,cve2024,rce
  classification:
    cve-id: CVE-2024-1234
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: word
        words: ["unique-marker"]
"""


def pg002(report):
    return [finding for finding in report.findings if finding.rule == "PG-002"]


def test_valid_identity_has_no_findings(lint_one):
    report = lint_one(NUCLEI, "cve-2024-1234.yaml")
    assert pg002(report) == []


def test_uppercase_id_is_medium(lint_one):
    text = NUCLEI.replace("id: cve-2024-1234", "id: CVE-2024-1234")
    report = lint_one(text, "CVE-2024-1234.yaml")
    finding = next(f for f in pg002(report) if "lowercase" in f.message)
    assert finding.severity.value == "medium"


def test_filename_must_match_id(lint_one):
    report = lint_one(NUCLEI, "wrong-name.yaml")
    finding = next(f for f in pg002(report) if "does not match file name" in f.message)
    assert finding.severity.value == "medium"


def test_duplicate_ids_across_files_are_high():
    first = load_template(NUCLEI, "a.yaml")
    second = load_template(NUCLEI, "b.yaml")
    report = lint([first, second])
    duplicate_findings = [
        finding
        for template_report in report.templates
        for finding in template_report.findings
        if finding.rule == "PG-002" and "duplicate id" in finding.message
    ]
    assert len(duplicate_findings) == 1
    assert duplicate_findings[0].severity.value == "high"
    assert duplicate_findings[0].path.endswith("b.yaml")


def test_cve_mismatch_is_high(lint_one):
    text = NUCLEI.replace("cve-id: CVE-2024-1234", "cve-id: CVE-2024-9999")
    report = lint_one(text, "cve-2024-1234.yaml")
    finding = next(f for f in pg002(report) if "CVE mismatch" in f.message)
    assert finding.severity.value == "high"


def test_declared_cve_without_cve_in_id(lint_one):
    text = NUCLEI.replace("id: cve-2024-1234", "id: example-issue")
    report = lint_one(text, "example-issue.yaml")
    assert any("has no CVE id" in f.message for f in pg002(report))


def test_cve_without_cve_tag_is_low(lint_one):
    text = NUCLEI.replace("tags: cve,cve2024,rce", "tags: demo,rce")
    report = lint_one(text, "cve-2024-1234.yaml")
    finding = next(f for f in pg002(report) if "cveYYYY" in f.message)
    assert finding.severity.value == "low"


def test_duplicate_yaml_keys_are_high(lint_one):
    text = """\
id: duplicate-keys
info:
  name: Duplicate keys
  author: xiangfuhua
  severity: low
  severity: high
  description: A sufficiently detailed description of the issue.
  reference: https://example.com
  tags: demo
method: GET
path: /x
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "duplicate-keys.yaml")
    finding = next(f for f in pg002(report) if "duplicate YAML key" in f.message)
    assert finding.severity.value == "high"
    assert finding.line == 6
