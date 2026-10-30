"""PG-006 cross-file duplicate detection."""
from __future__ import annotations

from pocverify.lint.engine import lint
from pocverify.loader import load_text

TEMPLATE = """\
id: {id}
info:
  name: {name}
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: {tags}
method: GET
path: {path}
matchers:
  - type: word
    words: ["{word}"]
"""


def native(template_id: str, path: str = "/same", word: str = "unique-marker", tags: str = "demo"):
    return load_text(
        TEMPLATE.format(
            id=template_id,
            name=f"Template {template_id}",
            path=path,
            word=word,
            tags=tags,
        ),
        path=f"{template_id}.yaml",
    )


def pg006(report):
    return [
        finding
        for template_report in report.templates
        for finding in template_report.findings
        if finding.rule == "PG-006"
    ]


def test_identical_templates_are_high_duplicates():
    report = lint([native("dup-a"), native("dup-b")])
    findings = pg006(report)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].path.endswith("dup-b.yaml")
    assert "dup-a.yaml" in findings[0].message


def test_first_copy_is_not_reported():
    report = lint([native("dup-a"), native("dup-b")])
    first = report.for_path("dup-a.yaml")
    assert first is not None
    assert [f for f in first.findings if f.rule == "PG-006"] == []


def test_same_endpoint_different_matchers_is_medium():
    report = lint([native("dup-a"), native("dup-c", word="other-marker")])
    finding = next(f for f in pg006(report) if "different matchers" in f.message)
    assert finding.severity.value == "medium"


def test_different_endpoints_are_not_duplicates():
    report = lint([native("one", path="/one"), native("two", path="/two")])
    assert pg006(report) == []


def test_same_cve_is_low():
    def with_cve(text: str) -> str:
        return text.replace(
            "  tags: cve,cve2024\n",
            "  tags: cve,cve2024\n  classification:\n    cve-id: CVE-2024-1234\n",
        )

    text_a = with_cve(
        TEMPLATE.format(
            id="cve-2024-1234-a",
            name="A",
            path="/a",
            word="unique-marker",
            tags="cve,cve2024",
        )
    )
    text_b = with_cve(
        TEMPLATE.format(
            id="cve-2024-1234-b",
            name="B",
            path="/b",
            word="other-marker",
            tags="cve,cve2024",
        )
    )
    report = lint([load_text(text_a, path="a.yaml"), load_text(text_b, path="b.yaml")])
    finding = next(f for f in pg006(report) if "CVE-2024-1234" in f.message)
    assert finding.severity.value == "low"


def test_cross_dialect_duplicates_are_detected():
    nuclei = """\
id: nuclei-copy
info:
  name: Nuclei copy
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/same"
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    report = lint([native("dup-a"), load_text(nuclei, path="nuclei-copy.yaml")])
    finding = next(f for f in pg006(report) if "duplicate of" in f.message)
    assert finding.severity.value == "high"


def test_raw_request_target_is_used_for_comparison():
    raw = """\
id: {id}
info:
  name: Raw {id}
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - raw:
      - |
        GET /raw-same HTTP/1.1
        Host: {{{{Hostname}}}}
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    report = lint(
        [
            load_text(raw.format(id="raw-a"), path="raw-a.yaml"),
            load_text(raw.format(id="raw-b"), path="raw-b.yaml"),
        ]
    )
    assert any(f.rule == "PG-006" and f.severity.value == "high" for f in report.findings)


def test_path_order_does_not_change_fingerprint():
    text = """\
id: {id}
info:
  name: Path order {id}
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path: {paths}
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    first = load_text(
        text.format(id="order-a", paths='["{{BaseURL}}/one", "{{BaseURL}}/two"]'),
        path="order-a.yaml",
    )
    second = load_text(
        text.format(id="order-b", paths='["{{BaseURL}}/two", "{{BaseURL}}/one"]'),
        path="order-b.yaml",
    )
    report = lint([first, second])
    assert any(f.rule == "PG-006" and f.severity.value == "high" for f in report.findings)
