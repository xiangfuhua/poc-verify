"""Loader: dialect detection, normalization, line mapping and discovery."""
from __future__ import annotations

from pathlib import Path

import pytest

from pocverify.loader import LoadError, load_file, load_templates, load_text
from pocverify.schema import Dialect

FIXTURES = Path(__file__).parent / "fixtures"

NATIVE = """\
id: demo-sqli
info:
  name: Demo SQL injection
  author: xiangfuhua, second-author
  severity: high
  description: The id parameter is concatenated into a SQL query.
  reference:
    - https://example.com/advisory
  tags: demo, sqli
method: GET
path: /vulnerabilities/sqli/
payload:
  id: "1' OR '1'='1"
headers:
  Cookie: "security=low"
matchers:
  - type: word
    words:
      - "ID: 1"
"""


def test_native_template_is_normalized():
    template = load_text(NATIVE, path="pocs/demo-sqli.yaml")
    assert template.dialect is Dialect.NATIVE
    assert template.id == "demo-sqli"
    assert template.name == "Demo SQL injection"
    assert template.authors == ("xiangfuhua", "second-author")
    assert template.severity == "high"
    assert template.tags == ("demo", "sqli")
    assert template.references == ("https://example.com/advisory",)
    request = template.requests[0]
    assert request.method == "GET"
    assert request.paths == ("/vulnerabilities/sqli/",)
    assert request.payload == {"id": "1' OR '1'='1"}
    assert request.header_dict["Cookie"] == "security=low"
    assert [matcher.type for matcher in request.matchers] == ["word"]


def test_legacy_flat_fields_become_matchers():
    template = load_file(FIXTURES / "legacy" / "v1-sqli.yaml")
    assert template.id is None
    assert template.name == "Legacy SQL injection"
    matchers = template.requests[0].matchers
    assert [matcher.type for matcher in matchers] == ["status", "word"]
    assert matchers[0].values == ("200",)
    assert matchers[1].values == ("ID: 1",)


def test_nuclei_template_is_normalized():
    template = load_file(FIXTURES / "nuclei" / "nuclei-basic.yaml")
    assert template.dialect is Dialect.NUCLEI
    assert template.name == "Nuclei basic demo"
    request = template.requests[0]
    assert request.paths == ("{{BaseURL}}/demo",)
    assert request.matchers[0].type == "word"
    assert request.matchers[0].values == ("unique-marker",)


def test_nuclei_cve_cvss_and_protocols():
    template = load_text(
        """\
id: CVE-2024-1234
info:
  name: Example RCE
  author: someone
  severity: critical
  description: Example template.
  reference: https://example.com
  tags: cve,cve2024,rce
  classification:
    cve-id: CVE-2024-1234
    cvss-score: 9.8
code:
  - engine: [sh, -c]
    args: [id]
http:
  - method: POST
    path:
      - "{{BaseURL}}/api"
      - "{{BaseURL}}/v2/api"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["root"]
        negative: true
""",
        path="templates/CVE-2024-1234.yaml",
    )
    assert template.cves == ("CVE-2024-1234",)
    assert template.cvss == 9.8
    assert template.protocols == ("code",)
    request = template.requests[0]
    assert request.method == "POST"
    assert request.paths == ("{{BaseURL}}/api", "{{BaseURL}}/v2/api")
    assert request.matcher_condition == "and"
    assert request.matchers[1].negative is True


def test_native_dialect_wins_when_info_is_present():
    template = load_text(
        """\
id: native-with-info
info:
  name: Native with info
method: GET
path: /x
""",
        path="native-with-info.yaml",
    )
    assert template.dialect is Dialect.NATIVE
    assert template.requests[0].paths == ("/x",)


def test_line_index_maps_nested_paths_and_sequences():
    template = load_text(NATIVE, path="pocs/demo-sqli.yaml")
    assert template.line_at("id") == 1
    assert template.line_at("info", "name") == 3
    assert template.line_at("info", "tags") == 9
    assert template.line_at("matchers", 0, "words") == 18
    assert template.line_at("matchers", 0, "words", 0) == 19
    assert template.line_at("payload", "id") == 13


def test_line_at_walks_up_for_missing_keys():
    template = load_text(NATIVE, path="pocs/demo-sqli.yaml")
    # info.author exists, info.cve-id does not: fall back to the info block.
    assert template.line_at("info", "cve-id") == 2
    assert template.line_at("nope") == 1


def test_duplicate_yaml_keys_are_reported():
    template = load_text(
        """\
id: duplicate-keys
info:
  name: Duplicate keys
  severity: low
  severity: high
method: GET
path: /x
""",
        path="duplicate-keys.yaml",
    )
    assert template.duplicate_keys
    dotted, line = template.duplicate_keys[0]
    assert dotted == "info.severity"
    assert line == 5


def test_empty_template_is_rejected():
    with pytest.raises(LoadError, match="empty template"):
        load_text("", path="empty.yaml")


def test_invalid_yaml_is_rejected():
    with pytest.raises(LoadError, match="invalid YAML"):
        load_text("id: [unclosed\n", path="broken.yaml")


def test_root_must_be_a_mapping():
    with pytest.raises(LoadError, match="root must be a mapping"):
        load_text("- one\n- two\n", path="list.yaml")


def test_bom_is_accepted(tmp_path):
    path = tmp_path / "bom.yaml"
    path.write_bytes("\ufeffid: bom-test\n".encode("utf-8"))
    template = load_file(path)
    assert template.id == "bom-test"


def test_discover_is_recursive_sorted_and_deduplicated():
    result = load_templates([FIXTURES / "duplicates", FIXTURES / "duplicates" / "dup-a.yaml"])
    names = [Path(template.rel_path).name for template in result.templates]
    assert names == ["dup-a.yaml", "dup-b.yaml", "dup-c.yaml"]
    assert result.errors == []
    assert result.files_seen == 3


def test_discover_skips_hidden_files_and_unknown_suffixes(tmp_path):
    (tmp_path / ".pocverify.yaml").write_text("version: 1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a template", encoding="utf-8")
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "one.yaml").write_text("id: one\n", encoding="utf-8")
    result = load_templates([tmp_path])
    assert [Path(t.rel_path).name for t in result.templates] == ["one.yaml"]


def test_load_templates_collects_errors_and_keeps_valid_ones(tmp_path):
    (tmp_path / "good.yaml").write_text("id: good\n", encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("id: [oops\n", encoding="utf-8")
    result = load_templates([tmp_path])
    assert len(result.templates) == 1
    assert len(result.errors) == 1
    assert "bad.yaml" in str(result.errors[0])


def test_missing_path_is_reported():
    result = load_templates(["does-not-exist"])
    assert result.templates == []
    assert "does not exist" in str(result.errors[0])


def test_relative_path_uses_forward_slashes():
    template = load_text(NATIVE, path="pocs/demo-sqli.yaml")
    assert "\\" not in template.rel_path
    assert template.rel_path.endswith("demo-sqli.yaml")
