"""PG-003 dangerous capabilities."""
from __future__ import annotations

import pytest


def pg003(report):
    return [finding for finding in report.findings if finding.rule == "PG-003"]


def _nuclei(protocol_block: str, *, matchers: str = "") -> str:
    matchers_block = matchers or """\
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    return f"""\
id: protocol-demo
info:
  name: Protocol demo
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference:
    - https://example.com/advisory
  tags: demo
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/x"
{matchers_block}{protocol_block}"""


@pytest.mark.parametrize("protocol", ["code", "javascript", "file", "headless"])
def test_execution_protocols_are_critical(lint_one, protocol):
    text = f"""\
id: {protocol}-demo
info:
  name: {protocol} demo
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference:
    - https://example.com/advisory
  tags: demo
{protocol}:
  - engine: [sh, -c]
    args: [id]
"""
    report = lint_one(text, f"{protocol}-demo.yaml")
    finding = next(f for f in pg003(report) if protocol in f.message)
    assert finding.severity.value == "critical"


def test_network_protocol_is_high(lint_one):
    text = _nuclei("network:\n  - host: ['{{Hostname}}:22']\n")
    report = lint_one(text, "protocol-demo.yaml")
    finding = next(f for f in pg003(report) if "network" in f.message)
    assert finding.severity.value == "high"


def test_crlf_header_is_high(lint_one):
    text = """\
id: crlf-demo
info:
  name: CRLF demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /x
headers:
  X-Test: "a\\r\\nX-Injected: yes"
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "crlf-demo.yaml")
    finding = next(f for f in pg003(report) if "CR/LF" in f.message)
    assert finding.severity.value == "high"


def test_non_latin1_header_is_medium(lint_one):
    text = """\
id: latin-demo
info:
  name: Latin demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /x
headers:
  X-Test: "测试"
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "latin-demo.yaml")
    finding = next(f for f in pg003(report) if "latin-1" in f.message)
    assert finding.severity.value == "medium"


def test_invalid_header_name_is_medium(lint_one):
    text = """\
id: header-demo
info:
  name: Header demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /x
headers:
  "X Bad": "1"
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "header-demo.yaml")
    assert any("valid HTTP token" in f.message for f in pg003(report))


def test_absolute_url_path_is_high(lint_one):
    text = """\
id: absolute-demo
info:
  name: Absolute demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: https://other.example/x
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "absolute-demo.yaml")
    finding = next(f for f in pg003(report) if "absolute URL" in f.message)
    assert finding.severity.value == "high"


def test_unsafe_flag_is_high(lint_one):
    text = """\
id: unsafe-flag
info:
  name: Unsafe flag
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    unsafe: true
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    report = lint_one(text, "unsafe-flag.yaml")
    finding = next(f for f in pg003(report) if "unsafe" in f.message)
    assert finding.severity.value == "high"


def test_raw_absolute_target_is_high(lint_one):
    text = """\
id: raw-demo
info:
  name: Raw demo
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - raw:
      - |
        GET http://other.example/x HTTP/1.1
        Host: other.example
    matchers:
      - type: word
        words: ["unique-marker"]
"""
    report = lint_one(text, "raw-demo.yaml")
    finding = next(f for f in pg003(report) if "absolute request target" in f.message)
    assert finding.severity.value == "high"


def test_safe_template_has_no_capability_findings(lint_one):
    text = """\
id: safe-demo
info:
  name: Safe demo
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /x
headers:
  Accept: application/json
matchers:
  - type: word
    words: ["unique-marker"]
"""
    report = lint_one(text, "safe-demo.yaml")
    assert pg003(report) == []
