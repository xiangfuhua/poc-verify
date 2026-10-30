"""Request planning, matcher evaluation, DSL subset and live HTTP execution."""
from __future__ import annotations

import pytest

from pocverify.loader import load_text
from pocverify.runner.dsl import UnsupportedMatcher
from pocverify.runner.dsl import evaluate as evaluate_dsl
from pocverify.runner.http import blocked, plan_request, preview, run_template
from pocverify.runner.matchers import evaluate
from pocverify.schema import Matcher

from conftest import load_template

NATIVE_GET = """\
id: plan-get
info:
  name: Plan GET
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /reflect
payload:
  q: "hello world"
  lang: en
headers:
  Cookie: "session=secret"
matchers:
  - type: word
    words: ["unique-marker"]
"""

NATIVE_POST = """\
id: plan-post
info:
  name: Plan POST
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: POST
path: /submit
payload:
  user: admin
matchers:
  - type: word
    words: ["posted:"]
"""

NUCLEI = """\
id: plan-nuclei
info:
  name: Plan nuclei
  author: xiangfuhua
  severity: medium
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/demo"
    matchers:
      - type: word
        words: ["unique-marker"]
"""


def test_native_get_plan_appends_query_and_defaults():
    template = load_template(NATIVE_GET, "plan-get.yaml")
    plans = plan_request(template, template.requests[0], "http://127.0.0.1:8080")
    assert len(plans) == 1
    plan = plans[0]
    assert plan.method == "GET"
    assert plan.url == "http://127.0.0.1:8080/reflect?q=hello+world&lang=en"
    headers = dict(plan.headers)
    assert headers["User-Agent"].startswith("pocverify/")
    assert headers["Cookie"] == "session=secret"
    assert plan.body is None


def test_native_post_plan_sends_a_form_body():
    template = load_template(NATIVE_POST, "plan-post.yaml")
    plan = plan_request(template, template.requests[0], "http://127.0.0.1:8080")[0]
    assert plan.body == b"user=admin"
    headers = dict(plan.headers)
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_nuclei_base_url_is_substituted():
    template = load_template(NUCLEI, "plan-nuclei.yaml")
    plan = plan_request(template, template.requests[0], "http://127.0.0.1:8080")[0]
    assert plan.url == "http://127.0.0.1:8080/demo"


def test_absolute_url_is_refused_by_default():
    template = load_template(
        """\
id: absolute
info:
  name: Absolute
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: http://other.example/x
matchers:
  - type: word
    words: ["unique-marker"]
""",
        "absolute.yaml",
    )
    with pytest.raises(UnsupportedMatcher, match="outside the configured target"):
        plan_request(template, template.requests[0], "http://127.0.0.1:8080")


def test_absolute_url_is_allowed_explicitly():
    template = load_template(
        """\
id: absolute
info:
  name: Absolute
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: http://other.example/x
matchers:
  - type: word
    words: ["unique-marker"]
""",
        "absolute.yaml",
    )
    plan = plan_request(
        template, template.requests[0], "http://127.0.0.1:8080", allowed_external=True
    )[0]
    assert plan.url == "http://other.example/x"


def test_unresolved_variable_is_reported():
    template = load_template(
        """\
id: unresolved
info:
  name: Unresolved
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path: ["{{BaseURL}}/{{missing}}"]
    matchers:
      - type: word
        words: ["unique-marker"]
""",
        "unresolved.yaml",
    )
    with pytest.raises(UnsupportedMatcher, match="unresolved template variable"):
        plan_request(template, template.requests[0], "http://127.0.0.1:8080")


def test_payload_set_expands_to_combinations():
    template = load_text(
        """\
id: combinations
info:
  name: Combinations
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path: ["{{BaseURL}}/search?q={{q}}&lang={{lang}}"]
    payloads:
      q: [one, two]
      lang: [en, fr]
    matchers:
      - type: word
        words: ["unique-marker"]
""",
        path="combinations.yaml",
    )
    plans = plan_request(template, template.requests[0], "http://127.0.0.1:8080")
    assert len(plans) == 4
    urls = {plan.url for plan in plans}
    assert "http://127.0.0.1:8080/search?q=one&lang=fr" in urls
    assert any("q=two" in plan.label for plan in plans)


def test_too_many_payload_combinations_are_refused():
    payloads = "\n".join(f"      k{i}: [a, b]" for i in range(8))
    template = load_text(
        f"""\
id: too-many
info:
  name: Too many
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - method: GET
    path: ["{{{{BaseURL}}}}/x?q={{{{k0}}}}"]
    payloads:
{payloads}
    matchers:
      - type: word
        words: ["unique-marker"]
""",
        path="too-many.yaml",
    )
    with pytest.raises(UnsupportedMatcher, match="combinations"):
        plan_request(template, template.requests[0], "http://127.0.0.1:8080")


def test_raw_request_is_parsed_and_host_is_dropped():
    template = load_text(
        """\
id: raw-plan
info:
  name: Raw plan
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
http:
  - raw:
      - |
        POST /raw HTTP/1.1
        Host: evil.example
        X-Test: one
        Content-Type: text/plain

        hello
    matchers:
      - type: word
        words: ["unique-marker"]
""",
        path="raw-plan.yaml",
    )
    plan = plan_request(template, template.requests[0], "http://127.0.0.1:8080")[0]
    assert plan.method == "POST"
    assert plan.url == "http://127.0.0.1:8080/raw"
    assert dict(plan.headers) == {"X-Test": "one", "Content-Type": "text/plain"}
    assert plan.body == b"hello"


def test_preview_masks_sensitive_headers():
    template = load_template(NATIVE_GET, "plan-get.yaml")
    plans = plan_request(template, template.requests[0], "http://127.0.0.1:8080")
    lines = preview(plans)
    rendered = "\n".join(lines)
    assert "Cookie: ***" in rendered
    assert "secret" not in rendered
    assert "headers:" in rendered


def test_status_matcher():
    outcome = evaluate([Matcher("status", ("200", "201"))], "or", status=201, body="", headers="")
    assert outcome.matched is True
    assert outcome.matched_by == "status"


def test_status_matcher_rejects_non_numeric_values():
    with pytest.raises(UnsupportedMatcher):
        evaluate([Matcher("status", ("ok",))], "or", status=200, body="", headers="")


def test_word_matcher_returns_evidence():
    body = "prefix unique-marker suffix"
    outcome = evaluate([Matcher("word", ("unique-marker",))], "or", status=200, body=body, headers="")
    assert outcome.matched
    assert "unique-marker" in outcome.evidence


def test_word_matcher_can_read_headers():
    outcome = evaluate(
        [Matcher("word", ("yes",), part="header")],
        "or",
        status=200,
        body="",
        headers="X-Marker: yes",
    )
    assert outcome.matched


def test_regex_matcher():
    outcome = evaluate([Matcher("regex", ("root:x:0:0",))], "or", status=200, body="root:x:0:0:root", headers="")
    assert outcome.matched
    assert outcome.evidence == "root:x:0:0"


def test_size_matcher():
    assert evaluate([Matcher("size", ("==5",))], "or", status=200, body="12345", headers="").matched
    assert not evaluate([Matcher("size", (">5",))], "or", status=200, body="12345", headers="").matched


def test_negative_matcher_inverts():
    outcome = evaluate(
        [Matcher("word", ("forbidden",), negative=True)],
        "or",
        status=200,
        body="all good",
        headers="",
    )
    assert outcome.matched


def test_and_condition_requires_all_matchers():
    matchers = [Matcher("status", ("200",)), Matcher("word", ("unique-marker",))]
    assert evaluate(matchers, "and", status=200, body="unique-marker", headers="").matched
    assert not evaluate(matchers, "and", status=200, body="nope", headers="").matched


def test_unsupported_matcher_type_raises():
    with pytest.raises(UnsupportedMatcher):
        evaluate([Matcher("xpath", ("//div",))], "or", status=200, body="", headers="")


def test_dsl_status_and_content():
    assert evaluate_dsl("status_code == 200", status=200, body="")
    assert not evaluate_dsl("status_code == 200", status=404, body="")
    assert evaluate_dsl("contains(body, 'unique-marker')", status=200, body="a unique-marker b")
    assert evaluate_dsl("contains_all(body, 'a', 'b')", status=200, body="ab")
    assert evaluate_dsl("len(body) > 3", status=200, body="abcd")
    assert evaluate_dsl("regex('unique-\\w+', body)", status=200, body="unique-marker")


def test_dsl_boolean_precedence():
    expression = "status_code == 200 && contains(body, 'x') || contains(body, 'y')"
    assert evaluate_dsl(expression, status=200, body="x")
    assert evaluate_dsl(expression, status=500, body="y")
    assert not evaluate_dsl(expression, status=500, body="x")


def test_dsl_unsupported_syntax_raises():
    with pytest.raises(UnsupportedMatcher):
        evaluate_dsl("sha256(body) == 'x'", status=200, body="")


def test_run_template_pass(lab_server):
    template = load_text(
        """\
id: run-pass
info:
  name: Run pass
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
""",
        path="run-pass.yaml",
    )
    result = run_template(template, lab_server)
    assert result.status == "PASS"
    assert result.http_status == 200
    assert result.matched_by == "word"
    assert "unique-marker" in result.evidence


def test_run_template_fail(lab_server):
    template = load_text(
        """\
id: run-fail
info:
  name: Run fail
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /ok
matchers:
  - type: word
    words: ["not-present-anywhere"]
""",
        path="run-fail.yaml",
    )
    assert run_template(template, lab_server).status == "FAIL"


def test_http_error_status_is_a_response(lab_server):
    template = load_text(
        """\
id: run-401
info:
  name: Run 401
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /login
matchers:
  - type: status
    status: [401]
""",
        path="run-401.yaml",
    )
    result = run_template(template, lab_server)
    assert result.status == "PASS"
    assert result.http_status == 401


def test_response_body_is_capped(lab_server):
    template = load_text(
        """\
id: run-big
info:
  name: Run big
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /big
matchers:
  - type: word
    words: ["xxxx"]
""",
        path="run-big.yaml",
    )
    result = run_template(template, lab_server, max_response_size=100)
    assert result.status == "PASS"
    assert result.requests[0].truncated is True


def test_same_origin_redirect_is_followed(lab_server):
    template = load_text(
        """\
id: run-redirect
info:
  name: Run redirect
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /redirect
matchers:
  - type: word
    words: ["unique-marker"]
""",
        path="run-redirect.yaml",
    )
    result = run_template(template, lab_server)
    assert result.status == "PASS"
    assert result.http_status == 200


def test_cross_origin_redirect_is_not_followed(lab_server):
    template = load_text(
        """\
id: run-offsite
info:
  name: Run offsite
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /offsite
matchers:
  - type: status
    status: [302]
""",
        path="run-offsite.yaml",
    )
    result = run_template(template, lab_server)
    assert result.status == "PASS"
    assert result.http_status == 302


def test_post_body_is_sent(lab_server):
    template = load_template(NATIVE_POST, "plan-post.yaml")
    result = run_template(template, lab_server)
    assert result.status == "PASS"
    assert "posted:user=admin" in result.evidence


def test_connection_error_is_reported():
    template = load_template(NATIVE_POST, "plan-post.yaml")
    result = run_template(template, "http://127.0.0.1:9", retries=0, timeout=1)
    assert result.status == "ERROR"
    assert result.failure


def test_template_without_requests_errors():
    template = load_text("id: empty\ninfo:\n  name: Empty\n", path="empty.yaml")
    result = run_template(template, "http://127.0.0.1:9")
    assert result.status == "ERROR"


def test_blocked_result_carries_reasons():
    template = load_template(NATIVE_POST, "plan-post.yaml")
    result = blocked(template, ["PG-003 critical: code"])
    assert result.status == "BLOCKED"
    assert result.blocked_reasons == ("PG-003 critical: code",)
