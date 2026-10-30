"""End-to-end CLI behaviour: exit codes, formats, gate wiring and dry-run."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pocverify.cli import main

GOOD = """\
id: demo
info:
  name: Demo
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
"""

BAD = """\
id: bad
info:
  name: Bad
  author: xiangfuhua
  severity: high
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /login
payload:
  q: "'; DROP TABLE users; --"
matchers:
  - type: status
    status: [200]
"""

LOW_FINDING = """\
id: low
info:
  name: Low
  author: xiangfuhua
  severity: low
  description: A sufficiently detailed description of the vulnerable condition.
  reference: https://example.com/advisory
  tags: demo
method: GET
path: /ok
matchers:
  - type: word
    words: ["ok"]
"""


def run_lint(tmp_path, capsys, text, *extra):
    path = tmp_path / "demo.yaml"
    path.write_text(text, encoding="utf-8")
    return main(["lint", str(path), "--no-color", *extra])


def test_lint_passes_and_prints_a_verdict(tmp_path, capsys):
    code = run_lint(tmp_path, capsys, GOOD)
    output = capsys.readouterr().out
    assert code == 0
    assert "gate passed" in output


def test_lint_fails_on_high_findings(tmp_path, capsys):
    code = run_lint(tmp_path, capsys, BAD)
    output = capsys.readouterr().out
    assert code == 1
    assert "gate failed" in output
    assert "PG-004" in output


def test_lint_reports_yaml_errors_with_exit_two(tmp_path, capsys):
    path = tmp_path / "broken.yaml"
    path.write_text("id: [unclosed\n", encoding="utf-8")
    code = main(["lint", str(path), "--no-color"])
    captured = capsys.readouterr()
    assert code == 2
    assert "load error" in captured.out


def test_lint_empty_scan_is_an_error(tmp_path, capsys):
    code = main(["lint", str(tmp_path), "--no-color"])
    captured = capsys.readouterr()
    assert code == 2
    assert "no templates found" in captured.out


def test_lint_json_output(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    output = tmp_path / "result.json"
    code = main(["lint", str(path), "--format", "json", "-o", str(output), "--no-color"])
    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["summary"]["templates"] == 1
    assert payload["summary"]["score"] == 100
    assert payload["templates"][0]["id"] == "demo"


def test_lint_sarif_output(tmp_path):
    path = tmp_path / "demo.yaml"
    path.write_text(BAD, encoding="utf-8")
    output = tmp_path / "pocverify.sarif"
    code = main(["lint", str(path), "--format", "sarif", "-o", str(output), "--no-color"])
    assert code == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "pocverify"
    assert payload["runs"][0]["results"]


def test_lint_fail_under(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(LOW_FINDING, encoding="utf-8")
    code = main(["lint", str(path), "--fail-under", "100", "--no-color"])
    output = capsys.readouterr().out
    assert code == 1
    assert "score below 100" in output


def test_lint_fail_under_is_validated(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    code = main(["lint", str(path), "--fail-under", "101", "--no-color"])
    assert code == 2


def test_missing_config_is_a_usage_error(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    code = main(["lint", str(path), "--config", str(tmp_path / "missing.yaml"), "--no-color"])
    assert code == 2
    assert "config error" in capsys.readouterr().out


def test_config_waiver_passes(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(BAD, encoding="utf-8")
    config = tmp_path / "waivers.yaml"
    config.write_text(
        "version: 1\nignore:\n  - rule: PG-004\n    file: '*'\n"
        "    reason: 'the target is a disposable lab database'\n"
        "  - rule: PG-005\n    file: '*'\n"
        "    reason: 'status code is the documented indicator here'\n",
        encoding="utf-8",
    )
    code = main(["lint", str(path), "--config", str(config), "--no-color"])
    assert code == 0


def test_strict_waivers_fail_on_unused_entries(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    config = tmp_path / "waivers.yaml"
    config.write_text(
        "version: 1\nignore:\n  - rule: PG-005\n    file: 'never/*.yaml'\n"
        "    reason: 'this entry no longer matches anything'\n",
        encoding="utf-8",
    )
    code = main(["lint", str(path), "--config", str(config), "--strict-waivers", "--no-color"])
    assert code == 1


def test_rules_json_lists_every_rule(capsys):
    code = main(["rules", "--format", "json"])
    assert code == 0
    rules = json.loads(capsys.readouterr().out)
    assert [rule["id"] for rule in rules] == [
        "PG-001",
        "PG-002",
        "PG-003",
        "PG-004",
        "PG-005",
        "PG-006",
    ]


def test_dry_run_never_sends_a_request(tmp_path, capsys):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    report_dir = tmp_path / "reports"
    code = main(
        [
            "run",
            str(path),
            "--target",
            "http://127.0.0.1:9",
            "--dry-run",
            "--report-dir",
            str(report_dir),
            "--no-color",
        ]
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "GET http://127.0.0.1:9/ok" in output
    reports = list(report_dir.glob("*.md"))
    assert len(reports) == 1
    assert "dry-run" in reports[0].read_text(encoding="utf-8")


def test_run_blocks_unsafe_template(tmp_path, capsys):
    path = tmp_path / "bad.yaml"
    path.write_text(BAD, encoding="utf-8")
    report_dir = tmp_path / "reports"
    code = main(
        [
            "run",
            str(path),
            "--target",
            "http://127.0.0.1:9",
            "--report-dir",
            str(report_dir),
            "--no-color",
        ]
    )
    output = capsys.readouterr().out
    assert code == 1
    assert "BLOCKED" in output
    assert "blocked" in next(report_dir.glob("*.md")).read_text(encoding="utf-8")


def test_allow_unsafe_then_dry_run(tmp_path, capsys):
    path = tmp_path / "bad.yaml"
    path.write_text(BAD, encoding="utf-8")
    code = main(
        [
            "run",
            str(path),
            "--target",
            "http://127.0.0.1:9",
            "--allow-unsafe",
            "--dry-run",
            "--no-report",
            "--no-color",
        ]
    )
    assert code == 0


def test_run_passes_against_the_lab(tmp_path, capsys, lab_server):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD, encoding="utf-8")
    report_dir = tmp_path / "reports"
    code = main(
        [
            "run",
            str(path),
            "--target",
            lab_server,
            "--report-dir",
            str(report_dir),
            "--no-color",
        ]
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "PASS" in output
    report = next(report_dir.glob("*.md")).read_text(encoding="utf-8")
    assert "unique-marker" in report


def test_run_fails_when_the_matcher_does_not_match(tmp_path, capsys, lab_server):
    path = tmp_path / "demo.yaml"
    path.write_text(GOOD.replace("unique-marker", "not-there"), encoding="utf-8")
    code = main(
        [
            "run",
            str(path),
            "--target",
            lab_server,
            "--no-report",
            "--no-color",
        ]
    )
    assert code == 1


def test_no_lint_executes_blocked_templates(tmp_path, capsys, lab_server):
    path = tmp_path / "bad.yaml"
    path.write_text(BAD, encoding="utf-8")
    code = main(
        [
            "run",
            str(path),
            "--target",
            lab_server,
            "--no-lint",
            "--no-report",
            "--no-color",
        ]
    )
    output = capsys.readouterr().out
    assert code == 1
    assert "BLOCKED" not in output


def test_missing_target_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit):
        main(["run", str(tmp_path)])


def test_version_flag():
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
