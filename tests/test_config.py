"""Configuration parsing, validation and waiver matching."""
from __future__ import annotations

import pytest

from pocverify.config import Config, ConfigError, IgnoreRule, load_config

VALID = """\
version: 1
ignore:
  - rule: PG-005
    file: "pocs/legacy/*.yaml"
    reason: "legacy status-only checks, tracked in issue #12"
lint:
  fail-on: medium
  fail-under: 70
  strict-waivers: true
gate:
  block-on: critical
run:
  allow-unsafe: true
"""


def write(tmp_path, text: str, name: str = ".pocverify.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_config_is_parsed(tmp_path):
    config = load_config(write(tmp_path, VALID))
    assert config.fail_on.value == "medium"
    assert config.fail_under == 70
    assert config.block_on.value == "critical"
    assert config.allow_unsafe is True
    assert config.strict_waivers is True
    assert len(config.ignore) == 1
    assert config.ignore[0].rule == "PG-005"
    assert config.ignore[0].file == "pocs/legacy/*.yaml"
    assert config.source is not None


def test_missing_config_path_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_defaults_when_no_config_is_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.fail_on.value == "high"
    assert config.block_on.value == "high"
    assert config.fail_under is None
    assert config.ignore == ()


def test_config_is_discovered_in_the_working_directory(tmp_path, monkeypatch):
    write(tmp_path, "version: 1\nlint:\n  fail-on: low\n")
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.fail_on.value == "low"


def test_waiver_requires_a_reason(tmp_path):
    text = """\
ignore:
  - rule: PG-005
    file: "*.yaml"
    reason: "short"
"""
    with pytest.raises(ConfigError, match="reason"):
        load_config(write(tmp_path, text))


def test_waiver_requires_a_rule(tmp_path):
    text = """\
ignore:
  - file: "*.yaml"
    reason: "a long enough reason"
"""
    with pytest.raises(ConfigError, match="ignore.rule"):
        load_config(write(tmp_path, text))


def test_waiver_rule_must_look_like_a_rule_id(tmp_path):
    text = """\
ignore:
  - rule: PG5
    reason: "a long enough reason"
"""
    with pytest.raises(ConfigError, match="PG-001"):
        load_config(write(tmp_path, text))


def test_unknown_top_level_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(write(tmp_path, "version: 1\nignores: []\n"))


def test_unknown_nested_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(write(tmp_path, "lint:\n  fail_on: high\n"))


def test_invalid_severity_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="fail-on"):
        load_config(write(tmp_path, "lint:\n  fail-on: urgent\n"))


def test_fail_under_must_be_a_percentage(tmp_path):
    with pytest.raises(ConfigError, match="fail-under"):
        load_config(write(tmp_path, "lint:\n  fail-under: 120\n"))


def test_unsupported_version_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="version"):
        load_config(write(tmp_path, "version: 2\n"))


def test_ignore_rule_matches_glob_and_rule_pattern():
    waiver = IgnoreRule(rule="PG-005", file="pocs/legacy/*.yaml", reason="legacy")
    assert waiver.matches("PG-005", "pocs/legacy/a.yaml")
    assert not waiver.matches("PG-005", "pocs/new/a.yaml")
    assert not waiver.matches("PG-001", "pocs/legacy/a.yaml")


def test_ignore_rule_supports_a_rule_wildcard():
    waiver = IgnoreRule(rule="PG-*", file="*.yaml", reason="legacy")
    assert waiver.matches("PG-001", "a.yaml")
    assert waiver.matches("PG-006", "b.yaml")


def test_ignore_rule_matches_file_name_only():
    waiver = IgnoreRule(rule="PG-005", file="*.yaml", reason="any yaml")
    assert waiver.matches("PG-005", "deep/nested/a.yaml")


def test_config_object_defaults_are_stable():
    config = Config()
    assert config.fail_on.value == "high"
    assert config.block_on.value == "high"
    assert config.ignore == ()
