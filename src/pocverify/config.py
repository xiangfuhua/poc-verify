"""Project configuration (``.pocverify.yaml``).

A waiver is a governance decision, not a mute button, so every ``ignore`` entry
must carry a non-trivial ``reason``. An entry that matches nothing is reported
as a dead waiver, which keeps the config honest as templates are fixed.

Example::

    version: 1
    ignore:
      - rule: PG-005
        file: "pocs/legacy/*.yaml"
        reason: "legacy status-only checks, tracked in issue #12"
    lint:
      fail-on: high
      fail-under: 80
    gate:
      block-on: high
    run:
      allow-unsafe: false
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch, fnmatchcase
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

import yaml

from .schema import Severity

CONFIG_NAMES = (".pocverify.yaml", ".pocverify.yml")
MIN_REASON_LENGTH = 8
_RULE_ID_RE = re.compile(r"^PG-\d{3}$|^PG-\*$")

_TOP_LEVEL = {"version", "ignore", "lint", "gate", "run"}
_LINT_KEYS = {"fail-on", "fail-under", "strict-waivers"}
_GATE_KEYS = {"block-on"}
_RUN_KEYS = {"allow-unsafe"}
_IGNORE_KEYS = {"rule", "file", "reason"}


class ConfigError(Exception):
    """Invalid or missing configuration."""


@dataclass(frozen=True)
class IgnoreRule:
    """A waiver scoped to one rule (or ``PG-*``) and a path glob."""

    rule: str
    file: str = "*"
    reason: str = ""

    def matches(self, rule_id: str, path: str) -> bool:
        if not fnmatchcase(rule_id.upper(), self.rule.upper()):
            return False
        return _path_matches(self.file, path)


@dataclass(frozen=True)
class Config:
    """Everything the linter, the gate and the runner need to know."""

    ignore: Tuple[IgnoreRule, ...] = ()
    fail_on: Severity = Severity.HIGH
    fail_under: Optional[int] = None
    block_on: Severity = Severity.HIGH
    allow_unsafe: bool = False
    strict_waivers: bool = False
    source: Optional[Path] = None


def load_config(
    path: Optional[Path] = None,
    *,
    search: bool = True,
    base_dir: Optional[Path] = None,
) -> Config:
    """Load an explicit config, or the first ``.pocverify.yaml`` beside it."""
    if path is not None:
        candidate = Path(path)
        if not candidate.is_file():
            raise ConfigError(f"config file not found: {candidate}")
        return _parse(candidate)
    if search:
        directory = Path(base_dir) if base_dir else Path.cwd()
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return _parse(candidate)
    return Config()


def _parse(path: Path) -> Config:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in config {path}: {exc}") from exc
    if raw is None:
        return Config(source=path)
    if not isinstance(raw, dict):
        raise ConfigError(f"config {path} must be a mapping")
    _reject_unknown(raw, _TOP_LEVEL, path, "top level")
    version = raw.get("version", 1)
    if version != 1:
        raise ConfigError(f"config {path}: unsupported version {version!r} (expected 1)")

    ignore = tuple(_parse_ignore(entry, path) for entry in _as_list(raw.get("ignore"), path, "ignore"))

    lint = _mapping(raw.get("lint"), path, "lint")
    _reject_unknown(lint, _LINT_KEYS, path, "lint")
    fail_on = _severity(lint.get("fail-on", "high"), path, "lint.fail-on")
    fail_under = lint.get("fail-under")
    if fail_under is not None:
        if not isinstance(fail_under, int) or isinstance(fail_under, bool) or not 0 <= fail_under <= 100:
            raise ConfigError(f"config {path}: lint.fail-under must be an integer between 0 and 100")
    strict = _boolean(lint.get("strict-waivers", False), path, "lint.strict-waivers")

    gate = _mapping(raw.get("gate"), path, "gate")
    _reject_unknown(gate, _GATE_KEYS, path, "gate")
    block_on = _severity(gate.get("block-on", "high"), path, "gate.block-on")

    run = _mapping(raw.get("run"), path, "run")
    _reject_unknown(run, _RUN_KEYS, path, "run")
    allow_unsafe = _boolean(run.get("allow-unsafe", False), path, "run.allow-unsafe")

    return Config(
        ignore=ignore,
        fail_on=fail_on,
        fail_under=fail_under,
        block_on=block_on,
        allow_unsafe=allow_unsafe,
        strict_waivers=strict,
        source=path,
    )


def _parse_ignore(entry: Any, path: Path) -> IgnoreRule:
    if not isinstance(entry, dict):
        raise ConfigError(f"config {path}: every ignore entry must be a mapping")
    _reject_unknown(entry, _IGNORE_KEYS, path, "ignore entry")
    rule = entry.get("rule")
    if not isinstance(rule, str) or not _RULE_ID_RE.match(rule.strip().upper()):
        raise ConfigError(
            f"config {path}: ignore.rule must look like PG-001 (or PG-*), got {rule!r}"
        )
    file_pattern = entry.get("file", "*")
    if not isinstance(file_pattern, str) or not file_pattern.strip():
        raise ConfigError(f"config {path}: ignore.file must be a non-empty glob")
    reason = entry.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON_LENGTH:
        raise ConfigError(
            f"config {path}: ignore entries must carry a reason of at least "
            f"{MIN_REASON_LENGTH} characters (rule {rule} on {file_pattern})"
        )
    return IgnoreRule(rule=rule.strip(), file=file_pattern.strip(), reason=reason.strip())


def _path_matches(pattern: str, path: str) -> bool:
    candidate = path.replace("\\", "/")
    current = pattern.replace("\\", "/")
    # fnmatch() folds case on Windows and stays case-sensitive on POSIX.
    return fnmatch(candidate, current) or fnmatch(Path(candidate).name, current)


def _severity(value: Any, path: Path, field: str) -> Severity:
    severity = Severity.coerce(value)
    if severity is None:
        raise ConfigError(f"config {path}: {field} must be one of critical/high/medium/low/warning")
    return severity


def _mapping(value: Any, path: Path, field: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"config {path}: {field} must be a mapping")
    return value


def _as_list(value: Any, path: Path, field: str) -> Sequence[Any]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"config {path}: {field} must be a list")
    return value


def _boolean(value: Any, path: Path, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"config {path}: {field} must be true or false")
    return value


def _reject_unknown(mapping: Dict[str, Any], allowed: Sequence[str], path: Path, where: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ConfigError(f"config {path}: unknown key(s) in {where}: {', '.join(unknown)}")
