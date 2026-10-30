"""Domain model shared by the loader, the linter, the gate and the runner.

Everything downstream of the loader speaks this model, so a lint rule never has
to care whether the file it is looking at is a native PoCVerify template or a
Nuclei template. Dialect differences are absorbed once, in ``loader.py``.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


class Severity(enum.Enum):
    """Finding severity. ``rank`` is "badness order", ``weight`` is score cost."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    WARNING = "warning"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @property
    def weight(self) -> int:
        return _WEIGHT[self.value]

    @property
    def sarif_level(self) -> str:
        return _SARIF[self.value]

    @classmethod
    def coerce(cls, value: Any) -> "Optional[Severity]":
        """Parse a severity name, returning ``None`` for anything unknown."""
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        try:
            return cls(value.strip().lower())
        except ValueError:
            return None

    def at_least(self, other: "Severity") -> bool:
        """True when this severity is at least as bad as ``other``."""
        return self.rank <= other.rank

    def __str__(self) -> str:  # nicer f-strings and table cells
        return self.value


_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "warning": 4}
_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "warning": 0}
_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "warning": "note",
}

# Matcher types and DSL functions the runner can actually evaluate. Anything
# else is reported by PG-005, because a result it cannot verify is not a pass.
SUPPORTED_MATCHER_TYPES = frozenset({"status", "word", "regex", "size", "dsl"})
SUPPORTED_DSL_FUNCTIONS = frozenset({"contains", "contains_all", "contains_any", "regex"})


class Dialect(enum.Enum):
    """Template dialect understood by the loader."""

    NATIVE = "native"
    NUCLEI = "nuclei"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RuleMeta:
    """Static description of a lint rule (used by CLI, SARIF and docs)."""

    id: str
    title: str
    description: str
    default_severity: Severity
    help_anchor: str = ""

    @property
    def help_uri(self) -> str:
        base = "https://github.com/xiangfuhua/poc-verify/blob/main/docs/rules.md"
        if self.help_anchor:
            return f"{base}#{self.help_anchor}"
        return base


@dataclass(frozen=True)
class Matcher:
    """One normalized matcher, independent of the source dialect."""

    type: str
    values: Tuple[str, ...] = ()
    condition: str = "or"
    negative: bool = False
    part: str = "body"

    def signature(self) -> Tuple[str, Tuple[str, ...]]:
        """Stable, case-insensitive fingerprint fragment."""
        values = tuple(sorted(str(v).strip().lower() for v in self.values))
        return (self.type, values)


@dataclass(frozen=True)
class Request:
    """One request definition plus the matchers that judge its response."""

    index: int = 0
    method: str = "GET"
    paths: Tuple[str, ...] = ()
    payload: Dict[str, Any] = None  # type: ignore[assignment]  # native form/query
    payloads: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()  # nuclei payload sets
    headers: Tuple[Tuple[str, str], ...] = ()
    body: str = ""
    raw: str = ""
    matchers: Tuple[Matcher, ...] = ()
    matcher_condition: str = "or"
    unsafe: bool = False

    def __post_init__(self) -> None:
        if self.payload is None:
            object.__setattr__(self, "payload", {})

    @property
    def header_dict(self) -> Dict[str, str]:
        return dict(self.headers)


@dataclass(frozen=True)
class Template:
    """A parsed template, whichever dialect it came from."""

    path: Path
    rel_path: str
    text: str
    data: Dict[str, Any]
    dialect: Dialect
    id: Optional[str] = None
    name: Optional[str] = None
    authors: Tuple[str, ...] = ()
    severity: Optional[str] = None
    description: Optional[str] = None
    references: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    cves: Tuple[str, ...] = ()
    cvss: Optional[float] = None
    protocols: Tuple[str, ...] = ()
    requests: Tuple[Request, ...] = ()
    lines: Dict[Tuple[Any, ...], int] = None  # type: ignore[assignment]
    duplicate_keys: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if self.lines is None:
            object.__setattr__(self, "lines", {})

    # -- presentation -----------------------------------------------------
    @property
    def display(self) -> str:
        return self.name or self.id or Path(self.rel_path).name

    @property
    def filename_stem(self) -> str:
        return Path(self.path).stem

    @property
    def all_matchers(self) -> Tuple[Matcher, ...]:
        out = []
        for request in self.requests:
            out.extend(request.matchers)
        return tuple(out)

    # -- source locations -------------------------------------------------
    def line_at(self, *yaml_path: Any) -> Optional[int]:
        """Line of a YAML path, walking up parents when the key is absent."""
        key = tuple(yaml_path)
        while key:
            if key in self.lines:
                return self.lines[key]
            key = key[:-1]
        return 1

    def text_line(self, needle: str) -> Optional[int]:
        """Best-effort line of a literal value found in the raw source."""
        if not needle:
            return None
        haystack = needle.lower()
        for number, line in enumerate(self.text.splitlines(), start=1):
            if haystack in line.lower():
                return number
        return None

    def source_line(self, needle: str, *yaml_path: Any) -> int:
        """Prefer the exact YAML key line, else the line the value appears on."""
        line = self.line_at(*yaml_path)
        if yaml_path and tuple(yaml_path) in self.lines:
            return line or 1
        return self.text_line(needle) or line or 1

    # -- scores -----------------------------------------------------------
    def score(self, findings: Iterable["Finding"]) -> int:
        penalty = sum(f.severity.weight for f in findings if not f.waived)
        return max(0, 100 - penalty)


@dataclass(frozen=True)
class Finding:
    """A single lint finding with a precise source location."""

    rule: str
    severity: Severity
    message: str
    path: str = ""
    line: Optional[int] = None
    hint: str = ""
    waived: bool = False
    reason: str = ""

    def waive(self, reason: str) -> "Finding":
        return replace(self, waived=True, reason=reason)

    @property
    def location(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        return self.path

    @property
    def sort_key(self) -> Tuple[int, int, str, str]:
        return (self.severity.rank, self.line or 0, self.rule, self.message)


def make_finding(
    rule: str,
    severity: Severity,
    message: str,
    template: Template,
    line: Optional[int] = None,
    hint: str = "",
) -> Finding:
    """Build a finding bound to a template, defaulting to line 1."""
    return Finding(
        rule=rule,
        severity=severity,
        message=message,
        path=template.rel_path,
        line=line or 1,
        hint=hint,
    )
