"""PG-004: destructive or invasive payloads.

The linter never executes a template, but it can read what the payload asks the
target to do. A PoC that drops a table proves a vulnerability by breaking the
target, which is not acceptable in shared pipelines.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Pattern, Tuple

from ...schema import Finding, RuleMeta, Severity, Template, make_finding
from .base import Rule, request_text_fields

RULE_ID = "PG-004"
MAX_REVIEWABLE_FIELD = 4096

# (pattern, human label). These mutate or hand over the target.
DESTRUCTIVE_PATTERNS: Tuple[Tuple[Pattern[str], str], ...] = (
    (re.compile(r"\bdrop\s+(?:table|database|schema)\b", re.IGNORECASE), "DROP TABLE/DATABASE"),
    (re.compile(r"\btruncate\s+table\b", re.IGNORECASE), "TRUNCATE TABLE"),
    (re.compile(r"\bdelete\s+from\b(?![^;]*\bwhere\b)", re.IGNORECASE), "DELETE without WHERE"),
    (re.compile(r"\bxp_cmdshell\b", re.IGNORECASE), "xp_cmdshell"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*\b", re.IGNORECASE), "rm -r[f]"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.IGNORECASE), "mkfs"),
    (re.compile(r"\bdd\s+if=", re.IGNORECASE), "dd if="),
    (re.compile(r"\bshutdown\s+(?:-h\s+)?(?:now|/s|/r)\b", re.IGNORECASE), "shutdown"),
    (re.compile(r":\s*\(\s*\)\s*\{[^}]*\|\s*:\s*&", re.IGNORECASE), "fork bomb"),
    (re.compile(r"--os-shell\b", re.IGNORECASE), "sqlmap --os-shell"),
    (re.compile(r"--dump-all\b", re.IGNORECASE), "sqlmap --dump-all"),
    (re.compile(r"\binto\s+outfile\b", re.IGNORECASE), "INTO OUTFILE"),
    (re.compile(r"\bload_file\s*\(", re.IGNORECASE), "LOAD_FILE()"),
    (re.compile(r"\balter\s+table\b[^;]*\bdrop\b", re.IGNORECASE), "ALTER TABLE ... DROP"),
    (re.compile(r"\bchmod\s+777\b", re.IGNORECASE), "chmod 777"),
    (re.compile(r"\b(?:wget|curl)\s+[^\s|]+\s*\|\s*(?:sh|bash)\b", re.IGNORECASE), "download-and-execute"),
)

# Slower but still intrusive: they hold the target's resources open.
INTRUSIVE_PATTERNS: Tuple[Tuple[Pattern[str], str], ...] = (
    (re.compile(r"\bsleep\s*\(", re.IGNORECASE), "SLEEP()"),
    (re.compile(r"\bbenchmark\s*\(", re.IGNORECASE), "BENCHMARK()"),
    (re.compile(r"\bpg_sleep\s*\(", re.IGNORECASE), "pg_sleep()"),
    (re.compile(r"\bwaitfor\s+delay\b", re.IGNORECASE), "WAITFOR DELAY"),
    (re.compile(r"\bdbms_lock\.sleep\b", re.IGNORECASE), "DBMS_LOCK.SLEEP"),
)

_OPAQUE_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


class PayloadRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Destructive or invasive payload",
        description=(
            "Scans request paths, parameters, headers, bodies and raw requests for "
            "statements that mutate or exhaust the target, and for oversized or "
            "opaque payloads that a reviewer cannot audit."
        ),
        default_severity=Severity.HIGH,
        help_anchor="pg-004-destructive-or-invasive-payload",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        findings: List[Finding] = []
        seen = set()

        def add(severity: Severity, message: str, line: Optional[int], hint: str = "") -> None:
            key = (severity, message, line)
            if key in seen:
                return
            seen.add(key)
            findings.append(make_finding(RULE_ID, severity, message, template, line, hint))

        for field in request_text_fields(template):
            value = field.value
            if not value:
                continue
            line = _line_for(template, field.value, field.yaml_path)
            for pattern, label in DESTRUCTIVE_PATTERNS:
                if pattern.search(value):
                    add(
                        Severity.HIGH,
                        f"{field.label} contains a destructive payload ({label})",
                        line,
                        "remove it, or scope it to a disposable test target and waive "
                        "PG-004 with a reason",
                    )
            for pattern, label in INTRUSIVE_PATTERNS:
                if pattern.search(value):
                    add(
                        Severity.MEDIUM,
                        f"{field.label} uses a time-based probe ({label})",
                        line,
                        "time-based probes are slow and noisy; prefer a content check",
                    )
            if len(value) > MAX_REVIEWABLE_FIELD:
                add(
                    Severity.MEDIUM,
                    f"{field.label} is {len(value)} bytes, above the "
                    f"{MAX_REVIEWABLE_FIELD} byte review limit",
                    line,
                    "split the payload, or attach it as a fixture file",
                )
            stripped = value.strip()
            if (
                len(stripped) >= 64
                and len(stripped) % 4 == 0
                and _OPAQUE_RE.match(stripped)
            ):
                add(
                    Severity.WARNING,
                    f"{field.label} holds a {len(stripped)} character opaque blob",
                    line,
                    "obfuscated payloads cannot be reviewed; decode and document it",
                )
        return findings


def _line_for(template: Template, value: str, yaml_path: Tuple[object, ...]) -> Optional[int]:
    """Find the source line of a value; fall back to its YAML key."""
    needle = value.strip()
    if len(needle) > 120 or "\n" in needle:
        needle = needle.splitlines()[0][:120] if needle else ""
    line = template.text_line(needle) if needle else None
    if line:
        return line
    exact = template.line_at(*yaml_path)
    return exact or 1
