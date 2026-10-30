"""PG-003: dangerous capabilities.

A template is executable code with network access. ``code``, ``javascript``,
``file`` and ``headless`` blocks run logic on the machine that scans, so they
are critical by default and must be waived deliberately.
"""
from __future__ import annotations

import re
from typing import Iterable, List

from ...schema import Finding, RuleMeta, Severity, Template, make_finding
from .base import Rule, request_line, request_prefix

RULE_ID = "PG-003"
_EXECUTION_PROTOCOLS = {"code", "javascript", "file", "headless"}
_NETWORK_PROTOCOLS = {"network", "tcp", "whois", "websocket"}
_ABSOLUTE_URL_RE = re.compile(r"^\s*[A-Z]+\s+https?://", re.IGNORECASE)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class CapabilityRule(Rule):
    meta = RuleMeta(
        id=RULE_ID,
        title="Dangerous capabilities",
        description=(
            "Flags code/javascript/file/headless protocol blocks, unsafe raw requests, "
            "header injection (CRLF), non latin-1 headers, absolute URLs that would "
            "escape the configured target, and invalid header names."
        ),
        default_severity=Severity.CRITICAL,
        help_anchor="pg-003-dangerous-capabilities",
    )

    def check(self, template: Template, context) -> Iterable[Finding]:
        findings: List[Finding] = []

        def add(severity: Severity, message: str, line, hint: str = "") -> None:
            findings.append(make_finding(RULE_ID, severity, message, template, line, hint))

        for protocol in template.protocols:
            if protocol in _EXECUTION_PROTOCOLS:
                add(
                    Severity.CRITICAL,
                    f"template uses the '{protocol}' protocol, which executes logic on the scanner",
                    template.line_at(protocol),
                    "remove it, or waive PG-003 explicitly after reviewing the code path",
                )
            elif protocol in _NETWORK_PROTOCOLS:
                add(
                    Severity.HIGH,
                    f"template uses the '{protocol}' protocol, which speaks raw network traffic",
                    template.line_at(protocol),
                    "raw protocols bypass HTTP scope checks; review the target list first",
                )

        for request in template.requests:
            prefix = request_prefix(template, request.index)
            line = request_line(template, request.index)
            if request.unsafe:
                add(
                    Severity.HIGH,
                    "request sets 'unsafe: true', enabling payloads Nuclei would otherwise sanitize",
                    template.line_at(*prefix, "unsafe") or line,
                )
            for key, value in request.headers:
                header_line = template.line_at(*prefix, "headers", key) or line
                if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                    add(
                        Severity.HIGH,
                        f"header {key!r} contains a CR/LF sequence (header injection)",
                        header_line,
                        "encode or remove the newline; the runner sends headers as-is",
                    )
                if not _HEADER_NAME_RE.match(key):
                    add(
                        Severity.MEDIUM,
                        f"header name {key!r} is not a valid HTTP token",
                        header_line,
                    )
                try:
                    value.encode("latin-1")
                    key.encode("latin-1")
                except UnicodeEncodeError:
                    add(
                        Severity.MEDIUM,
                        f"header {key!r} contains non latin-1 characters; HTTP headers cannot carry them",
                        header_line,
                    )
            for path in request.paths:
                if path.strip().lower().startswith(("http://", "https://")):
                    add(
                        Severity.HIGH,
                        f"path {path!r} is an absolute URL and would escape the configured target",
                        template.line_at(*prefix, "path") or line,
                        "keep paths relative to the target ({{BaseURL}}/...)",
                    )
            if request.raw and _ABSOLUTE_URL_RE.match(request.raw):
                add(
                    Severity.HIGH,
                    "raw request uses an absolute request target and would escape the configured target",
                    template.line_at(*prefix, "raw") or line,
                )
        return findings
