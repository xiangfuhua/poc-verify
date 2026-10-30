"""Rule protocol plus the helpers every rule shares."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Iterator, Optional, Tuple

from ...schema import Dialect, Finding, RuleMeta, Severity, Template

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import LintContext


class Rule:
    """Base class for a lint rule.

    ``check_all`` exists so a cross-file rule (duplicates) can override the
    default per-template loop without special-casing in the engine.
    """

    meta: RuleMeta

    def check(self, template: Template, context: "LintContext") -> Iterable[Finding]:
        return ()

    def check_all(self, templates: Tuple[Template, ...], context: "LintContext") -> Iterable[Finding]:
        for template in templates:
            yield from self.check(template, context)


def metadata_line(template: Template, key: str) -> Optional[int]:
    """Line of a metadata field, accepting both the nested and flat layouts."""
    for path in (("info", key), (key,)):
        if path in template.lines:
            return template.lines[path]
    return template.line_at("info")


def request_prefix(template: Template, request_index: int) -> Tuple[object, ...]:
    """YAML path prefix for a request, so findings land on the right line."""
    if template.dialect is Dialect.NATIVE:
        return ()
    base = "http" if "http" in template.data else "requests"
    return (base, request_index)


def request_line(template: Template, request_index: int) -> Optional[int]:
    return template.line_at(*request_prefix(template, request_index))


@dataclass(frozen=True)
class TextField:
    """A request value scanned for dangerous content, with its YAML anchor."""

    label: str
    value: str
    yaml_path: Tuple[object, ...]


def request_text_fields(template: Template) -> Iterator[TextField]:
    """Every attacker-controlled string in the template's requests.

    Matchers are deliberately excluded: a matcher holding ``DROP TABLE`` is
    usually evidence of a reflected payload, not a destructive request.
    """
    for request in template.requests:
        prefix = request_prefix(template, request.index)
        for path in request.paths:
            yield TextField("path", path, prefix + ("path",))
        for key, value in request.payload.items():
            yield TextField(f"payload.{key}", str(value), prefix + ("payload", key))
        for name, values in request.payloads:
            for value in values:
                yield TextField(f"payloads.{name}", value, prefix + ("payloads", name))
        for key, value in request.headers:
            yield TextField(f"headers.{key}", value, prefix + ("headers", key))
        if request.body:
            yield TextField("body", request.body, prefix + ("body",))
        if request.raw:
            yield TextField("raw", request.raw, prefix + ("raw",))
