"""Build scoped HTTP requests, send them, and keep the evidence.

Safety properties enforced here, not only in documentation:

* every request URL is built from the configured target unless a template asked
  for an absolute URL and the run was explicitly allowed to leave scope;
* redirects that change scheme/host/port are refused;
* response bodies are read with a hard cap;
* nothing is sent in ``--dry-run`` mode.

The only network primitive used is ``urllib`` from the standard library, which
keeps the runtime dependency list at PyYAML + rich.
"""
from __future__ import annotations

import itertools
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .. import __version__
from ..schema import Request, Template
from .dsl import UnsupportedMatcher
from .matchers import evaluate as evaluate_matchers

DEFAULT_HEADERS = {
    "User-Agent": f"pocverify/{__version__}",
    "Accept": "*/*",
}
MAX_PAYLOAD_COMBINATIONS = 50
MAX_EVIDENCE = 4000
_SENSITIVE_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token", "proxy-authorization"}
_VARIABLE_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class PreparedRequest:
    method: str
    url: str
    headers: Tuple[Tuple[str, str], ...] = ()
    body: Optional[bytes] = None
    label: str = ""


@dataclass(frozen=True)
class RequestResult:
    label: str
    method: str
    url: str
    status: str  # PASS / FAIL / ERROR
    http_status: int = 0
    matched_by: str = ""
    evidence: str = ""
    error: str = ""
    elapsed_ms: int = 0
    truncated: bool = False


@dataclass(frozen=True)
class TemplateResult:
    template: Template
    status: str  # PASS / FAIL / ERROR / BLOCKED
    requests: Tuple[RequestResult, ...] = ()
    blocked_reasons: Tuple[str, ...] = ()
    error: str = ""

    @property
    def http_status(self) -> int:
        return self.requests[0].http_status if self.requests else 0

    @property
    def matched_by(self) -> str:
        for result in self.requests:
            if result.matched_by:
                return result.matched_by
        return ""

    @property
    def evidence(self) -> str:
        for result in self.requests:
            if result.status == "PASS" and result.evidence:
                return result.evidence
        return ""

    @property
    def duration_ms(self) -> int:
        return sum(result.elapsed_ms for result in self.requests)

    @property
    def truncated(self) -> bool:
        return any(result.truncated for result in self.requests)

    @property
    def failure(self) -> str:
        return self.error or next((r.error for r in self.requests if r.error), "")


def blocked(template: Template, reasons: Sequence[str]) -> TemplateResult:
    """Represent a gate refusal as a result so reports stay uniform."""
    return TemplateResult(template=template, status="BLOCKED", blocked_reasons=tuple(reasons))


def run_template(
    template: Template,
    target: str,
    *,
    timeout: float = 10.0,
    retries: int = 1,
    max_response_size: int = 2 * 1024 * 1024,
    insecure: bool = False,
    allowed_external: bool = False,
) -> TemplateResult:
    """Execute one template against ``target``; returns evidence, never raises."""
    if not template.requests:
        return TemplateResult(template=template, status="ERROR", error="template defines no request")

    results: List[RequestResult] = []
    for request in template.requests:
        try:
            plans = plan_request(template, request, target, allowed_external=allowed_external)
        except UnsupportedMatcher as exc:
            results.append(
                RequestResult(
                    label=f"request[{request.index}]",
                    method=request.method,
                    url=target,
                    status="ERROR",
                    error=str(exc),
                )
            )
            continue
        for plan in plans:
            result = _execute(
                request,
                plan,
                timeout=timeout,
                retries=retries,
                max_response_size=max_response_size,
                insecure=insecure,
            )
            results.append(result)
            if result.status == "PASS":
                return TemplateResult(template=template, status="PASS", requests=tuple(results))

    if not results:
        return TemplateResult(template=template, status="ERROR", error="no request could be built")
    # A transport or matcher error means the template was not fully verified;
    # report that instead of a clean FAIL.
    if any(result.status == "ERROR" for result in results):
        return TemplateResult(template=template, status="ERROR", requests=tuple(results))
    return TemplateResult(template=template, status="FAIL", requests=tuple(results))


def plan_request(
    template: Template,
    request: Request,
    target: str,
    *,
    allowed_external: bool = False,
) -> List[PreparedRequest]:
    """Turn a request definition into concrete, target-scoped HTTP calls."""
    payload_items = {key: str(value) for key, value in request.payload.items()}
    combinations = _payload_combinations(request)
    plans: List[PreparedRequest] = []

    if request.raw:
        for combination in combinations:
            variables = {**payload_items, **combination}
            plans.append(_from_raw(request, target, variables, allowed_external))
        return plans

    for combination in combinations:
        variables = {**payload_items, **combination}
        for path in request.paths or ("/",):
            resolved_path = _substitute(path, target, variables)
            url = _build_url(target, resolved_path, allowed_external)
            headers = _headers_with_defaults(request, target, variables)
            body = _body_for(request, target, variables)
            if body is not None:
                headers = _ensure_content_type(headers)
            method = request.method.upper()
            if method == "GET" and payload_items:
                url = _append_query(url, urllib.parse.urlencode(payload_items, doseq=True))
            label = f"{method} {resolved_path}"
            if combination:
                label += " [" + ", ".join(f"{k}={v}" for k, v in sorted(combination.items())) + "]"
            plans.append(
                PreparedRequest(
                    method=method,
                    url=url,
                    headers=tuple(headers.items()),
                    body=body,
                    label=label,
                )
            )
    if not plans:
        raise UnsupportedMatcher("request produced no executable plan")
    return plans


def preview(plans: Sequence[PreparedRequest]) -> List[str]:
    """Human-readable preview for ``--dry-run``; never touches the network."""
    lines = []
    for plan in plans:
        lines.append(f"{plan.method} {plan.url}")
        headers = ", ".join(
            f"{key}: ***" if key.lower() in _SENSITIVE_HEADERS else f"{key}: {value}"
            for key, value in plan.headers
        )
        details = f"headers: {headers}" if headers else ""
        if plan.body:
            details += f"{', ' if details else ''}body: {len(plan.body)} bytes"
        if details:
            lines.append(f"  {details}")
    return lines


def _execute(
    request: Request,
    plan: PreparedRequest,
    *,
    timeout: float,
    retries: int,
    max_response_size: int,
    insecure: bool,
) -> RequestResult:
    started = time.perf_counter()
    status_code, body, headers, truncated, error = _send(
        plan,
        timeout=timeout,
        retries=retries,
        max_response_size=max_response_size,
        insecure=insecure,
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    if error:
        return RequestResult(
            label=plan.label,
            method=plan.method,
            url=plan.url,
            status="ERROR",
            error=error,
            elapsed_ms=elapsed_ms,
        )
    try:
        outcome = evaluate_matchers(
            request.matchers,
            request.matcher_condition,
            status=status_code,
            body=body,
            headers=headers,
        )
    except UnsupportedMatcher as exc:
        return RequestResult(
            label=plan.label,
            method=plan.method,
            url=plan.url,
            status="ERROR",
            http_status=status_code,
            error=str(exc),
            elapsed_ms=elapsed_ms,
            truncated=truncated,
        )
    return RequestResult(
        label=plan.label,
        method=plan.method,
        url=plan.url,
        status="PASS" if outcome.matched else "FAIL",
        http_status=status_code,
        matched_by=outcome.matched_by,
        evidence=outcome.evidence[:MAX_EVIDENCE],
        elapsed_ms=elapsed_ms,
        truncated=truncated,
    )


def _send(
    plan: PreparedRequest,
    *,
    timeout: float,
    retries: int,
    max_response_size: int,
    insecure: bool,
) -> Tuple[int, str, str, bool, str]:
    """Send one request; HTTP error statuses are responses, not exceptions."""
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _ScopedRedirectHandler(),
    )

    last_error = ""
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                plan.url,
                data=plan.body,
                headers=dict(plan.headers),
                method=plan.method,
            )
            with opener.open(request, timeout=timeout) as response:
                body, truncated = _read_capped(response, max_response_size)
                return response.status, body, _headers_text(response.headers), truncated, ""
        except urllib.error.HTTPError as exc:
            body, truncated = _read_capped(exc, max_response_size)
            return exc.code, body, _headers_text(exc.headers), truncated, ""
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError) as exc:
            last_error = str(getattr(exc, "reason", exc))
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
    return 0, "", "", False, last_error or "request failed"


def _read_capped(response, max_size: int) -> Tuple[str, bool]:
    raw = response.read(max_size + 1)
    truncated = len(raw) > max_size
    return raw[:max_size].decode("utf-8", errors="replace"), truncated


def _headers_text(headers) -> str:
    if not headers:
        return ""
    return "\r\n".join(f"{key}: {value}" for key, value in headers.items())


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow same-origin redirects only; a cross-origin 3xx is returned as-is."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _same_origin(req.full_url, newurl):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"cross-origin redirect to {newurl} blocked",
            headers,
            fp,
        )


def _same_origin(first: str, second: str) -> bool:
    try:
        base = urllib.parse.urlsplit(first)
        target = urllib.parse.urlsplit(urllib.parse.urljoin(first, second))
    except ValueError:
        return False
    return (
        base.scheme == target.scheme
        and base.hostname == target.hostname
        and (base.port or _DEFAULT_PORTS.get(base.scheme))
        == (target.port or _DEFAULT_PORTS.get(target.scheme))
    )


def _payload_combinations(request: Request) -> List[Dict[str, str]]:
    if not request.payloads:
        return [{}]
    keys = [key for key, _ in request.payloads]
    values = [list(value) or [""] for _, value in request.payloads]
    total = 1
    for value in values:
        total *= len(value)
    if total > MAX_PAYLOAD_COMBINATIONS:
        raise UnsupportedMatcher(
            f"payload set expands to {total} combinations, above the "
            f"{MAX_PAYLOAD_COMBINATIONS} limit"
        )
    return [dict(zip(keys, combination)) for combination in itertools.product(*values)]


def _build_url(target: str, path: str, allowed_external: bool) -> str:
    target = target.rstrip("/")
    if path.lower().startswith(("http://", "https://")):
        # A path may become absolute after {{BaseURL}} substitution; that is
        # still in scope. Only a *different* origin needs an explicit opt-in.
        if allowed_external or _same_origin(target, path):
            return path
        raise UnsupportedMatcher(
            f"absolute URL {path!r} is outside the configured target; "
            "rerun with --allow-unsafe only if that is intended"
        )
    if not path.startswith("/"):
        path = "/" + path
    return target + path


def _substitute(text: str, target: str, variables: Dict[str, str]) -> str:
    mapping = _target_variables(target)
    mapping.update({key: str(value) for key, value in variables.items()})

    def replace(match: "re.Match[str]") -> str:
        return mapping.get(match.group(1), match.group(0))

    resolved = _VARIABLE_RE.sub(replace, text)
    unresolved = sorted(set(_VARIABLE_RE.findall(resolved)))
    if unresolved:
        raise UnsupportedMatcher(
            "unresolved template variable(s): "
            + ", ".join(f"{{{{{name}}}}}" for name in unresolved)
        )
    return resolved


def _target_variables(target: str) -> Dict[str, str]:
    target = target.rstrip("/")
    parsed = urllib.parse.urlsplit(target)
    return {
        "BaseURL": target,
        "RootURL": target,
        "Hostname": parsed.hostname or "",
        "Host": parsed.netloc,
        "Port": str(parsed.port or _DEFAULT_PORTS.get(parsed.scheme, "")),
    }


def _headers_with_defaults(request: Request, target: str, variables: Dict[str, str]) -> Dict[str, str]:
    headers = dict(DEFAULT_HEADERS)
    for key, value in request.headers:
        resolved_key = _substitute(key, target, variables)
        headers[resolved_key] = _substitute(value, target, variables)
    return headers


def _body_for(request: Request, target: str, variables: Dict[str, str]) -> Optional[bytes]:
    if request.body:
        return _substitute(request.body, target, variables).encode("utf-8")
    if request.method.upper() in ("POST", "PUT", "PATCH") and request.payload:
        encoded = urllib.parse.urlencode(
            {key: _substitute(str(value), target, variables) for key, value in request.payload.items()},
            doseq=True,
        )
        return encoded.encode("utf-8")
    return None


def _append_query(url: str, query: str) -> str:
    if not query:
        return url
    separator = "&" if urllib.parse.urlsplit(url).query else "?"
    return url + separator + query


def _from_raw(
    request: Request,
    target: str,
    variables: Dict[str, str],
    allowed_external: bool,
) -> PreparedRequest:
    raw = _substitute(request.raw, target, variables)
    lines = raw.replace("\r\n", "\n").split("\n")
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        raise UnsupportedMatcher("malformed raw request line")
    method, raw_target = request_line[0].upper(), request_line[1]
    headers: List[Tuple[str, str]] = []
    index = 1
    while index < len(lines) and lines[index].strip():
        key, _, value = lines[index].partition(":")
        if key.strip():
            headers.append((key.strip(), value.strip()))
        index += 1
    body = "\n".join(lines[index + 1:]).strip()
    url = _build_url(target, raw_target, allowed_external)
    # Host always comes from the target, never from the raw request.
    headers = [(key, value) for key, value in headers if key.lower() != "host"]
    if body:
        headers = list(_ensure_content_type(dict(headers)).items())
    return PreparedRequest(
        method=method,
        url=url,
        headers=tuple(headers),
        body=body.encode("utf-8") if body else None,
        label=f"{method} raw {raw_target}",
    )


def _ensure_content_type(headers: Dict[str, str]) -> Dict[str, str]:
    if not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return headers
