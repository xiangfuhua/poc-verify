"""Load native PoCVerify templates and Nuclei templates into one model.

Two things happen here and nowhere else:

* dialect detection and normalization (native flat fields, Nuclei ``http:``
  blocks, legacy v1 ``match_*`` fields) — so rules and the runner never branch
  on the source format;
* source-location indexing — every YAML path is mapped to a 1-based line by
  walking the ``yaml.compose`` node tree, which is what makes findings point at
  ``pocs/x.yaml:12`` instead of at the whole file.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .schema import Dialect, Matcher, Request, Template

TEMPLATE_SUFFIXES = {".yaml", ".yml"}
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".tox", "reports", "dist", "build"}

DANGEROUS_PROTOCOLS = ("code", "javascript", "file", "headless")
NETWORK_PROTOCOLS = ("network", "tcp", "whois", "websocket")
ALL_PROTOCOLS = DANGEROUS_PROTOCOLS + NETWORK_PROTOCOLS

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class LoadError(Exception):
    """A template (or scan path) that could not be turned into a model."""

    def __init__(self, path: os.PathLike | str, message: str) -> None:
        self.path = Path(path)
        self.message = message
        super().__init__(f"{self.path}: {message}")


@dataclass
class LoadResult:
    templates: List[Template]
    errors: List[LoadError]
    files_seen: int = 0


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def load_templates(
    paths: Iterable[os.PathLike | str],
    *,
    exclude: Sequence[str] = (),
) -> LoadResult:
    """Load every template under ``paths`` (files or directories)."""
    files, errors = discover(paths, exclude=exclude)
    templates: List[Template] = []
    for file_path in files:
        try:
            templates.append(load_file(file_path))
        except LoadError as exc:
            errors.append(exc)
    return LoadResult(templates=templates, errors=errors, files_seen=len(files))


def discover(
    paths: Iterable[os.PathLike | str],
    *,
    exclude: Sequence[str] = (),
) -> Tuple[List[Path], List[LoadError]]:
    """Expand files and directories into a de-duplicated, sorted file list."""
    files: List[Path] = []
    errors: List[LoadError] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            errors.append(LoadError(path, "path does not exist"))
            continue
        if path.is_dir():
            found = [
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in TEMPLATE_SUFFIXES
                and not _skipped(candidate, path, exclude)
            ]
            files.extend(sorted(found, key=lambda p: p.as_posix().lower()))
        elif path.suffix.lower() in TEMPLATE_SUFFIXES:
            if not _matches_exclude(path.name, exclude):
                files.append(path)
        else:
            errors.append(LoadError(path, "not a .yaml/.yml file"))
    unique: Dict[str, Path] = {}
    for file_path in files:
        unique.setdefault(_key(file_path), file_path)
    return list(unique.values()), errors


def load_file(path: os.PathLike | str, *, rel_path: Optional[str] = None) -> Template:
    """Load a single template file."""
    file_path = Path(path)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise LoadError(file_path, f"cannot stat file: {exc}") from exc
    if size > MAX_TEMPLATE_BYTES:
        raise LoadError(file_path, f"file is {size} bytes, above the {MAX_TEMPLATE_BYTES} byte limit")
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LoadError(file_path, f"template is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise LoadError(file_path, f"cannot read file: {exc}") from exc
    return load_text(text, path=file_path, rel_path=rel_path)


def load_text(
    text: str,
    *,
    path: os.PathLike | str = "<string>",
    rel_path: Optional[str] = None,
) -> Template:
    """Parse template text (used by tests and by ``load_file``)."""
    file_path = Path(path)
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise LoadError(file_path, f"invalid YAML: {exc}") from exc
    if node is None:
        raise LoadError(file_path, "empty template")

    lines: Dict[Tuple[Any, ...], int] = {}
    _index_lines(node, (), lines, set())
    duplicates = _duplicate_keys(node, (), set())

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - compose already validated
        raise LoadError(file_path, f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise LoadError(file_path, "template root must be a mapping")

    dialect = detect_dialect(data)
    common = dict(
        path=file_path,
        rel_path=rel_path or _relative(file_path),
        text=text,
        dialect=dialect,
        lines=lines,
        duplicate_keys=tuple(duplicates),
    )
    kwargs = _load_nuclei(data, **common) if dialect is Dialect.NUCLEI else _load_native(data, **common)
    return Template(data=data, **kwargs)


# ---------------------------------------------------------------------------
# dialect detection
# ---------------------------------------------------------------------------
def detect_dialect(data: Dict[str, Any]) -> Dialect:
    """Native templates carry a single ``method``/``path`` request.

    Nuclei templates carry ``http:``/``requests:`` (or a protocol block) and an
    ``info:`` block. Checking the native request keys first keeps a native
    template that happens to document itself with ``info:`` on the right side.
    """
    native_markers = ("method", "path", "match_status", "match_keyword", "match_regex")
    if any(marker in data for marker in native_markers):
        return Dialect.NATIVE
    if "http" in data or "requests" in data or "info" in data:
        return Dialect.NUCLEI
    return Dialect.NATIVE


# ---------------------------------------------------------------------------
# per-dialect normalization
# ---------------------------------------------------------------------------
def _load_native(data: Dict[str, Any], **common: Any) -> Dict[str, Any]:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    path_value = _text(data.get("path"))
    headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
    payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    matchers = _native_matchers(data)
    request = Request(
        index=0,
        method=(_text(data.get("method")) or "GET").upper(),
        paths=(path_value,) if path_value else (),
        payload=dict(payload),
        headers=tuple((str(k), str(v)) for k, v in headers.items()),
        body=_text(data.get("body")) or "",
        matchers=matchers,
        matcher_condition=_condition(data.get("matchers-condition")),
        unsafe=bool(data.get("unsafe", False)),
    )
    return {
        **common,
        "id": _text(data.get("id")) or None,
        "name": _first(_text(info.get("name")), _text(data.get("name"))),
        "authors": _split_list(info.get("author") or data.get("author")),
        "severity": _first(_text(info.get("severity")), _text(data.get("severity"))),
        "description": _first(_text(info.get("description")), _text(data.get("description"))),
        "references": _split_list(info.get("reference") or data.get("reference"), split_commas=False),
        "tags": _split_list(info.get("tags") or data.get("tags")),
        "cves": _extract_cves(info, data),
        "cvss": _cvss(info, data),
        "protocols": _protocols(data),
        "requests": (request,),
    }


def _load_nuclei(data: Dict[str, Any], **common: Any) -> Dict[str, Any]:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    entries = data.get("http") or data.get("requests") or []
    if isinstance(entries, dict):
        entries = [entries]
    requests: List[Request] = []
    extra_protocols = set(_protocols(data))
    for index, entry in enumerate(entries if isinstance(entries, list) else []):
        if not isinstance(entry, dict):
            continue
        if entry.get("headless"):
            extra_protocols.add("headless")
        payloads = entry.get("payloads") if isinstance(entry.get("payloads"), dict) else {}
        requests.append(
            Request(
                index=index,
                method=(_text(entry.get("method")) or "GET").upper(),
                paths=_as_text_list(entry.get("path")),
                payloads=tuple(
                    (str(k), _as_text_list(v)) for k, v in payloads.items()
                ),
                headers=tuple(
                    (str(k), str(v))
                    for k, v in (entry.get("headers") or {}).items()
                )
                if isinstance(entry.get("headers"), dict)
                else (),
                body="\n".join(_as_text_list(entry.get("body"))),
                raw="\n".join(_as_text_list(entry.get("raw"))),
                matchers=tuple(
                    matcher
                    for matcher in (
                        _nuclei_matcher(item)
                        for item in (entry.get("matchers") or [])
                        if isinstance(item, dict)
                    )
                    if matcher is not None
                ),
                matcher_condition=_condition(entry.get("matchers-condition")),
                unsafe=bool(entry.get("unsafe", False)),
            )
        )
    return {
        **common,
        "id": _text(data.get("id")) or None,
        "name": _text(info.get("name")),
        "authors": _split_list(info.get("author")),
        "severity": _text(info.get("severity")),
        "description": _text(info.get("description")),
        "references": _split_list(info.get("reference"), split_commas=False),
        "tags": _split_list(info.get("tags")),
        "cves": _extract_cves(info, data),
        "cvss": _cvss(info, data),
        "protocols": tuple(sorted(extra_protocols)),
        "requests": tuple(requests),
    }


# ---------------------------------------------------------------------------
# field helpers
# ---------------------------------------------------------------------------
def _text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (dict, list, tuple)):
        return None
    text = str(value).strip()
    return text or None


def _first(*values: Optional[str]) -> Optional[str]:
    for value in values:
        if value:
            return value
    return None


def _as_text_list(value: Any) -> Tuple[str, ...]:
    """Normalize scalar-or-list YAML into a tuple of non-empty strings."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        out: List[str] = []
        for item in value:
            out.extend(_as_text_list(item))
        return tuple(out)
    if isinstance(value, dict):
        return ()
    text = str(value).strip()
    return (text,) if text else ()


def _split_list(value: Any, *, split_commas: bool = True) -> Tuple[str, ...]:
    """Normalize ``author``/``tags`` style fields; they may be CSV strings."""
    items = _as_text_list(value)
    if not split_commas:
        return items
    out: List[str] = []
    for item in items:
        out.extend(part.strip() for part in item.split(",") if part.strip())
    return tuple(out)


def _condition(value: Any) -> str:
    return "and" if str(value or "").strip().lower() == "and" else "or"


def _native_matchers(data: Dict[str, Any]) -> Tuple[Matcher, ...]:
    matchers: List[Matcher] = []
    raw = data.get("matchers")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                matcher = _nuclei_matcher(item)
                if matcher is not None:
                    matchers.append(matcher)
    # v1 compatibility: flat match_* fields are still accepted and linted.
    status = data.get("match_status")
    if status not in (None, "") and str(status).strip():
        matchers.append(Matcher("status", (str(status).strip(),)))
    keyword = _text(data.get("match_keyword"))
    if keyword:
        matchers.append(Matcher("word", (keyword,)))
    regex = _text(data.get("match_regex"))
    if regex:
        matchers.append(Matcher("regex", (regex,)))
    return tuple(matchers)


def _nuclei_matcher(data: Dict[str, Any]) -> Optional[Matcher]:
    matcher_type = _text(data.get("type"))
    if not matcher_type:
        for candidate, key in (
            ("status", "status"),
            ("word", "words"),
            ("regex", "regex"),
            ("size", "size"),
            ("dsl", "dsl"),
            ("xpath", "xpath"),
            ("binary", "binary"),
        ):
            if key in data:
                matcher_type = candidate
                break
    if not matcher_type:
        return None
    matcher_type = matcher_type.lower()
    if matcher_type == "words":
        matcher_type = "word"
    if matcher_type == "status":
        values = _as_text_list(data.get("status"))
    elif matcher_type == "word":
        values = _as_text_list(data.get("words") or data.get("word"))
    elif matcher_type == "regex":
        values = _as_text_list(data.get("regex"))
    elif matcher_type == "size":
        values = _as_text_list(data.get("size"))
    elif matcher_type == "dsl":
        values = _as_text_list(data.get("dsl"))
    elif matcher_type == "xpath":
        values = _as_text_list(data.get("xpath"))
    else:
        values = _as_text_list(data.get("words")) or _as_text_list(data.get("binary"))
    return Matcher(
        type=matcher_type,
        values=values,
        condition=_condition(data.get("condition")),
        negative=bool(data.get("negative", False)),
        part=str(data.get("part") or "body").strip().lower(),
    )


def _protocols(data: Dict[str, Any]) -> Tuple[str, ...]:
    found = []
    for protocol in ALL_PROTOCOLS:
        value = data.get(protocol)
        if value:
            found.append(protocol)
    return tuple(sorted(found))


def _extract_cves(info: Dict[str, Any], data: Dict[str, Any]) -> Tuple[str, ...]:
    found: List[str] = []

    def collect(value: Any) -> None:
        for item in _as_text_list(value):
            for match in _CVE_RE.findall(item):
                normalized = match.upper()
                if normalized not in found:
                    found.append(normalized)

    classification = info.get("classification")
    if isinstance(classification, dict):
        collect(classification.get("cve-id"))
    collect(data.get("cve-id"))
    collect(data.get("cve"))
    for tag in _split_list(info.get("tags")):
        collect(tag)
    return tuple(found)


def _cvss(info: Dict[str, Any], data: Dict[str, Any]) -> Optional[float]:
    classification = info.get("classification")
    raw = None
    if isinstance(classification, dict):
        raw = classification.get("cvss-score")
    if raw is None:
        raw = data.get("cvss-score", data.get("cvss"))
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float("nan")


# ---------------------------------------------------------------------------
# YAML node walking
# ---------------------------------------------------------------------------
def _index_lines(
    node: Any,
    prefix: Tuple[Any, ...],
    out: Dict[Tuple[Any, ...], int],
    seen: set,
) -> None:
    if id(node) in seen:
        return
    seen.add(id(node))
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = _node_text(key_node)
            path = prefix + (key,)
            out.setdefault(path, key_node.start_mark.line + 1)
            _index_lines(value_node, path, out, seen)
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            path = prefix + (index,)
            out[path] = item.start_mark.line + 1
            _index_lines(item, path, out, seen)


def _duplicate_keys(
    node: Any,
    prefix: Tuple[Any, ...],
    seen: set,
) -> List[Tuple[str, int]]:
    """Duplicate mapping keys silently override each other; surface them."""
    duplicates: List[Tuple[str, int]] = []
    if id(node) in seen:
        return duplicates
    seen.add(id(node))
    if isinstance(node, yaml.MappingNode):
        keys: Dict[str, int] = {}
        for key_node, value_node in node.value:
            key = _node_text(key_node)
            line = key_node.start_mark.line + 1
            if key in keys:
                duplicates.append((_dotted(prefix + (key,)), line))
            else:
                keys[key] = line
            duplicates.extend(_duplicate_keys(value_node, prefix + (key,), seen))
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            duplicates.extend(_duplicate_keys(item, prefix + (index,), seen))
    return duplicates


def _node_text(node: Any) -> str:
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    return "?"


def _dotted(path: Tuple[Any, ...]) -> str:
    out = ""
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------
def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return path.resolve().as_posix() if path.is_absolute() else path.as_posix()


def _key(path: Path) -> str:
    try:
        return path.resolve().as_posix().lower()
    except OSError:
        return path.as_posix().lower()


def _skipped(path: Path, root: Path, exclude: Sequence[str]) -> bool:
    if path.name.startswith("."):  # config and editor files are not templates
        return True
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.as_posix()
    if any(part in SKIP_DIRS for part in Path(rel).parts[:-1]):
        return True
    return _matches_exclude(rel, exclude) or _matches_exclude(path.name, exclude)


def _matches_exclude(name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch(name, pattern) or fnmatch(name.lower(), pattern.lower()) for pattern in patterns)
