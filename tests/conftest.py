"""Shared pytest fixtures: path setup, template helpers and a local lab server."""
from __future__ import annotations

import os
import sys
import textwrap
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pocverify.config import Config, IgnoreRule  # noqa: E402
from pocverify.lint.engine import lint  # noqa: E402
from pocverify.loader import load_text  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_path():
    """A per-test directory created without pytest's mode-0700 temp helper."""
    base = Path(os.environ.get("TMP") or os.environ.get("TEMP") or "/tmp") / "pocverify-tests"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
    path.mkdir()
    return path


def load_template(text: str, filename: str = "template.yaml"):
    """Parse inline YAML into a Template (no filesystem needed)."""
    return load_text(textwrap.dedent(text).lstrip("\n"), path=filename)


@pytest.fixture
def lint_one():
    """Return ``(template_report)`` for a single inline template."""

    def _lint(text: str, filename: str = "template.yaml", config: Config | None = None):
        template = load_template(text, filename)
        report = lint([template], config=config)
        return report.templates[0]

    return _lint


@pytest.fixture
def make_config():
    def _make(ignore=(), **kwargs) -> Config:
        rules = tuple(IgnoreRule(**entry) for entry in ignore)
        return Config(ignore=rules, **kwargs)

    return _make


def findings(template_report, rule: str):
    return [finding for finding in template_report.findings if finding.rule == rule]


class _LabHandler(BaseHTTPRequestHandler):
    """A tiny target with the response shapes the tests need."""

    def log_message(self, *args):  # keep test output clean
        return

    def _send(self, status: int, body: bytes = b"", headers=None):
        self.send_response(status)
        content_type = "application/json" if self.path.startswith("/health") else "text/html; charset=utf-8"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/ok":
            self._send(200, b"unique-marker here")
        elif parsed.path == "/login":
            self._send(401, b"denied")
        elif parsed.path == "/reflect":
            self._send(200, ("<pre>Hello " + query.get("q", [""])[0] + "</pre>").encode())
        elif parsed.path == "/redirect":
            self._send(302, b"", headers={"Location": "/ok"})
        elif parsed.path == "/offsite":
            self._send(302, b"", headers={"Location": "http://example.invalid/ok"})
        elif parsed.path == "/big":
            self._send(200, b"x" * 5000)
        elif parsed.path == "/server-error":
            self._send(500, b"boom")
        elif parsed.path == "/header-check":
            self._send(200, b"body", headers={"X-Marker": "yes"})
        elif parsed.path == "/health":
            self._send(200, b'{"status":"ok"}')
        else:
            self._send(404, b"not found")

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length)
        if self.path.startswith("/submit"):
            self._send(200, b"posted:" + body)
        else:
            self._send(404, b"not found")


@pytest.fixture(scope="session")
def lab_server():
    """A 127.0.0.1-only HTTP target; returns its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def write_template(tmp_path):
    """Write a template to disk and return its path."""

    def _write(name: str, text: str) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
        return path

    return _write
