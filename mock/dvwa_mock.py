"""Local DVWA-shaped target used by the demo and the manual test run.

It is deliberately tiny and binds to 127.0.0.1 only. **Never deploy this to a
public host**: it is an intentionally vulnerable service.

Start it with::

    python mock/dvwa_mock.py

Then run the bundled templates against it::

    pocverify run pocs --target http://127.0.0.1:8080
"""
from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, request

try:  # running as ``python mock/dvwa_mock.py``
    PASSWD_FILE = Path(__file__).with_name("mock_passwd.txt")
except NameError:  # pragma: no cover - defensive
    PASSWD_FILE = Path(__file__).parent / "mock_passwd.txt"

app = Flask(__name__)


@app.before_request
def log_request() -> None:
    """Print each request so the demo shows what the runner sent."""
    print(f"[REQ] {request.method} {request.path} params={dict(request.args)}", flush=True)


@app.route("/vulnerabilities/sqli/")
def sqli():
    """DVWA SQLi (low): the id parameter is echoed back verbatim."""
    return f"<pre>ID: {request.args.get('id', '')}</pre>"


@app.route("/vulnerabilities/xss_r/")
def xss_r():
    """DVWA reflected XSS (low): the name parameter is not escaped."""
    return f"<pre>Hello {request.args.get('name', '')}</pre>"


@app.route("/vulnerabilities/fi/")
def fi():
    """DVWA file inclusion (low): page is read as a filesystem path."""
    return _read_file(request.args.get("page", ""))


@app.route("/health")
def health():
    return {"status": "ok"}


def _read_file(page: str) -> bytes:
    try:
        return Path(page).read_bytes()
    except OSError:
        # Windows has no /etc/passwd; return the bundled fixture instead.
        try:
            return PASSWD_FILE.read_bytes()
        except OSError:
            return b"file not found"


if __name__ == "__main__":
    if "--host" in sys.argv:  # pragma: no cover - guard against accidents
        print("refusing to bind beyond 127.0.0.1: this target is intentionally vulnerable")
        raise SystemExit(2)
    app.run(host="127.0.0.1", port=8080)
