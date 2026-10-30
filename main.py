"""v1 compatibility entry point (deprecated).

Kept so ``python main.py --target ... --poc-dir pocs`` keeps working. The v1
behaviour (run everything, no gate) maps to ``pocverify run --no-lint
--allow-unsafe``; new scripts should call the console script directly::

    pocverify run pocs --target http://127.0.0.1:8080
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pocverify.cli import legacy_main  # noqa: E402  (path set up above)

if __name__ == "__main__":
    sys.exit(legacy_main())
