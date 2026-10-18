"""Portable bounded artifact assessment entrypoint."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor" / "runtime"))
from cops.assessments.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(["assess", "credential_history", *sys.argv[1:]]))
