"""Portable bounded Git history scanner entrypoint."""

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor" / "runtime"))

from cops.assessments.git_history import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
