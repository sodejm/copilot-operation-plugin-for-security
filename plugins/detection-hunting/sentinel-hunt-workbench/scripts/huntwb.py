#!/usr/bin/env python3
"""Repository-local entry point that does not require package installation."""

from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PACKAGE_ROOT))

from huntwb.cli import main  # noqa: E402

raise SystemExit(main())
