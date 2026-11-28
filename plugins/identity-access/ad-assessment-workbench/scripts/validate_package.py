#!/usr/bin/env python3
"""Run the deterministic offline package gate."""

from __future__ import annotations

import unittest
from pathlib import Path

package = Path(__file__).resolve().parents[1]
suite = unittest.defaultTestLoader.discover(str(package / "tests"), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
