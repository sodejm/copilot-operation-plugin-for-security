#!/usr/bin/env python3
"""Demonstrate offline analysis against a synthetic two-forest fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adwb import analyze, load_export  # noqa: E402

fixture = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-two-forest.json"
print(json.dumps(analyze(load_export(fixture)), indent=2, sort_keys=True))
