# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Synthetic, no-network package demo."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from threat_intel import Indicator, normalize

claims = normalize(
    "misp",
    Indicator("domain", "example.org"),
    {
        "Attribute": [
            {"type": "domain", "value": "example.org", "to_ids": True, "timestamp": "1700000000", "distribution": 0}
        ]
    },
    retrieved_at=1700000100,
)
assert len(claims) == 1 and claims[0]["source"] == "misp"
assert claims[0]["retrieved_at"] == "2023-11-14T22:15:00Z"
assert claims[0]["sharing_restrictions"] == ["misp:distribution:0"]
print("synthetic claims: 1; network requests: 0")
