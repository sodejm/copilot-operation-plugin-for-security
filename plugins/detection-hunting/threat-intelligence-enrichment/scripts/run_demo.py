# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Synthetic, no-network package demo."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from threat_intel import Indicator, normalize

claims = normalize('misp', Indicator('domain', 'example.org'), {
    'Attribute': [{'type': 'domain', 'value': 'example.org', 'to_ids': True, 'timestamp': '1700000000'}]
})
assert len(claims) == 1 and claims[0]['source'] == 'misp'
print('synthetic claims: 1; network requests: 0')
