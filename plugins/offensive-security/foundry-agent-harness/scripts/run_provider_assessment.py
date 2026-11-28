#!/usr/bin/env python3
"""Run the bundled, fixture-only provider assessment from an exported plugin."""

import sys
from pathlib import Path


def main() -> int:
    """Bootstrap the exported package before loading its assessment module."""
    plugin_root = Path(__file__).resolve().parent.parent
    if str(plugin_root) not in sys.path:
        sys.path.insert(0, str(plugin_root))
    from foundryharness.provider_assessment import main as provider_main

    return provider_main()


if __name__ == "__main__":
    raise SystemExit(main())
