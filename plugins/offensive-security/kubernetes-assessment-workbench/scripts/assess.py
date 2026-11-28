#!/usr/bin/env python3
"""Assess one sanitized offline Kubernetes context record."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kubernetes_assessment_context import GateError, assess, load_record  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assess.py <sanitized-record.json>", file=sys.stderr)
        return 2
    try:
        report = assess(load_record(sys.argv[1]))
    except GateError as error:
        print(f"error: {error.code}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
