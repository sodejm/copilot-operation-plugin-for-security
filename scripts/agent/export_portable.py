#!/usr/bin/env python3
"""Export cataloged Agent Plugins v1.0.0 packages without host-native files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cops.catalog import plugin_records  # noqa: E402
from cops.portable import export_portable_package  # noqa: E402
from cops.validation import ValidationError, validate_repository  # noqa: E402


def export_all(output: Path) -> None:
    for record in plugin_records(ROOT):
        destination = output / record.primary_category / record.id
        destination.parent.mkdir(parents=True, exist_ok=True)
        export_portable_package(ROOT / record.path, destination)
        print(f"Validated portable package: {record.id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="build and validate in a temporary directory")
    group.add_argument("--output", type=Path, help="write packages into a new output directory")
    args = parser.parse_args()
    try:
        validate_repository(ROOT)
        if args.check:
            with TemporaryDirectory(prefix="copse-agent-plugins-") as temporary:
                export_all(Path(temporary))
        else:
            output = args.output.resolve()
            if output.exists():
                raise ValidationError(f"output directory already exists: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(prefix=".copse-agent-plugins-", dir=output.parent) as temporary:
                stage = Path(temporary) / "packages"
                stage.mkdir()
                export_all(stage)
                if output.exists():
                    raise ValidationError(f"output directory already exists: {output}")
                stage.rename(output)
    except (ValidationError, ValueError, OSError) as error:
        print(f"portable export error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
