"""Run a bounded offline artifact report."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vendor" / "runtime"))
from cops.assessments.__main__ import add_report_arguments, command_report  # noqa: E402

CAPABILITIES = ("compliance_evidence",)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_report_arguments(parser, capabilities=CAPABILITIES)
    raise SystemExit(command_report(parser.parse_args()))
