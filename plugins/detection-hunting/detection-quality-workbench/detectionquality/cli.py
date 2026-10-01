"""Command-line interface for the Detection Quality & Regression Workbench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from detectionquality.evaluator import evaluate_rule_suite
    from detectionquality.models import FixtureSuite, QualityError, Rule
    from detectionquality.reporting import render_json_report, render_markdown_report
else:
    from .evaluator import evaluate_rule_suite
    from .models import FixtureSuite, QualityError, Rule
    from .reporting import render_json_report, render_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detectionquality",
        description="Detection quality, regression testing, and precision/recall evaluation workbench.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # evaluate command
    eval_parser = subparsers.add_parser("evaluate", help="evaluate a detection rule against fixture suite")
    eval_parser.add_argument("--rule", type=Path, required=True, help="path to rule JSON")
    eval_parser.add_argument("--fixtures", type=Path, required=True, help="path to fixture suite JSON")
    eval_parser.add_argument("--json", action="store_true", help="output structured JSON instead of Markdown")
    eval_parser.add_argument("--output", type=Path, help="write report output to file")

    # validate command
    val_parser = subparsers.add_parser("validate", help="validate rule definitions against contract schema")
    val_parser.add_argument("--rules-dir", type=Path, required=True, help="directory containing rule JSON files")

    # test-suite command
    suite_parser = subparsers.add_parser("test-suite", help="run evaluation across entire rules and fixtures directory")
    suite_parser.add_argument("--rules-dir", type=Path, required=True, help="path to rules directory")
    suite_parser.add_argument("--fixtures-dir", type=Path, required=True, help="path to fixtures directory")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "evaluate":
            if not args.rule.is_file():
                raise QualityError(f"Rule file not found: {args.rule}")
            if not args.fixtures.is_file():
                raise QualityError(f"Fixture file not found: {args.fixtures}")

            rule_data = json.loads(args.rule.read_text(encoding="utf-8"))
            rule = Rule.from_dict(rule_data)

            fixture_data = json.loads(args.fixtures.read_text(encoding="utf-8"))
            suite = FixtureSuite.from_dict(fixture_data)

            report_data = evaluate_rule_suite(rule, suite)

            if args.json:
                out = render_json_report(report_data)
            else:
                out = render_markdown_report(report_data)

            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(out, encoding="utf-8")
                print(f"Wrote quality report to {args.output}")
            else:
                print(out, end="")
            return 0

        elif args.command == "validate":
            if not args.rules_dir.is_dir():
                raise QualityError(f"Rules directory not found: {args.rules_dir}")

            count = 0
            for p in sorted(args.rules_dir.glob("*.json")):
                data = json.loads(p.read_text(encoding="utf-8"))
                rule = Rule.from_dict(data)
                print(f"Validated rule: {rule.rule_id} ({rule.platform}) - {rule.name}")
                count += 1
            print(f"\nAll {count} detection rules validated successfully.")
            return 0

        elif args.command == "test-suite":
            if not args.rules_dir.is_dir():
                raise QualityError(f"Rules directory not found: {args.rules_dir}")
            if not args.fixtures_dir.is_dir():
                raise QualityError(f"Fixtures directory not found: {args.fixtures_dir}")

            rule_files = {p.stem: p for p in args.rules_dir.glob("*.json")}
            fixture_files = {p.stem: p for p in args.fixtures_dir.glob("*.json")}

            print(f"Running Detection Quality Test Suite...")
            print(f"{'Rule ID':<35} {'Platform':<15} {'Precision':<12} {'Recall':<10} {'Status'}")
            print("-" * 85)

            all_passed = True
            for name, r_path in sorted(rule_files.items()):
                f_path = fixture_files.get(name)
                if not f_path:
                    print(f"Warning: No matching fixture suite for {name}", file=sys.stderr)
                    continue

                rule = Rule.from_dict(json.loads(r_path.read_text(encoding="utf-8")))
                suite = FixtureSuite.from_dict(json.loads(f_path.read_text(encoding="utf-8")))
                rep = evaluate_rule_suite(rule, suite)

                prec = f"{rep['metrics']['precision_on_labeled_fixtures']*100:.1f}%"
                rec = f"{rep['metrics']['recall_on_labeled_fixtures']*100:.1f}%"
                status = "PASS" if rep["metrics"]["false_positives"] == 0 and rep["metrics"]["false_negatives"] == 0 else "REVIEW"
                if status == "REVIEW":
                    all_passed = False

                print(f"{rule.rule_id:<35} {rule.platform:<15} {prec:<12} {rec:<10} {status}")

            return 0 if all_passed else 1

    except QualityError as exc:
        print(f"detectionquality error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
