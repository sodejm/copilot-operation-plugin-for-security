"""Create a native assessment report from a bounded offline inspection."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "vendor" / "runtime"))

from cops.assessments import ArtifactAssessmentError, assess  # noqa: E402
from cops.assessments.__main__ import _load_artifacts  # noqa: E402
from cops.assessments.reporting import to_assessment_report  # noqa: E402
from cops.contracts.lifecycle import ContractError  # noqa: E402

CAPABILITIES = {
    "cloud-posture-workbench": "cloud_configuration",
    "compliance-posture-workbench": "compliance_evidence",
    "network-segmentation-workbench": "network_segmentation",
    "secrets-remediation-workbench": "credential_history",
    "supply-chain-cicd-workbench": "supply_chain",
    "tls-crypto-workbench": "transport_identity",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="bounded JSON artifact envelope")
    parser.add_argument("--as-of", required=True, help="canonical RFC 3339 assessment timestamp")
    parser.add_argument("--report-id", required=True)
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--result-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--exclude-target", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        assessment = assess(
            CAPABILITIES[PACKAGE.name],
            _load_artifacts(args.input),
            as_of=args.as_of,
            engagement_id=args.engagement_id,
            scenario_id=args.scenario_id,
            result_id=args.result_id,
        )
        report = to_assessment_report(
            assessment,
            report_id=args.report_id,
            engagement_id=args.engagement_id,
            scenario_id=args.scenario_id,
            result_id=args.result_id,
            target=args.target,
            excluded_targets=args.exclude_target,
        )
    except (ArtifactAssessmentError, ContractError) as exc:
        code = exc.code if isinstance(exc, ArtifactAssessmentError) else "invalid_artifact_assessment"
        print(json.dumps({"error": code}, sort_keys=True), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"error": "input_read_error"}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
