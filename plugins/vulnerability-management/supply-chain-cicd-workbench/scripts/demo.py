"""Run bounded synthetic corrections without executing submitted content."""
from __future__ import annotations
import base64
import copy
import json
from pathlib import Path
import sys

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE / "vendor" / "runtime"))
from cops.assessments import assess  # noqa: E402
from cops.assessments.reporting import to_assessment_report  # noqa: E402


def main() -> int:
    fixture = json.loads((PACKAGE / "examples" / "correction-cases.json").read_text())
    outcomes = []
    for case in fixture["cases"]:
        artifacts = copy.deepcopy(case["artifacts"])
        for artifact in artifacts:
            if "content_b64" in artifact:
                artifact["content"] = base64.b64decode(artifact.pop("content_b64"), validate=True)
        report = assess(case["capability"], artifacts, as_of=fixture["as_of"])
        observed = sorted(report["finding_codes"].values())
        if observed != sorted(case["expected_codes"]):
            raise RuntimeError("correction fixture mismatch: " + case["id"])
        native_report = to_assessment_report(
            report,
            report_id="report-" + case["id"],
            engagement_id="eng-offline-artifact",
            scenario_id="COPS-OFFLINE-ARTIFACT",
            result_id="res-offline-artifact",
            target="fixture:" + case["id"],
        )
        coverage = native_report["coverage"][0]
        if coverage["provenance"] != "imported" or coverage["status"] not in {"partial", "not_assessed"}:
            raise RuntimeError("native report overstates offline coverage: " + case["id"])
        outcomes.append({"case": case["id"], "phase": case["phase"], "finding_codes": observed,
                         "readiness": report["readiness"], "evidence": report["evidence"],
                         "assessment_report_schema": native_report["schema_version"],
                         "assessment_status": coverage["status"]})
    print(json.dumps({"schema_version": "cops.correction-playback/v1", "mode": "offline",
                      "cases": outcomes, "laboratory_readiness": "unverified"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
