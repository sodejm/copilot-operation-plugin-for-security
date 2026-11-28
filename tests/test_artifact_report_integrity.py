from __future__ import annotations

from cops.assessments import assess
from cops.assessments.reporting import to_assessment_report
from cops.contracts.validation import validate_contract
from cops.reporting.assessment import validate_report_semantics

AS_OF = "2026-10-15T12:00:00Z"
ASSESSMENT_CONTEXT = {
    "engagement_id": "eng-report-integrity",
    "scenario_id": "COPS-REPORT-INTEGRITY",
    "result_id": "res-report-integrity",
}
REPORT_CONTEXT = {
    **ASSESSMENT_CONTEXT,
    "report_id": "report-artifact-integrity",
    "target": "service.internal",
}


def test_repeated_findings_are_accepted_by_repository_reporting() -> None:
    assessment = assess(
        "application_security",
        [
            {
                "artifact_id": "source",
                "kind": "python_source",
                "content": "def one(value):\n    return eval(value)\n\ndef two(value):\n    exec(value)\n",
            }
        ],
        as_of=AS_OF,
        **ASSESSMENT_CONTEXT,
    )

    report = to_assessment_report(assessment, **REPORT_CONTEXT)

    validate_contract(report, "assessment_report")
    validate_report_semantics(report)
    assessment_ids = [finding["finding_id"] for finding in assessment["findings"]]
    report_ids = [finding["finding_id"] for finding in report["findings"]]
    assert len(assessment_ids) == len(set(assessment_ids)) == 2
    assert set(assessment["finding_codes"]) == set(assessment_ids)
    assert report_ids == assessment_ids
