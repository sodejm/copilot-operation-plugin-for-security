from __future__ import annotations

import copy

import pytest

from cops.assessments import ArtifactAssessmentError, assess
from cops.assessments.reporting import EVIDENCE_NOTICE, to_assessment_report
from cops.contracts.validation import validate_contract
from cops.reporting.assessment import validate_report_semantics


AS_OF = "2026-10-15T12:00:00Z"
ASSESSMENT_CONTEXT = {
    "engagement_id": "eng-report-test",
    "scenario_id": "COPS-REPORT-TEST",
    "result_id": "res-report-test",
}
REPORT_CONTEXT = {
    **ASSESSMENT_CONTEXT,
    "report_id": "report-artifact-test",
    "target": "service.internal",
}


def _application_assessment(source: str) -> dict[str, object]:
    return assess(
        "application_security",
        [{"artifact_id": "source", "kind": "python_source", "content": source}],
        as_of=AS_OF,
        **ASSESSMENT_CONTEXT,
    )


def test_adapter_maps_vulnerable_offline_evidence_to_partial_import() -> None:
    assessment = _application_assessment("def parse(value):\n    return eval(value)\n")

    report = to_assessment_report(assessment, **REPORT_CONTEXT)

    validate_contract(report, "assessment_report")
    validate_report_semantics(report)
    assert report["schema_version"] == "cops.assessment-report/v1"
    assert report["evidence_notice"] == EVIDENCE_NOTICE
    assert report["coverage"] == [
        {
            "scenario_id": "COPS-REPORT-TEST",
            "target": "service.internal",
            "mode": "import",
            "provenance": "imported",
            "access": "available",
            "status": "partial",
            "result_id": "res-report-test",
            "evidence_records": [assessment["evidence"][0]["sha256"]],
        }
    ]
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["assessment_status"] == "partial"
    assert finding["verification"] == "partially-verified"
    assert finding["evidence_strength"] == "limited"
    assert finding["evidence_references"] == report["coverage"][0]["evidence_records"]
    assert "Not assessed for assets: service.internal" in finding["limitations"]


def test_adapter_keeps_corrected_static_review_partial_without_findings() -> None:
    assessment = _application_assessment("def parse(value):\n    return int(value)\n")

    report = to_assessment_report(
        assessment,
        excluded_targets=("admin.service.internal",),
        **REPORT_CONTEXT,
    )

    validate_report_semantics(report)
    assert report["scope"]["excluded_targets"] == ["admin.service.internal"]
    assert report["coverage"][0]["status"] == "partial"
    assert report["findings"] == []


def test_adapter_maps_insufficient_source_to_not_assessed() -> None:
    assessment = _application_assessment("def parse(")

    report = to_assessment_report(assessment, **REPORT_CONTEXT)

    validate_report_semantics(report)
    assert assessment["readiness"] == "insufficient_evidence"
    assert report["coverage"][0]["status"] == "not_assessed"
    assert report["coverage"][0]["access"] == "unknown"
    assert report["coverage"][0]["mode"] == "import"
    assert report["findings"][0]["assessment_status"] == "not_assessed"
    assert report["findings"][0]["verification"] == "unverified"
    assert report["findings"][0]["evidence_strength"] == "limited"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"extra": "sensitive marker"}),
        lambda value: value["evidence"][0].update({"sha256": "0" * 64}),
        lambda value: value["findings"][0].update({"scenario_id": "COPS-DIFFERENT"}),
        lambda value: value["coverage"].update({"kinds": ["unexpected_kind"]}),
    ],
    ids=["unknown-field", "evidence-hash", "finding-context", "coverage-kind"],
)
def test_adapter_rejects_tampered_native_assessment_without_echo(mutation) -> None:
    assessment = copy.deepcopy(
        _application_assessment("def parse(value):\n    return eval(value)\n")
    )
    mutation(assessment)

    with pytest.raises(ArtifactAssessmentError) as caught:
        to_assessment_report(assessment, **REPORT_CONTEXT)

    assert caught.value.code == "invalid_artifact_assessment"
    assert str(caught.value) == "invalid_artifact_assessment"
    assert "sensitive marker" not in str(caught.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("report_id", ""),
        ("engagement_id", ""),
        ("scenario_id", ""),
        ("result_id", ""),
        ("target", ""),
    ],
)
def test_adapter_requires_explicit_valid_report_context(field: str, value: str) -> None:
    context = dict(REPORT_CONTEXT)
    context[field] = value

    with pytest.raises(ArtifactAssessmentError) as caught:
        to_assessment_report(
            _application_assessment("def parse(value):\n    return int(value)\n"),
            **context,
        )

    assert caught.value.code == "invalid_artifact_assessment"
