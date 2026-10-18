from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from cops.assessments import ArtifactAssessmentError, assess
from cops.contracts.models import Finding

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "artifact_assessment_cases_v1.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
CASES = FIXTURE["cases"]


def _artifacts(case: dict[str, Any]) -> list[dict[str, Any]]:
    result = copy.deepcopy(case["artifacts"])
    for artifact in result:
        encoded = artifact.pop("content_b64", None)
        if encoded is not None:
            artifact["content"] = base64.b64decode(encoded, validate=True)
    return result


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_pinned_artifact_assessment_cases(case: dict[str, Any]) -> None:
    artifacts = _artifacts(case)
    before = copy.deepcopy(artifacts)

    report = assess(case["capability"], artifacts, as_of=FIXTURE["as_of"])

    assert artifacts == before
    assert report["schema_version"] == "cops.artifact-assessment/v1"
    assert report["capability"] == case["capability"]
    assert report["assessment_mode"] == "offline"
    assert sorted(report["finding_codes"].values()) == sorted(case["expected_codes"])
    assert report["coverage"]["artifact_count"] == len(artifacts)
    assert report["limitations"]
    assert report["prerequisites"]
    for finding in report["findings"]:
        assert Finding.from_dict(finding).to_dict() == finding
    for evidence, artifact in zip(report["evidence"], artifacts, strict=True):
        assert set(evidence) == {"artifact_id", "kind", "sha256", "bytes"}
        content = artifact["content"]
        raw = (
            content
            if isinstance(content, bytes)
            else content.encode()
            if isinstance(content, str)
            else _canonical(content)
        )
        assert evidence["sha256"] == hashlib.sha256(raw).hexdigest()
        assert evidence["bytes"] == len(raw)

    serialized = json.dumps(report, sort_keys=True).lower()
    assert "untrusted_content" not in serialized
    assert "occurrences" not in serialized
    assert "ignore all previous" not in serialized
    assert "eval(value)" not in serialized


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_fixture_has_all_four_evidence_states_for_each_capability() -> None:
    observed: dict[str, set[str]] = {}
    for case in CASES:
        observed.setdefault(case["capability"], set()).add(case["phase"])

    assert len(observed) == 10
    assert all(phases == {"vulnerable", "corrected", "insufficient", "benign"} for phases in observed.values())


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        (
            {"artifacts": [{"artifact_id": "a", "kind": "python_source", "content": "x"}] * 2, "max_artifacts": 1},
            "artifact_count_limit",
        ),
        (
            {"artifacts": [{"artifact_id": "a", "kind": "python_source", "content": "xx"}], "max_artifact_bytes": 1},
            "artifact_size_limit",
        ),
        (
            {
                "artifacts": [
                    {"artifact_id": "a", "kind": "python_source", "content": "x"},
                    {"artifact_id": "b", "kind": "python_source", "content": "y"},
                ],
                "max_total_bytes": 1,
            },
            "total_size_limit",
        ),
    ],
)
def test_bounds_fail_with_content_free_error(kwargs: dict[str, Any], code: str) -> None:
    with pytest.raises(ArtifactAssessmentError) as caught:
        assess("application_security", as_of=FIXTURE["as_of"], **kwargs)

    assert caught.value.code == code
    assert str(caught.value) == code


def test_nested_credential_value_field_is_rejected_without_echo() -> None:
    artifact = {
        "artifact_id": "history",
        "kind": "git_history",
        "content": {"occurrences": [{"password": "do-not-copy"}]},
    }

    with pytest.raises(ArtifactAssessmentError) as caught:
        assess("credential_history", [artifact], as_of=FIXTURE["as_of"])

    assert caught.value.code == "credential_value_forbidden"
    assert "do-not-copy" not in str(caught.value)


def test_unsupported_artifact_returns_prerequisite_and_does_not_claim_readiness() -> None:
    report = assess(
        "network_segmentation",
        [{"artifact_id": "capture", "kind": "pcap", "content": b"not-a-pcap"}],
        as_of=FIXTURE["as_of"],
    )

    assert report["readiness"] == "insufficient_evidence"
    assert "registered-adapter:pcap-flow-extractor@1" in report["prerequisites"]
    assert any("registered adapter" in value for value in report["limitations"])


@pytest.mark.parametrize(
    ("case_id", "expected_readiness"),
    [
        ("app-corrected", "supported"),
        ("app-insufficient", "insufficient_evidence"),
        ("forensic-corrected", "limited"),
    ],
)
def test_module_cli_assesses_json_documents(tmp_path: Path, case_id: str, expected_readiness: str) -> None:
    case = next(item for item in CASES if item["id"] == case_id)
    input_path = tmp_path / f"{case_id}.json"
    input_path.write_text(json.dumps({"artifacts": case["artifacts"]}), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "cops.assessments",
            "assess",
            case["capability"],
            "--input",
            str(input_path),
            "--as-of",
            FIXTURE["as_of"],
        ],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    report = json.loads(completed.stdout)
    assert report["capability"] == case["capability"]
    assert report["readiness"] == expected_readiness
    assert sorted(report["finding_codes"].values()) == sorted(case["expected_codes"])


def test_module_cli_rejects_invalid_base64_without_echo(tmp_path: Path) -> None:
    input_path = tmp_path / "invalid.json"
    input_path.write_text(
        json.dumps(
            {
                "artifacts": [
                    {
                        "artifact_id": "binary",
                        "kind": "binary",
                        "content_b64": "not base64 with a sensitive marker",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "cops.assessments",
            "assess",
            "malware_static",
            "--input",
            str(input_path),
            "--as-of",
            FIXTURE["as_of"],
        ],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 2
    assert json.loads(completed.stderr) == {"error": "invalid_content_b64"}
    assert "sensitive marker" not in completed.stderr


@pytest.mark.parametrize(
    "changes",
    [
        {"decision": "unknown"},
        {"expected_decision": True},
        {"observed_calls": [None]},
        {"allowed_resources": ["public"]},
        {"allowed_resources": ["public"], "observed_resources": [5]},
    ],
)
def test_malformed_tool_observations_are_inconclusive(changes: dict) -> None:
    content = {
        "prompt_origin": "direct",
        "untrusted_content": "synthetic",
        "decision": "deny",
        "expected_decision": "deny",
        "allowed_tools": ["read"],
        "observed_calls": [],
    }
    report = assess(
        "foundry_security",
        [{"artifact_id": "gateway", "kind": "foundry_test", "content": {**content, **changes}}],
        as_of=FIXTURE["as_of"],
    )
    assert "foundry_security_test_insufficient_evidence" in report["finding_codes"].values()


def test_tool_gateway_reports_resource_scope_bypass() -> None:
    content = {
        "prompt_origin": "indirect",
        "untrusted_content": "synthetic",
        "decision": "allow",
        "expected_decision": "deny",
        "allowed_tools": ["read"],
        "observed_calls": ["read"],
        "allowed_resources": ["public"],
        "observed_resources": ["private"],
    }
    report = assess(
        "foundry_security",
        [{"artifact_id": "gateway", "kind": "foundry_test", "content": content}],
        as_of=FIXTURE["as_of"],
    )
    assert "foundry_resource_scope" in report["finding_codes"].values()


@pytest.mark.parametrize(
    "changes", [{"collected_at": "2030-01-01T00:00:00Z"}, {"evidence_refs": [None]}, {"framework_version": ""}]
)
def test_invalid_control_evidence_cannot_pass(changes: dict) -> None:
    record = {
        "framework": "SOC2",
        "framework_version": "2017",
        "control_id": "CC6.1",
        "status": "effective",
        "collected_at": FIXTURE["as_of"],
        "evidence_refs": ["evidence-1"],
    }
    report = assess(
        "compliance_evidence",
        [{"artifact_id": "control", "kind": "control_evidence", "content": {"controls": [{**record, **changes}]}}],
        as_of=FIXTURE["as_of"],
    )
    assert report["finding_codes"]
    assert all(item["verification"] == "unverified" for item in report["findings"])


@pytest.mark.parametrize(
    "changes",
    [
        {"source_ref": None},
        {"collected_at": None},
        {"custody": [{"at": "2026-10-15T10:00:00Z"}]},
        {"custody": [{"at": "2026-10-14T10:00:00Z", "actor_ref": "collector"}]},
        {"collected_at": "2030-01-01T00:00:00Z"},
    ],
)
def test_incomplete_forensic_provenance_cannot_pass(changes: dict) -> None:
    artifact = {
        "artifact_id": "disk",
        "kind": "disk_image",
        "content": b"synthetic",
        "source_ref": "source-1",
        "collected_at": "2026-10-15T10:00:00Z",
        "sha256": hashlib.sha256(b"synthetic").hexdigest(),
        "collection_authorized": True,
        "custody": [{"at": "2026-10-15T10:00:00Z", "actor_ref": "collector"}],
    }
    report = assess("forensic_evidence", [{**artifact, **changes}], as_of="2026-10-15T12:00:00Z")
    assert report["finding_codes"]
