"""Offline Linux host assessment contract and abuse-case tests."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, assess_document, load_report_bytes  # noqa: E402


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_linux_{name}_v1.json").read_text())


def test_all_surfaces_and_positive_canary_are_reported_without_live_claim() -> None:
    report = assess_document(fixture("positive"))
    assert report["mode"] == "offline_import"
    assert report["source"]["kind"] == "synthetic_lab"
    assert len(report["coverage"]) == 8
    assert len(report["observations"]) == 8
    positive = report["observations"][0]
    assert positive["decision"] == "selected"
    assert positive["classification"] == "reported_canary_crossing"
    assert positive["requirements"]["kernel_release"] == "6.8.0"
    assert positive["requirements"]["distribution_id"] == "ubuntu"
    assert positive["requirements"]["distribution_version"] == "24.04"
    assert positive["requirements"]["namespace"] == "host"
    assert positive["requirements"]["protections"] == {"apparmor": "enforcing"}
    assert report["counts"]["reported_canary_crossing"] == 1
    assert report["counts"]["configuration_candidate"] == 6
    assert report["counts"]["ordinary_configuration"] == 1
    assert "demonstrated" not in json.dumps(report)


@pytest.mark.parametrize("case", ["negative", "fixed"])
def test_blocked_canaries(case: str) -> None:
    result = assess_document(fixture(case))["observations"][0]
    assert result["classification"] == "reported_canary_blocked"
    assert result["canary_case"] == case


def test_unmatched_prerequisite_does_not_select_canary() -> None:
    payload = fixture("positive")
    payload["observations"][0]["requirements"]["namespace"] = "container"
    result = assess_document(payload)["observations"][0]
    assert result["decision"] == "inapplicable"
    assert result["classification"] == "not_evaluated"


def test_distribution_version_mismatch_does_not_select_canary() -> None:
    payload = fixture("positive")
    payload["host"]["distribution_version"] = "22.04"
    result = assess_document(payload)["observations"][0]
    assert result["decision"] == "inapplicable"
    assert result["classification"] == "not_evaluated"


def test_unknown_distribution_version_is_unresolved() -> None:
    payload = fixture("positive")
    payload["host"]["distribution_version"] = "unknown"
    result = assess_document(payload)["observations"][0]
    assert result["decision"] == "unresolved"
    assert result["classification"] == "not_evaluated"


def test_missing_distribution_version_requirement_is_rejected() -> None:
    payload = fixture("positive")
    del payload["observations"][0]["requirements"]["distribution_version"]
    with pytest.raises(ContractError):
        assess_document(payload)


def test_unknown_context_is_unresolved() -> None:
    payload = fixture("positive")
    payload["host"]["protections"]["apparmor"] = "unknown"
    result = assess_document(payload)["observations"][0]
    assert result["decision"] == "unresolved"
    assert result["classification"] == "not_evaluated"


@pytest.mark.parametrize("field", ["cleanup_verified", "disposable_host", "assessment_owned"])
def test_canary_safety_assertions_required(field: str) -> None:
    payload = fixture("positive")
    payload["observations"][0]["canary"][field] = False
    with pytest.raises(ContractError):
        assess_document(payload)


def test_positive_canary_cannot_claim_crossing_without_granted_access() -> None:
    payload = fixture("positive")
    payload["observations"][0]["canary"]["after_access"] = "denied"
    with pytest.raises(ContractError):
        assess_document(payload)


def test_nonassessed_surface_rejects_observation() -> None:
    payload = fixture("positive")
    payload["coverage"]["sudo"] = "access_denied"
    with pytest.raises(ContractError):
        assess_document(payload)


def test_raw_credential_field_rejected_and_not_echoed() -> None:
    payload = fixture("positive")
    payload["observations"][0]["credential_value"] = "never-echo-this"
    with pytest.raises(ContractError) as error:
        assess_document(payload)
    assert "never-echo-this" not in str(error.value)


def test_duplicate_ids_and_duplicate_json_keys_fail_closed() -> None:
    payload = fixture("positive")
    payload["observations"][1]["id"] = payload["observations"][0]["id"]
    with pytest.raises(ContractError):
        assess_document(payload)
    with pytest.raises(ContractError):
        load_report_bytes(b'{"schema_version":"1.0","schema_version":"1.0"}')


def test_oversized_and_nonfinite_json_fail_closed() -> None:
    with pytest.raises(ContractError):
        load_report_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ContractError):
        load_report_bytes(b'{"value": NaN}')


def test_deeply_nested_json_fails_closed_in_api_and_cli(tmp_path: Path) -> None:
    nested = b"[" * 1100 + b"0" + b"]" * 1100
    with pytest.raises(ContractError, match="nesting exceeds parser limit"):
        load_report_bytes(nested)
    export = tmp_path / "nested.json"
    export.write_bytes(nested)
    result = subprocess.run(
        [sys.executable, str(PACKAGE / "scripts" / "assess.py"), str(export)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert "JSON nesting exceeds parser limit" in result.stderr
    assert "Traceback" not in result.stderr


def test_json_depth_check_ignores_brackets_inside_strings() -> None:
    quoted = b'{"source_id":"source\\"' + b"[" * 1100 + b'"}'
    with pytest.raises(ContractError, match="document has missing or unsupported fields"):
        load_report_bytes(quoted)


def test_result_is_deterministic_and_does_not_modify_input() -> None:
    payload = fixture("positive")
    before = copy.deepcopy(payload)
    assert assess_document(payload) == assess_document(payload)
    assert payload == before
