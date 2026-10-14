"""Offline Windows privilege-boundary import and abuse-case tests."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, assess_document, load_report_bytes  # noqa: E402


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_windows_{name}_v1.json").read_text())


def test_host_discovery_metadata_tracks_portable_platforms() -> None:
    portable = json.loads((PACKAGE / "plugin.json").read_text())
    codex = json.loads((PACKAGE / ".codex-plugin" / "plugin.json").read_text())
    claude = json.loads((PACKAGE / ".claude-plugin" / "plugin.json").read_text())
    catalog = json.loads((ROOT / "catalog" / "plugins.json").read_text())
    catalog_entry = next(record for record in catalog["plugins"] if record["id"] == portable["name"])

    platform_terms = {"linux", "windows"}
    supported = set(portable["keywords"]) & platform_terms
    assert supported == platform_terms
    assert set(codex["keywords"]) & platform_terms == supported
    assert set(catalog_entry["tags"]) & platform_terms == supported
    descriptions = (
        portable["description"],
        codex["description"],
        claude["description"],
        codex["interface"]["shortDescription"],
        *codex["interface"]["defaultPrompt"],
    )
    assert all(platform in description.lower() for description in descriptions for platform in supported)


def test_all_windows_surfaces_and_reported_positive_canary() -> None:
    report = assess_document(fixture("vulnerable"))
    assert report["schema_version"] == "windows-1.0"
    assert report["mode"] == "offline_import"
    assert report["bridge"]["mode"] == "offline_windows_export"
    assert len(report["coverage"]) == 7
    assert len(report["observations"]) == 7
    assert report["observations"][0]["classification"] == "reported_canary_crossing"
    assert report["observations"][0]["cleanup_reported"] is True
    assert report["counts"]["reported_canary_crossing"] == 1
    assert report["counts"]["configuration_candidate"] == 5
    assert "demonstrated" not in json.dumps(report)


@pytest.mark.parametrize("case", ["protected", "remediated"])
def test_blocked_canary_cases(case: str) -> None:
    report = assess_document(fixture(case))
    assert report["observations"][0]["classification"] == "reported_canary_blocked"
    assert report["observations"][0]["canary_case"] == ("negative" if case == "protected" else "fixed")


def test_unsupported_surface_has_no_observation_or_safety_claim() -> None:
    report = assess_document(fixture("unsupported"))
    assert report["coverage"]["versioned_escalation_families"] == "unsupported"
    assert report["observations"] == []
    assert sum(report["counts"].values()) == 0


@pytest.mark.parametrize(
    ("field", "value", "decision"),
    [
        ("os_build", "10.0.10000", "inapplicable"),
        ("os_build", "unknown", "unresolved"),
        ("architecture", "arm64", "inapplicable"),
        ("architecture", "unknown", "unresolved"),
    ],
)
def test_host_context_decision(field: str, value: str, decision: str) -> None:
    payload = fixture("vulnerable")
    payload["host"][field] = value
    result = assess_document(payload)["observations"][0]
    assert result["decision"] == decision
    assert result["classification"] == "not_evaluated"


def test_numeric_build_comparison_and_inclusive_bounds() -> None:
    payload = fixture("vulnerable")
    requirement = payload["observations"][0]["requirements"]
    requirement["build_min"] = "10.0.9"
    requirement["build_max"] = "10.0.19045"
    assert assess_document(payload)["observations"][0]["decision"] == "selected"
    requirement["build_max"] = "10.0.10"
    assert assess_document(payload)["observations"][0]["decision"] == "inapplicable"


@pytest.mark.parametrize(
    ("field", "value", "decision"),
    [
        ("integrity", "low", "inapplicable"),
        ("integrity", "unknown", "unresolved"),
        ("elevated", False, "inapplicable"),
        ("elevated", "unknown", "unresolved"),
    ],
)
def test_token_context_decision(field: str, value: object, decision: str) -> None:
    payload = fixture("vulnerable")
    payload["host"]["token"][field] = value
    assert assess_document(payload)["observations"][0]["decision"] == decision


def test_required_privilege_missing_from_complete_or_partial_list() -> None:
    payload = fixture("vulnerable")
    payload["host"]["token"]["privileges"] = []
    assert assess_document(payload)["observations"][0]["decision"] == "inapplicable"
    payload["host"]["token"]["privileges_complete"] = False
    assert assess_document(payload)["observations"][0]["decision"] == "unresolved"


def test_protection_context_and_capability_declarations() -> None:
    payload = fixture("vulnerable")
    payload["host"]["protections"]["uac"] = "unknown"
    assert assess_document(payload)["observations"][0]["decision"] == "unresolved"
    payload["host"]["protections"]["uac"] = "disabled"
    assert assess_document(payload)["observations"][0]["decision"] == "inapplicable"
    payload["bridge"]["capabilities"].remove("service_permissions")
    with pytest.raises(ContractError):
        assess_document(payload)


@pytest.mark.parametrize("field", ["cleanup_verified", "disposable_host", "assessment_owned"])
def test_canary_safety_assertions_required(field: str) -> None:
    payload = fixture("vulnerable")
    payload["observations"][0]["canary"][field] = False
    with pytest.raises(ContractError):
        assess_document(payload)


def test_canary_requires_declared_capability_and_consistent_access() -> None:
    payload = fixture("vulnerable")
    payload["bridge"]["canary_assertions"] = False
    with pytest.raises(ContractError):
        assess_document(payload)
    payload["bridge"]["canary_assertions"] = True
    payload["observations"][0]["canary"]["after_access"] = "denied"
    with pytest.raises(ContractError):
        assess_document(payload)


def test_nonassessed_surface_and_family_id_rejected() -> None:
    payload = fixture("vulnerable")
    payload["coverage"]["service_permissions"] = "access_denied"
    with pytest.raises(ContractError):
        assess_document(payload)
    payload = fixture("vulnerable")
    del payload["observations"][-1]["family_id"]
    with pytest.raises(ContractError):
        assess_document(payload)


def test_raw_secret_field_rejected_without_echo() -> None:
    payload = fixture("vulnerable")
    payload["observations"][0]["credential_value"] = "never-echo-this"
    with pytest.raises(ContractError) as error:
        assess_document(payload)
    assert "never-echo-this" not in str(error.value)


def test_invalid_build_range_and_duplicate_privilege_fail_closed() -> None:
    payload = fixture("vulnerable")
    payload["observations"][0]["requirements"]["build_min"] = "10.0.99999"
    with pytest.raises(ContractError):
        assess_document(payload)
    payload = fixture("vulnerable")
    payload["host"]["token"]["privileges"].append("SeChangeNotifyPrivilege")
    with pytest.raises(ContractError):
        assess_document(payload)


def test_cli_is_deterministic_and_does_not_execute_export(tmp_path: Path) -> None:
    payload = fixture("vulnerable")
    before = copy.deepcopy(payload)
    assert assess_document(payload) == assess_document(payload)
    assert payload == before
    export = tmp_path / "export.json"
    export.write_text(json.dumps(payload))
    command = [sys.executable, str(PACKAGE / "scripts" / "assess.py"), str(export)]
    first = subprocess.run(command, capture_output=True, text=True, check=True)
    second = subprocess.run(command, capture_output=True, text=True, check=True)
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["mode"] == "offline_import"


def test_package_validator_rejects_wrong_semantics_under_optimized_python(tmp_path: Path) -> None:
    copied_package = tmp_path / PACKAGE.name
    shutil.copytree(PACKAGE, copied_package)
    fixture_path = copied_package / "fixtures" / "synthetic" / "host_windows_vulnerable_v1.json"
    payload = json.loads(fixture_path.read_text())
    payload["observations"][0]["canary"]["case"] = "negative"
    payload["observations"][0]["canary"]["after_access"] = "denied"
    fixture_path.write_text(json.dumps(payload))

    result = subprocess.run(
        [sys.executable, "-O", str(copied_package / "scripts" / "validate-package.py")],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Windows vulnerable classification mismatch" in result.stderr


def test_duplicate_keys_oversize_and_unknown_schema_rejected() -> None:
    with pytest.raises(ContractError):
        load_report_bytes(b'{"schema_version":"windows-1.0","schema_version":"windows-1.0"}')
    with pytest.raises(ContractError):
        load_report_bytes(b" " * (1024 * 1024 + 1))
    payload = fixture("vulnerable")
    payload["schema_version"] = "windows-2.0"
    with pytest.raises(ContractError):
        assess_document(payload)
