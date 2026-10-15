"""Offline Windows privilege-boundary import and abuse-case tests."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import (  # noqa: E402
    MAX_INPUT_BYTES,
    ContractError,
    assess_document,
    load_report_bytes,
)
from host_assessment_workbench.windows_bridge import validate_bridge_receipt  # noqa: E402


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_windows_{name}_v1.json").read_text())


def native_payload() -> dict:
    payload = fixture("unsupported")
    payload["source_kind"] = "operator_export"
    payload["source_id"] = "native_windows_ci"
    payload["bridge"]["mode"] = "native_windows_bridge"
    payload["bridge"]["capabilities"] = ["registry_controls", "local_credential_references"]
    payload["coverage"]["registry_controls"] = "assessed"
    payload["coverage"]["local_credential_references"] = "assessed"
    return payload


def native_receipt(export_bytes: bytes, canary_root: Path) -> dict:
    root_identity = canary_root.resolve()
    resource_id = "native_canary_1"
    return {
        "schema_version": "windows-bridge-receipt-1.2",
        "platform": "windows",
        "bridge_mode": "native_windows_bridge",
        "export_sha256": hashlib.sha256(export_bytes).hexdigest(),
        "capabilities": ["registry_controls", "local_credential_references"],
        "canary": {
            "resource_id": resource_id,
            "root_identity": str(root_identity),
            "resource_identity": str(root_identity / resource_id),
            "ownership_sha256": hashlib.sha256(b"test ownership marker").hexdigest(),
            "assessment_owned": True,
            "before_absent": True,
            "created": True,
            "ownership_verified": True,
            "removed": True,
            "cleanup_verified": True,
            "observer_kind": "separate_same_token_process",
            "before_observation": "resource_absent",
            "after_create_observation": "readable_owned_marker",
            "after_cleanup_observation": "resource_absent",
            "evidence_ids": [
                "canary_before_observer",
                "canary_identity_bound",
                "canary_created",
                "canary_after_create_observer",
                "canary_ownership_verified",
                "canary_removed",
                "canary_after_cleanup_observer",
            ],
        },
    }


def powershell_function(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.find("\nfunction ", start + 1)
    return source[start:] if end == -1 else source[start:end]


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


def test_native_bridge_import_preserves_capability_and_coverage_boundaries() -> None:
    report = assess_document(native_payload())
    assert report["mode"] == "native_bridge_import"
    assert report["bridge"]["mode"] == "native_windows_bridge"
    assert report["bridge"]["canary_assertions"] is False
    assert report["coverage"]["registry_controls"] == "assessed"
    assert report["coverage"]["service_permissions"] == "not_assessed"


def test_native_bridge_cannot_self_assert_privilege_crossing() -> None:
    payload = native_payload()
    payload["bridge"]["canary_assertions"] = True
    with pytest.raises(ContractError, match="cannot assert privilege crossings"):
        assess_document(payload)


def test_native_bridge_receipt_is_bound_to_export_and_empty_canary_root(tmp_path: Path) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    result = validate_bridge_receipt(native_receipt(export_bytes, canary_root), export_bytes, canary_root)
    assert result["canary"]["cleanup_verified"] is True
    assert result["canary"]["ownership_verified"] is True
    assert result["canary"]["observer_kind"] == "separate_same_token_process"
    assert result["canary"]["after_create_observation"] == "readable_owned_marker"
    assert "crossing" not in json.dumps(result)


@pytest.mark.parametrize(
    "field",
    [
        "assessment_owned",
        "before_absent",
        "created",
        "ownership_verified",
        "removed",
        "cleanup_verified",
    ],
)
def test_native_bridge_receipt_requires_lifecycle_assertions(tmp_path: Path, field: str) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt = native_receipt(export_bytes, canary_root)
    receipt["canary"][field] = False
    with pytest.raises(ContractError):
        validate_bridge_receipt(receipt, export_bytes, canary_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observer_kind", "collector_process"),
        ("before_observation", "unknown"),
        ("after_create_observation", "resource_absent"),
        ("after_cleanup_observation", "readable_owned_marker"),
    ],
)
def test_native_bridge_receipt_requires_independent_lifecycle_observations(
    tmp_path: Path, field: str, value: str
) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt = native_receipt(export_bytes, canary_root)
    receipt["canary"][field] = value

    with pytest.raises(ContractError):
        validate_bridge_receipt(receipt, export_bytes, canary_root)


def test_native_bridge_receipt_rejects_changed_export_and_residue(tmp_path: Path) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt = native_receipt(export_bytes, canary_root)
    with pytest.raises(ContractError, match="hash"):
        validate_bridge_receipt(receipt, export_bytes + b" ", canary_root)
    (canary_root / "residue").write_text("unexpected")
    with pytest.raises(ContractError, match="not empty"):
        validate_bridge_receipt(receipt, export_bytes, canary_root)


def test_native_bridge_receipt_rejects_swapped_empty_canary_root(tmp_path: Path) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    recorded_root = tmp_path / "recorded"
    supplied_root = tmp_path / "supplied"
    recorded_root.mkdir()
    supplied_root.mkdir()

    with pytest.raises(ContractError, match="root identity"):
        validate_bridge_receipt(native_receipt(export_bytes, recorded_root), export_bytes, supplied_root)


def test_native_bridge_receipt_rejects_unowned_child_identity(tmp_path: Path) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt = native_receipt(export_bytes, canary_root)
    receipt["canary"]["resource_identity"] = str(canary_root.resolve() / "other_child")

    with pytest.raises(ContractError, match="resource identity"):
        validate_bridge_receipt(receipt, export_bytes, canary_root)


def test_native_bridge_receipt_requires_identity_and_ownership_evidence(tmp_path: Path) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt = native_receipt(export_bytes, canary_root)
    receipt["canary"]["evidence_ids"] = ["before", "created", "removed"]

    with pytest.raises(ContractError, match="bounded evidence IDs"):
        validate_bridge_receipt(receipt, export_bytes, canary_root)


@pytest.mark.parametrize("oversize_target", ["receipt", "export"])
def test_bridge_validator_rejects_oversize_input_before_parsing(tmp_path: Path, oversize_target: str) -> None:
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    receipt_path = tmp_path / "receipt.json"
    export_path = tmp_path / "export.json"
    receipt_path.write_text(
        json.dumps(native_receipt(export_bytes, canary_root), sort_keys=True, separators=(",", ":"))
    )
    export_path.write_bytes(export_bytes)
    selected_path = receipt_path if oversize_target == "receipt" else export_path
    selected_path.write_bytes(b" " * (MAX_INPUT_BYTES + 1))

    result = subprocess.run(
        [
            sys.executable,
            str(PACKAGE / "scripts" / "validate-windows-bridge.py"),
            str(receipt_path),
            str(export_path),
            "--canary-root",
            str(canary_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert f"{selected_path.name} exceeds the {MAX_INPUT_BYTES}-byte input limit" in result.stderr


def test_native_collector_records_only_enabled_privileges() -> None:
    script = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    common = (PACKAGE / "scripts" / "windows-bridge-common.ps1").read_text()
    resolver = powershell_function(common, "Resolve-CopsEnabledPrivileges")

    assert "$row.State -notin @('Enabled', 'Disabled')" in resolver
    assert "if ($row.State -eq 'Enabled')" in resolver
    assert "$enabled += $row.Privilege" in resolver
    assert "Resolve-CopsEnabledPrivileges -Rows $privilegeRows" in script
    assert "$line | ConvertFrom-Csv -Header Privilege, Description, State" not in script


def test_native_collector_validates_every_path_before_filesystem_probe() -> None:
    script = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    common = (PACKAGE / "scripts" / "windows-bridge-common.ps1").read_text()
    exercise = (PACKAGE / "scripts" / "exercise-windows-bridge.ps1").read_text()
    validator = powershell_function(common, "Assert-CopsLocalPathEntry")

    assert "$Path -notmatch '^[A-Za-z]:" in validator
    assert "$Path -match" in validator
    assert r"\.{1,2}" in validator
    assert "$Path.Substring(2).Contains(':')" in validator
    assert "$drive.DisplayRoot" in validator
    assert "[IO.DriveInfo]::new" in validator
    assert "[IO.DriveType]::Fixed" in validator
    assert "[IO.FileAttributes]::ReparsePoint" in validator
    syntax_validation = validator.index("if ($Path -notmatch")
    canonicalization = validator.index("$full = [IO.Path]::GetFullPath($Path)")
    drive_probe = validator.index("$drive = Get-PSDrive")
    ancestor_probe = validator.index("$item = Get-Item")
    assert syntax_validation < canonicalization < drive_probe < ancestor_probe
    assert "Assert-CopsLocalPathEntry -Path '\\\\server\\share'" in exercise
    assert "A remote PATH entry must be rejected before filesystem inspection." in exercise

    section_start = script.index("$pathDirectories =")
    section_end = script.index("$familyCoverage", section_start)
    section = script[section_start:section_end]
    validation_loop = section.index("foreach ($directory in $pathDirectories)")
    probe_loop = section.index("foreach ($directory in $pathDirectories)", validation_loop + 1)
    validation = section.index("Assert-CopsLocalPathEntry -Path $directory")
    existence_probe = section.index("Test-Path -LiteralPath $directory")
    acl_probe = section.index("Get-Acl -LiteralPath $directory")

    assert validation_loop < validation < probe_loop < existence_probe < acl_probe


def test_native_collector_uses_exclusive_create_for_all_artifact_writes() -> None:
    script = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    common = (PACKAGE / "scripts" / "windows-bridge-common.ps1").read_text()
    writer = powershell_function(common, "Write-CopsNewUtf8File")

    assert "[IO.FileMode]::CreateNew" in writer
    assert "[IO.FileAccess]::Write" in writer
    assert "[IO.FileShare]::None" in writer
    assert "finally {" in writer
    assert "$stream.Dispose()" in writer
    assert "[IO.File]::WriteAllText" not in script
    assert "Write-CopsNewUtf8File -Path $markerPath" in script
    assert "Write-CopsNewUtf8File -Path $outputFull" in script
    assert "Write-CopsNewUtf8File -Path $receiptFull" in script


def test_native_exercise_uses_exclusive_create_for_derived_artifacts() -> None:
    exercise = (PACKAGE / "scripts" / "exercise-windows-bridge.ps1").read_text()

    assert "[IO.File]::WriteAllText" not in exercise
    assert "Write-CopsNewUtf8File -Path $reportPath" in exercise
    assert "Write-CopsNewUtf8File -Path $validatedReceiptPath" in exercise


def test_native_exercise_reports_only_artifact_names() -> None:
    exercise = (PACKAGE / "scripts" / "exercise-windows-bridge.ps1").read_text()
    summary = exercise[exercise.rindex("[ordered]@{") :]

    for artifact in (
        "windows-export.json",
        "windows-receipt.json",
        "windows-report.json",
        "windows-validated-receipt.json",
    ):
        assert f'"{artifact}"' in summary
    for path_variable in (
        "$runFull",
        "$canaryRoot",
        "$exportPath",
        "$receiptPath",
        "$reportPath",
        "$validatedReceiptPath",
    ):
        assert path_variable not in summary


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell runtime is unavailable")
def test_native_path_validator_rejects_unc_before_probe_runtime() -> None:
    common_path = PACKAGE / "scripts" / "windows-bridge-common.ps1"
    quoted_common_path = str(common_path).replace("'", "''")
    command = (
        f". '{quoted_common_path}'; "
        "try { Assert-CopsLocalPathEntry -Path '\\\\server\\share'; exit 1 } "
        "catch { if ($_.Exception.Message -ne "
        "'PATH entry is not a fully qualified local drive path.') { exit 2 } }; exit 0"
    )

    result = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_native_canary_cleanup_is_identity_bound_and_fails_closed() -> None:
    script = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    section_start = script.index("New-Item -ItemType Directory -Path $canaryPath")
    section_end = script.index("$exportJson =", section_start)
    section = script[section_start:section_end]
    failure_cleanup = section[section.index("} catch {") :]

    assert section.index("Assert-CopsCanaryDirectoryIdentity") < section.index(
        "Write-CopsNewUtf8File -Path $markerPath"
    )
    assert section.index("Assert-CopsCanaryOwnership") < section.index("Remove-Item -LiteralPath $markerPath")
    assert section.index("Remove-Item -LiteralPath $markerPath") < section.index("Remove-Item -LiteralPath $canaryPath")
    assert "$lifecycleFailure = $_" in failure_cleanup
    assert failure_cleanup.index("Assert-CopsCanaryDirectoryIdentity") < failure_cleanup.index(
        "Get-ChildItem -LiteralPath $canaryPath"
    )
    assert "$children.Count -eq 1" in failure_cleanup
    assert "$children.Count -ne 0" in failure_cleanup
    assert failure_cleanup.index("Assert-CopsCanaryOwnership") < failure_cleanup.index(
        "Remove-Item -LiteralPath $markerPath"
    )
    assert "ownership-aware cleanup was refused or failed" in failure_cleanup
    assert "Residue may remain under the assessment canary root" in failure_cleanup
    assert "throw $lifecycleFailure" in failure_cleanup
    assert section.rindex("Invoke-CopsCanaryObserver") > section.index("Remove-Item -LiteralPath $canaryPath")


def test_native_collector_has_bounded_static_contract() -> None:
    script = (PACKAGE / "scripts" / "collect-windows.ps1").read_text()
    common = (PACKAGE / "scripts" / "windows-bridge-common.ps1").read_text()
    assert all(name in script for name in ("OutputPath", "ReceiptPath", "CanaryRoot"))
    assert "native_windows_bridge" in script
    assert "Invoke-Expression" not in script
    assert "Start-Process" not in script
    assert all(
        right in common
        for right in (
            "WriteData",
            "AppendData",
            "WriteExtendedAttributes",
            "WriteAttributes",
            "DeleteSubdirectoriesAndFiles",
            "Delete",
            "ChangePermissions",
            "TakeOwnership",
        )
    )
    assert all(composite not in common for composite in ("::Write -bor", "::Modify", "::FullControl"))
    assert "Resolve-CopsIntegrityLevel" in common
    assert "Resolve-CopsIntegrityLevelFromSources" in common
    assert 'return "unknown"' in common
    assert 'whoami.exe" /groups /fo csv /nh' in script
    assert "Resolve-CopsIntegrityLevelFromSources" in script
    assert "-PrimaryRids $primaryIntegrityRids" in script
    assert "$primaryIntegrityRids.Count -ne 1" not in script
    assert "Unable to determine a single Windows token integrity level" not in script
    assert "windows-bridge-receipt-1.2" in script
    assert "ownership_sha256" in script
    assert "observe-windows-canary.ps1" in script
    assert "separate_same_token_process" in script
    assert script.index("$ownershipVerified = $true") < script.index("Remove-Item -LiteralPath $canaryPath")
    workflow = (ROOT / ".github" / "workflows" / "repository-contract.yml").read_text()
    assert "Exercise native Windows host assessment bridge" in workflow
    assert "exercise-windows-bridge.ps1" in workflow
    exercise = (PACKAGE / "scripts" / "exercise-windows-bridge.ps1").read_text()
    assert "ReadAndExecute" in exercise
    assert "WriteData" in exercise
    assert "Resolve-CopsIntegrityLevel -Rids @()" in exercise
    assert "Resolve-CopsIntegrityLevel -Rids @(8192, 12288)" in exercise
    assert "Ambiguous primary token integrity SIDs must fail closed without fallback" in exercise
    assert "A missing primary token integrity SID must use the bounded fallback" in exercise
    assert "Ambiguous fallback token integrity SIDs must fail closed" in exercise
    assert "A failed token integrity fallback must fail closed" in exercise
    assert 'report.mode -ne "native_bridge_import"' in exercise
    assert "ownership_verified" in exercise
    assert "after_create_observation" in exercise


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
