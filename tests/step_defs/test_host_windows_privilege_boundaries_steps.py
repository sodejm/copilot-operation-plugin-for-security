"""BDD steps for the Windows privilege-boundary contract."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pytest_bdd import given, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "plugins" / "offensive-security" / "host-assessment-workbench"
sys.path.insert(0, str(PACKAGE))

from host_assessment_workbench.core import ContractError, assess_document  # noqa: E402
from host_assessment_workbench.windows_bridge import validate_bridge_receipt  # noqa: E402

scenarios("../../specs/features/host_windows_privilege_boundaries.feature")


@pytest.fixture
def context() -> dict:
    return {}


def fixture(name: str) -> dict:
    return json.loads((ROOT / "tests" / "fixtures" / f"host_windows_{name}_v1.json").read_text())


def native_payload() -> dict:
    payload = fixture("unsupported")
    payload["source_kind"] = "operator_export"
    payload["source_id"] = "native_windows_ci"
    payload["bridge"]["mode"] = "native_windows_bridge"
    payload["bridge"]["capabilities"] = ["registry_controls"]
    payload["coverage"]["registry_controls"] = "assessed"
    return payload


@given("the vulnerable synthetic Windows host fixture")
def vulnerable(context):
    context["payload"] = fixture("vulnerable")


@given("the protected and remediated synthetic Windows host fixtures")
def protected_remediated(context):
    context["payloads"] = [fixture("protected"), fixture("remediated")]


@given("a vulnerable synthetic Windows host fixture with an unmatched build")
def unmatched_build(context):
    context["payload"] = fixture("vulnerable")
    context["payload"]["host"]["os_build"] = "10.0.10000"


@given("a vulnerable synthetic Windows host fixture without cleanup assertion")
def no_cleanup(context):
    context["payload"] = fixture("vulnerable")
    context["payload"]["observations"][0]["canary"]["cleanup_verified"] = False


@given("a capability-declared native Windows bridge export")
def native_export(context):
    context["payload"] = native_payload()


@given("a native bridge export and assessment-owned cleanup receipt")
def native_receipt(context, tmp_path):
    export_bytes = json.dumps(native_payload(), sort_keys=True, separators=(",", ":")).encode()
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    root_identity = canary_root.resolve()
    resource_id = "native_canary_1"
    context["export_bytes"] = export_bytes
    context["canary_root"] = canary_root
    context["receipt"] = {
        "schema_version": "windows-bridge-receipt-1.2",
        "platform": "windows",
        "bridge_mode": "native_windows_bridge",
        "export_sha256": hashlib.sha256(export_bytes).hexdigest(),
        "capabilities": ["registry_controls"],
        "canary": {
            "resource_id": resource_id,
            "root_identity": str(root_identity),
            "resource_identity": str(root_identity / resource_id),
            "ownership_sha256": hashlib.sha256(b"test ownership marker").hexdigest(),
            "assessment_owned": True,
            "observer_kind": "separate_same_token_process",
            "before_observation": "resource_absent",
            "after_create_observation": "readable_owned_marker",
            "after_cleanup_observation": "resource_absent",
            "before_absent": True,
            "created": True,
            "ownership_verified": True,
            "removed": True,
            "cleanup_verified": True,
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


@when("the Windows host importer assesses it")
def assess_one(context):
    context["report"] = assess_document(context["payload"])


@when("the Windows host importer assesses both")
def assess_both(context):
    context["reports"] = [assess_document(payload) for payload in context["payloads"]]


@when("the Windows host importer attempts to assess it")
def attempts_assessment(context):
    assert "payload" in context


@when("the bridge receipt is validated against the export and empty canary root")
def validate_receipt(context):
    context["validated_receipt"] = validate_bridge_receipt(
        context["receipt"], context["export_bytes"], context["canary_root"]
    )


@then("the report identifies a source-reported canary crossing")
def reported_crossing(context):
    assert context["report"]["source"]["kind"] == "synthetic_lab"
    assert context["report"]["observations"][0]["classification"] == "reported_canary_crossing"


@then("all seven Windows surfaces have explicit coverage states")
def coverage(context):
    assert len(context["report"]["coverage"]) == 7


@then("the selected check records build, architecture, token, and protections")
def prerequisites(context):
    result = context["report"]["observations"][0]
    assert result["decision"] == "selected"
    assert set(result["requirements"]) == {"build_min", "build_max", "architecture", "token", "protections"}
    assert context["report"]["host"]["os_build"] == "10.0.19045"


@then("both reports identify source-reported blocked canaries")
def reported_blocked(context):
    assert all(
        report["observations"][0]["classification"] == "reported_canary_blocked" for report in context["reports"]
    )


@then("the Windows observation is inapplicable without a success classification")
def no_success(context):
    result = context["report"]["observations"][0]
    assert result["decision"] == "inapplicable"
    assert result["classification"] == "not_evaluated"


@then("the Windows importer rejects the incomplete canary report")
def rejects(context):
    with pytest.raises(ContractError):
        assess_document(context["payload"])


@then("the report preserves the native bridge mode and explicit coverage")
def native_mode(context):
    assert context["report"]["mode"] == "native_bridge_import"
    assert context["report"]["bridge"]["mode"] == "native_windows_bridge"
    assert context["report"]["coverage"]["registry_controls"] == "assessed"
    assert context["report"]["coverage"]["service_permissions"] == "not_assessed"


@then("the receipt preserves the separate-process lifecycle observations without claiming a privilege crossing")
def lifecycle_only(context):
    result = context["validated_receipt"]
    assert result["canary"]["cleanup_verified"] is True
    assert result["canary"]["observer_kind"] == "separate_same_token_process"
    assert result["canary"]["before_observation"] == "resource_absent"
    assert result["canary"]["after_create_observation"] == "readable_owned_marker"
    assert result["canary"]["after_cleanup_observation"] == "resource_absent"
    assert "crossing" not in json.dumps(result)
