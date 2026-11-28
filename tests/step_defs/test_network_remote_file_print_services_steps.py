# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
"""Step definitions for Network Remote Administration, File Sharing, and Printing Services BDD scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.discovery import (
    OfflineSyntheticRemoteCollector,
    RemoteAuthPrerequisite,
    RemoteExposureStatus,
    RemoteServiceCategory,
    assess_remote_services,
)

scenarios("../../specs/features/network_remote_file_print_services.feature")


@pytest.fixture
def bdd_ctx():
    return {
        "targets": ["vulnerable-server.corp.internal"],
        "targets_db": {
            "vulnerable-server.corp.internal": {
                "ssh": {
                    "password_auth": True,
                    "publickey_auth": False,
                    "version": "OpenSSH 6.6.1",
                },
                "telnet": {
                    "banner": "Cisco Telnet Gateway",
                    "auth_required": True,
                },
                "rdp": {
                    "nla_enabled": False,
                    "security_layer": "RDP",
                },
                "vnc": {
                    "auth_required": False,
                    "rfb_version": "003.008",
                },
                "winrm": {
                    "https_enforced": False,
                    "port": 5985,
                },
                "x11": {
                    "auth_required": False,
                    "display": ":0",
                },
                "smb": {
                    "smbv1_enabled": True,
                    "smb_signing_required": False,
                    "shares": ["backup", "netlogon"],
                    "anonymous_access": True,
                },
                "nfs": {
                    "no_root_squash": True,
                    "exports": ["/data (world)"],
                },
                "ftp": {
                    "anonymous_enabled": True,
                    "anonymous_login": True,
                    "banner": "ProFTPD 1.3.5",
                },
                "rsync": {
                    "auth_users_required": False,
                    "modules": ["public_sync"],
                },
                "ipp": {
                    "auth_required": False,
                    "printers": ["office_printer"],
                },
            },
            "hardened-server.corp.internal": {
                "ssh": {
                    "password_auth": False,
                    "publickey_auth": True,
                    "version": "OpenSSH 9.2",
                    "protected": True,
                },
                "rdp": {
                    "nla_enabled": True,
                    "protected": True,
                },
                "smb": {
                    "smbv1_enabled": False,
                    "smb_signing_required": True,
                    "anonymous_access": False,
                    "protected": True,
                },
            },
            "filtered-server.corp.internal": {
                "ssh": {"state": "filtered"},
                "smb": {"state": "closed"},
                "rdp": {"inaccessible": True},
            },
        },
        "collector": None,
        "report": None,
        "assessment": None,
        "candidates": [],
        "receipts": [],
        "canary_file": None,
    }


# Scenario 1: Assessing remote administration, file sharing, and printing services
@given("an approved target host exposing SSH, Telnet, RDP, VNC, WinRM, X11, SMB, NFS, FTP, rsync, and IPP")
def step_given_approved_target_host(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticRemoteCollector(targets=bdd_ctx["targets_db"])


@when("the remote services assessment engine executes protocol-specific probes")
def step_when_engine_executes_probes(bdd_ctx):
    bdd_ctx["report"] = assess_remote_services(
        targets=["vulnerable-server.corp.internal"],
        service_types=["ssh", "telnet", "rdp", "vnc", "winrm", "x11", "smb", "nfs", "ftp", "rsync", "ipp"],
        collector=bdd_ctx["collector"],
        vantage="internal",
        canary_artifact="canary_share/audit.tmp",
    )


@then("discrete assessments are recorded across remote administration, file sharing, and printing categories")
def step_then_discrete_assessments_recorded(bdd_ctx):
    report = bdd_ctx["report"]
    assert report is not None
    assert len(report.services_assessed) >= 11
    categories = {s.category for s in report.services_assessed}
    assert RemoteServiceCategory.REMOTE_ADMIN.value in categories
    assert RemoteServiceCategory.FILE_SHARING.value in categories
    assert RemoteServiceCategory.PRINTING.value in categories


@then("observed configurations, authentication prerequisites, and legacy versions are recorded for each service")
def step_then_configurations_and_versions_recorded(bdd_ctx):
    report = bdd_ctx["report"]
    smb_svc = next(s for s in report.services_assessed if s.service_type == "smb")
    assert smb_svc.is_legacy_or_unencrypted is True
    assert "shares" in smb_svc.configuration_details

    telnet_svc = next(s for s in report.services_assessed if s.service_type == "telnet")
    assert telnet_svc.is_legacy_or_unencrypted is True

    rdp_svc = next(s for s in report.services_assessed if s.service_type == "rdp")
    assert rdp_svc.auth_prerequisite == RemoteAuthPrerequisite.NONE.value


# Scenario 2: Enforcing truth-in-advertising boundary
@given("a remote service that is filtered, connection-refused, or timed out")
def step_given_filtered_remote_service(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticRemoteCollector(targets=bdd_ctx["targets_db"])


@when("the remote services assessment probe executes")
def step_when_remote_probe_executes(bdd_ctx):
    bdd_ctx["report"] = assess_remote_services(
        targets=["filtered-server.corp.internal"],
        service_types=["ssh", "smb", "rdp"],
        collector=bdd_ctx["collector"],
        vantage="external",
    )


@then('the service exposure status is strictly recorded as "inaccessible"')
def step_then_status_strictly_inaccessible(bdd_ctx):
    for s in bdd_ctx["report"].services_assessed:
        assert s.exposure_status == RemoteExposureStatus.INACCESSIBLE.value


@then('the service is never marked as "protected" or "hardened"')
def step_then_service_never_protected(bdd_ctx):
    for s in bdd_ctx["report"].services_assessed:
        assert s.exposure_status != RemoteExposureStatus.PROTECTED.value


@then('authentication prerequisite is recorded as "unknown" with explicit uncertainty notes')
def step_then_auth_prereq_unknown_with_uncertainty(bdd_ctx):
    for s in bdd_ctx["report"].services_assessed:
        assert s.auth_prerequisite == RemoteAuthPrerequisite.UNKNOWN.value
        assert len(s.uncertainty_notes) > 0
        assert "cannot be reported as secure or hardened" in s.uncertainty_notes[0]


# Scenario 3: Extracting host privilege candidates
@given("an evaluated target exhibiting SMBv1, missing SMB signing, RDP without NLA, and NFS with no root squash")
def step_given_target_with_vulnerabilities(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticRemoteCollector(targets=bdd_ctx["targets_db"])
    bdd_ctx["report"] = assess_remote_services(
        targets=["vulnerable-server.corp.internal"],
        service_types=["smb", "rdp", "nfs"],
        collector=bdd_ctx["collector"],
        vantage="internal",
    )


@when("host privilege candidates are extracted")
def step_when_candidates_extracted(bdd_ctx):
    bdd_ctx["candidates"] = bdd_ctx["report"].host_privilege_candidates


@then('actionable candidates for "smb_v1_enabled", "smb_signing_disabled", "rdp_nla_disabled", and "nfs_no_root_squash" are generated')
def step_then_actionable_candidates_generated(bdd_ctx):
    finding_types = {c.finding_type for c in bdd_ctx["candidates"]}
    assert "smb_v1_enabled" in finding_types
    assert "smb_signing_disabled" in finding_types
    assert "rdp_nla_disabled" in finding_types
    assert "nfs_no_root_squash" in finding_types


@then("each candidate contains service type, target host, port, lateral movement impact, SHA-256 evidence hash, and remediation guidance")
def step_then_candidate_fields_complete(bdd_ctx):
    for c in bdd_ctx["candidates"]:
        assert c.service_type
        assert c.target_host
        assert c.port > 0
        assert c.lateral_movement_impact
        assert c.evidence_hash
        assert len(c.evidence_hash) == 64
        assert c.remediation_guidance


# Scenario 4: Validating boundary controls using canary files
@given(parsers.parse('an assessment configured with canary file "{canary_file}"'))
def step_given_canary_file(bdd_ctx, canary_file):
    bdd_ctx["canary_file"] = canary_file
    bdd_ctx["collector"] = OfflineSyntheticRemoteCollector(targets=bdd_ctx["targets_db"])


@when("the remote services assessment executes canary file boundary probes")
def step_when_canary_probes_execute(bdd_ctx):
    bdd_ctx["report"] = assess_remote_services(
        targets=["vulnerable-server.corp.internal"],
        service_types=["smb"],
        collector=bdd_ctx["collector"],
        vantage="internal",
        canary_artifact=bdd_ctx["canary_file"],
    )


@then("canary validation status is confirmed in the assessment record")
def step_then_canary_validation_confirmed(bdd_ctx):
    smb_svc = bdd_ctx["report"].services_assessed[0]
    assert smb_svc.canary_validated is True
    assert smb_svc.canary_identifier == bdd_ctx["canary_file"]


@then(parsers.parse('a verified cleanup receipt with "{action_status}" status and receipt hash is emitted'))
def step_then_verified_cleanup_receipt_emitted(bdd_ctx, action_status):
    receipts = bdd_ctx["report"].cleanup_receipts
    assert len(receipts) > 0
    receipt = receipts[0]
    assert receipt.action_taken == action_status
    assert receipt.verified_clean is True
    assert receipt.receipt_hash
    assert len(receipt.receipt_hash) == 64


# Scenario 5: Reporting properly authenticated and hardened services
@given("a hardened server enforcing SSH public key authentication, RDP NLA, and SMB message signing")
def step_given_hardened_server(bdd_ctx):
    bdd_ctx["collector"] = OfflineSyntheticRemoteCollector(targets=bdd_ctx["targets_db"])


@when("the remote services assessment evaluates access controls")
def step_when_evaluates_hardened_controls(bdd_ctx):
    bdd_ctx["report"] = assess_remote_services(
        targets=["hardened-server.corp.internal"],
        service_types=["ssh", "rdp", "smb"],
        collector=bdd_ctx["collector"],
        vantage="internal",
    )


@then('the exposure status is reported as "protected"')
def step_then_status_protected(bdd_ctx):
    for s in bdd_ctx["report"].services_assessed:
        assert s.exposure_status == RemoteExposureStatus.PROTECTED.value


@then(parsers.parse('authentication prerequisites reflect "{p1}", "{p2}", and "{p3}"'))
def step_then_auth_prereqs_reflect(bdd_ctx, p1, p2, p3):
    prereqs = {s.auth_prerequisite for s in bdd_ctx["report"].services_assessed}
    assert p1 in prereqs
    assert p2 in prereqs
    assert p3 in prereqs


@then("zero unauthenticated host privilege candidates are generated")
def step_then_zero_unauthenticated_candidates(bdd_ctx):
    assert len(bdd_ctx["report"].host_privilege_candidates) == 0
