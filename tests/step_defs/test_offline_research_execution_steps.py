"""Executable preflight scenarios; native Linux isolation needs separate evidence."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.execution import ApprovalStore
from cops.execution.cleanup import SideEffectLedger
from cops.execution.control import ApprovalControlError
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.offline_research import (
    OfflineResearchError,
    stage_corpora,
    verify_isolation_observation,
)
from tests.auth_testkit import TestApprovalControl, authorize_test_plan
from tests.test_offline_research import WORKER_ID, _plan, _profile, _validate

scenarios("../../specs/features/offline_research_execution.feature")


@pytest.fixture
def offline_context(tmp_path):
    source = tmp_path.resolve() / "sample.txt"
    source.write_bytes(b"approved fixture\n")
    profile = _profile(source)
    return {"root": tmp_path.resolve(), "source": source, "profile": profile, "plan": _plan(profile)}


@given("an offline research plan for a pinned local corpus and worker")
def approved_local_plan(offline_context):
    _validate(offline_context["plan"])


def _stage(context, profile):
    workspace = context["root"] / "workspace"
    workspace.mkdir(mode=0o700, exist_ok=True)
    workspace_fd = open_directory_no_symlinks(workspace)
    try:
        ledger = SideEffectLedger(
            "plan-offline-test", "eng-offline-test", WORKER_ID, workspace_dir=workspace
        )
        return stage_corpora(profile, workspace=workspace, workspace_fd=workspace_fd, ledger=ledger)
    finally:
        os.close(workspace_fd)


@when("preflight validates and stages the approved corpus")
def stage_approved_corpus(offline_context):
    offline_context["staged"] = _stage(offline_context, offline_context["profile"])

    class SyntheticObservation:
        def observe_offline_isolation(self, **_kwargs):
            return {
                "digest": offline_context["profile"]["isolation_attestation"]["digest"],
                "scope": "synthetic",
            }

    offline_context["observation"] = verify_isolation_observation(
        offline_context["profile"],
        sandbox=SyntheticObservation(),
        workspace=offline_context["root"] / "workspace",
        workspace_fd=-1,
    )


@then("the staged digest and synthetic isolation observation match the plan")
def verify_staged_evidence(offline_context):
    profile = offline_context["profile"]
    assert offline_context["staged"] == [
        {"name": "sample", "sha256": profile["corpora"][0]["sha256"]}
    ]
    assert offline_context["observation"] == {
        "digest": profile["isolation_attestation"]["digest"],
        "scope": "synthetic",
    }


@when("the corpus changes, is oversized, or becomes a symlink")
def stage_unsafe_sources(offline_context):
    source = offline_context["source"]
    profile = offline_context["profile"]
    failures = []
    source.write_bytes(b"changed fixture")
    with pytest.raises(OfflineResearchError):
        _stage(offline_context, profile)
    failures.append("changed")
    source.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(OfflineResearchError):
        _stage(offline_context, profile)
    failures.append("oversized")
    source.unlink()
    source.symlink_to(offline_context["root"] / "other.txt")
    with pytest.raises(OfflineResearchError):
        _stage(offline_context, profile)
    failures.append("symlink")
    offline_context["failures"] = failures


@then("corpus staging rejects every unsafe source")
def verify_unsafe_sources_rejected(offline_context):
    assert offline_context["failures"] == ["changed", "oversized", "symlink"]


@when("the target, adapter, arguments, egress policy, or credentials request an external channel")
def validate_external_channels(offline_context):
    profile = offline_context["profile"]
    forbidden = (
        {"target": "https://example.invalid"},
        {
            "operations": [
                {
                    "step_id": "step-1",
                    "tool": "curl",
                    "tool_version": "8.0.0",
                    "action": "fetch",
                    "arguments": {},
                    "timeout_seconds": 10,
                }
            ]
        },
        {
            "operations": [
                {
                    "step_id": "step-1",
                    "tool": "inert",
                    "tool_version": "0.7.0",
                    "action": "print_status",
                    "arguments": {"proxy": "http://example.invalid"},
                    "timeout_seconds": 10,
                }
            ]
        },
        {"egress": True},
        {"credentials": ["credential-ref"]},
    )
    for options in forbidden:
        with pytest.raises(OfflineResearchError):
            _validate(_plan(profile, **options))
    offline_context["external_rejections"] = len(forbidden)


@then("offline request preflight rejects every external channel")
def verify_external_channels_rejected(offline_context):
    assert offline_context["external_rejections"] == 5


@when("the isolation observation is stale or differs from the approved digest")
def validate_isolation_evidence(offline_context):
    profile = dict(offline_context["profile"])
    profile["isolation_attestation"] = dict(profile["isolation_attestation"])
    profile["isolation_attestation"]["observed_at"] = (
        (datetime.now(UTC) - timedelta(minutes=6))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    with pytest.raises(OfflineResearchError, match="stale"):
        _validate(_plan(profile))

    class WrongObservation:
        def observe_offline_isolation(self, **_kwargs):
            return {"digest": "b" * 64}

    with pytest.raises(OfflineResearchError, match="does not match"):
        verify_isolation_observation(
            offline_context["profile"],
            sandbox=WrongObservation(),
            workspace=offline_context["root"],
            workspace_fd=-1,
        )
    offline_context["isolation_rejections"] = 2


@then("isolation preflight rejects the invalid evidence")
def verify_isolation_evidence_rejected(offline_context):
    assert offline_context["isolation_rejections"] == 2


@when("the approval client receives a substituted receipt")
def substitute_receipt(offline_context):
    plan = offline_context["plan"]
    authorization, trust_store, engagement = authorize_test_plan(plan, worker_identity=WORKER_ID)
    store = ApprovalStore(offline_context["root"] / "approvals.sqlite3")
    store.store_authorization(authorization)
    control = TestApprovalControl(store, trust_store, engagement)
    receipt = control.consume_authorization(authorization.authorization_id, plan, WORKER_ID)
    offline_context["control"] = control
    offline_context["receipt"] = receipt
    offline_context["substituted_receipt"] = replace(receipt)


@then("receipt provenance validation rejects the substitution")
def verify_substituted_receipt_rejected(offline_context):
    control = offline_context["control"]
    receipt = offline_context["receipt"]
    assert control.validate_receipt_provenance(receipt) is receipt
    with pytest.raises(ApprovalControlError, match="not issued"):
        control.validate_receipt_provenance(offline_context["substituted_receipt"])
