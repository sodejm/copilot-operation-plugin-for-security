"""Fail-closed checks for the Linux offline research profile."""

from __future__ import annotations

import hashlib
import os
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cops.adapters.registry import ToolAdapterRegistry
from cops.contracts import ActionPlan, ContractError
from cops.evidence.canonical import digest, utc_now
from cops.execution.cleanup import SideEffectLedger
from cops.execution.filesystem import open_directory_no_symlinks
from cops.execution.offline_research import (
    OfflineResearchError,
    stage_corpora,
    validate_offline_cat_adapter,
    validate_offline_request,
    verify_isolation_observation,
)
from cops.execution.sandbox import LinuxBubblewrapSandbox, OfflineIsolationViolation

WORKER_ID = "worker-offline-test"
INVENTORY = {"worker_identity": WORKER_ID, "tools": {"inert": "0.7.0"}}


def _profile(source: Path) -> dict:
    return {
        "profile": "offline-research",
        "version": "v1",
        "worker_identity": WORKER_ID,
        "worker_inventory_sha256": digest(INVENTORY),
        "corpora": [
            {
                "name": "sample",
                "path": str(source),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        ],
        "isolation_attestation": {"digest": "a" * 64, "observed_at": utc_now()},
    }


def _plan(
    profile: dict,
    *,
    target: str = "local:sample",
    operations: list[dict] | None = None,
    credentials: list[str] | None = None,
    egress: bool = False,
) -> ActionPlan:
    return ActionPlan.create(
        plan_id="plan-offline-test",
        engagement_id="eng-offline-test",
        scenario_id="scen-offline-test",
        target=target,
        specialist_id="cops-offline-specialist",
        operations=operations
        or [
            {
                "step_id": "step-1",
                "tool": "inert",
                "tool_version": "0.7.0",
                "action": "print_status",
                "arguments": {},
                "timeout_seconds": 10,
            }
        ],
        limits={"max_duration_seconds": 30, "max_output_bytes": 4096, "egress_allowed": egress},
        credential_references=credentials or [],
        created_at=utc_now(),
        platform_prerequisites=["linux"],
        offline_research=profile,
    )


def _validate(plan: ActionPlan, **overrides: object) -> None:
    options = {
        "worker_identity": WORKER_ID,
        "worker_inventory": INVENTORY,
        "cat_executable_sha256": None,
        "sandbox": LinuxBubblewrapSandbox(),
        "workspace_dir": None,
        "scope_guard": None,
        "credential_resolver": None,
        "egress_identity_verifier": None,
    }
    options.update(overrides)
    validate_offline_request(plan, **options)


def test_profile_is_bound_to_signed_plan_and_trusted_inventory(tmp_path):
    source = tmp_path.resolve() / "sample.txt"
    source.write_text("inert fixture\n", encoding="utf-8")
    plan = _plan(_profile(source))

    _validate(plan)
    altered = plan.to_dict()
    altered["offline_research"]["corpora"][0]["sha256"] = "0" * 64
    with pytest.raises(ContractError):
        ActionPlan.from_dict(altered)
    with pytest.raises(OfflineResearchError, match="inventory digest mismatch"):
        _validate(plan, worker_inventory={"worker_identity": WORKER_ID, "tools": {}})


@pytest.mark.parametrize("violation", ["url", "egress", "credentials", "proxy", "adapter", "stale"])
def test_profile_rejects_out_of_scope_requests(tmp_path, violation):
    source = tmp_path.resolve() / "sample.txt"
    source.write_text("inert fixture\n", encoding="utf-8")
    profile = _profile(source)
    options = {}
    if violation == "url":
        options["target"] = "https://example.invalid"
    elif violation == "egress":
        options["egress"] = True
    elif violation == "credentials":
        options["credentials"] = ["credential-ref"]
    elif violation == "proxy":
        options["operations"] = [
            {
                "step_id": "step-1",
                "tool": "inert",
                "tool_version": "0.7.0",
                "action": "print_status",
                "arguments": {"proxy": "http://example.invalid"},
                "timeout_seconds": 10,
            }
        ]
    elif violation == "adapter":
        options["operations"] = [
            {
                "step_id": "step-1",
                "tool": "curl",
                "tool_version": "8.0.0",
                "action": "fetch",
                "arguments": {},
                "timeout_seconds": 10,
            }
        ]
    elif violation == "stale":
        profile["isolation_attestation"]["observed_at"] = (
            (datetime.now(UTC) - timedelta(minutes=6)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        )
    with pytest.raises(OfflineResearchError):
        _validate(_plan(profile, **options))


def test_profile_rejects_mediators_and_untrusted_sandbox(tmp_path):
    source = tmp_path.resolve() / "sample.txt"
    source.write_text("fixture", encoding="utf-8")
    plan = _plan(_profile(source))
    for override in (
        {"scope_guard": object()},
        {"credential_resolver": object()},
        {"egress_identity_verifier": object()},
        {"sandbox": object()},
        {"workspace_dir": tmp_path.resolve()},
    ):
        with pytest.raises(OfflineResearchError):
            _validate(plan, **override)


def test_cat_adapter_requires_exact_pinned_executable_and_corpus_name(tmp_path):
    source = tmp_path.resolve() / "sample.txt"
    source.write_text("fixture", encoding="utf-8")
    profile = _profile(source)
    profile["cat_executable_sha256"] = "b" * 64
    operation = {
        "step_id": "step-1",
        "tool": "cat",
        "tool_version": "coreutils-9.4",
        "action": "read_local_corpus",
        "arguments": {"filename": "corpus-sample"},
        "timeout_seconds": 10,
    }
    _validate(_plan(profile, operations=[operation]), cat_executable_sha256="b" * 64)
    with pytest.raises(OfflineResearchError, match="pin mismatch"):
        _validate(_plan(profile, operations=[operation]), cat_executable_sha256="c" * 64)
    with pytest.raises(OfflineResearchError, match="outside the approved adapter profile"):
        _validate(
            _plan(profile, operations=[{**operation, "arguments": {"filename": "corpus-other"}}]),
            cat_executable_sha256="b" * 64,
        )


def test_cat_adapter_definition_cannot_change_after_executable_pin():
    adapter = ToolAdapterRegistry(executable_sha256_pins={"cat": "b" * 64}).get_adapter("cat")
    validate_offline_cat_adapter(adapter, expected_pin="b" * 64)

    changed_template = deepcopy(adapter)
    changed_template.actions["read_local_corpus"].base_args = ["--", "/extra"]
    with pytest.raises(OfflineResearchError, match="definition differs"):
        validate_offline_cat_adapter(changed_template, expected_pin="b" * 64)

    changed_probe = deepcopy(adapter)
    changed_probe.executable_verification = replace(
        changed_probe.executable_verification, version_args=("/extra", "--version")
    )
    with pytest.raises(OfflineResearchError, match="definition differs"):
        validate_offline_cat_adapter(changed_probe, expected_pin="b" * 64)


def test_rejected_started_process_observation_is_retained_before_release():
    approved = "a" * 64
    measured = {
        "interfaces": ["lo"],
        "routes": [],
        "ipv6_routes": [],
        "socket_fds": 0,
        "separate_network_namespace": True,
    }
    rejected = {"digest": "b" * 64, "measured": measured}
    recorded = []
    with pytest.raises(OfflineIsolationViolation, match="differs from approved isolation"):
        LinuxBubblewrapSandbox._authorize_offline_observation(rejected, approved, recorded.append)
    assert recorded == [rejected]

    network_channel = {"digest": approved, "measured": {**measured, "socket_fds": 1}}
    recorded.clear()
    with pytest.raises(OfflineIsolationViolation, match="has a network channel"):
        LinuxBubblewrapSandbox._authorize_offline_observation(network_channel, approved, recorded.append)
    assert recorded == [network_channel]


def test_corpus_staging_requires_approved_regular_file_and_digest(tmp_path):
    root = tmp_path.resolve()
    source = root / "sample.txt"
    source.write_text("approved fixture\n", encoding="utf-8")
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    workspace_fd = open_directory_no_symlinks(workspace)
    ledger = SideEffectLedger("plan-offline-test", "eng-offline-test", WORKER_ID, workspace_dir=workspace)
    try:
        profile = _profile(source)
        assert stage_corpora(profile, workspace=workspace, workspace_fd=workspace_fd, ledger=ledger) == [
            {"name": "sample", "sha256": profile["corpora"][0]["sha256"]}
        ]
        assert (workspace / "corpus-sample").read_bytes() == source.read_bytes()
        assert (workspace / "corpus-sample").stat().st_mode & 0o777 == 0o600

        source.write_text("substituted fixture\n", encoding="utf-8")
        profile["corpora"][0]["name"] = "changed"
        with pytest.raises(OfflineResearchError, match="failed its approved digest"):
            stage_corpora(profile, workspace=workspace, workspace_fd=workspace_fd, ledger=ledger)
    finally:
        os.close(workspace_fd)


def test_corpus_staging_rejects_symlink_and_oversized_file(tmp_path):
    root = tmp_path.resolve()
    source = root / "sample.txt"
    source.write_bytes(b"safe")
    link = root / "link.txt"
    link.symlink_to(source)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    workspace_fd = open_directory_no_symlinks(workspace)
    ledger = SideEffectLedger("plan-offline-test", "eng-offline-test", WORKER_ID, workspace_dir=workspace)
    try:
        profile = _profile(source)
        profile["corpora"][0]["path"] = str(link)
        with pytest.raises(OfflineResearchError, match="safely staged"):
            stage_corpora(profile, workspace=workspace, workspace_fd=workspace_fd, ledger=ledger)
        source.write_bytes(b"x" * (1024 * 1024 + 1))
        profile = _profile(source)
        with pytest.raises(OfflineResearchError, match="bounded regular file"):
            stage_corpora(profile, workspace=workspace, workspace_fd=workspace_fd, ledger=ledger)
    finally:
        os.close(workspace_fd)


def test_configuration_alone_does_not_satisfy_isolation_attestation(tmp_path):
    class ObservedSandbox:
        def observe_offline_isolation(self, **_kwargs):
            return {"digest": "b" * 64, "namespace_separate": False}

    source = tmp_path.resolve() / "sample.txt"
    source.write_bytes(b"fixture")
    profile = _profile(source)
    with pytest.raises(OfflineResearchError, match="does not match"):
        verify_isolation_observation(profile, sandbox=ObservedSandbox(), workspace=tmp_path.resolve(), workspace_fd=-1)
