"""Adversarial coverage for verified adapter executable launches."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sqlite3
import stat
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cops.execution.cleanup as cleanup_module
import cops.execution.evidence as evidence_module
import cops.execution.executable as executable_module
import cops.execution.process as process_module
import cops.execution.worker as worker_module
from cops.adapters import (
    AdapterError,
    ExecutableVerification,
    ToolActionDefinition,
    ToolAdapter,
    ToolAdapterRegistry,
)
from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest
from cops.execution import (
    ApprovalStore,
    CleanupJournal,
    CleanupManager,
    CleanupPersistenceError,
    IsolatedWorker,
    SideEffectLedger,
    WorkerIsolationError,
)
from cops.execution.credentials import CredentialGrant, ScopedCredentialResolver
from cops.execution.evidence import EvidenceCaptureError, EvidenceCleanupError, EvidenceContext, EvidenceRecorder
from cops.execution.executable import (
    ExecutablePreparationTimeoutError,
    ExecutableVerificationError,
    prepare_executable,
)
from cops.execution.process import BoundedProcessResult, run_bounded_process
from tests.auth_testkit import (
    TestApprovalControl,
    TestExecutionSandbox,
    authorize_test_plan,
    worker_inventory_for_plan,
)

HAS_PROC_FD = Path("/proc/self/fd").is_dir()

_TEST_CONTROLS: dict[int, TestApprovalControl] = {}
_TEST_SANDBOXES: dict[int, TestExecutionSandbox] = {}


def _approval_control(worker: IsolatedWorker) -> TestApprovalControl:
    return _TEST_CONTROLS[id(worker)]


def _sandbox(worker: IsolatedWorker) -> TestExecutionSandbox:
    return _TEST_SANDBOXES[id(worker)]


@pytest.fixture(autouse=True)
def simulate_supported_launch_for_mocked_worker_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep process-mocked worker tests portable; explicit preflight tests override this."""
    if not HAS_PROC_FD:
        monkeypatch.setattr(worker_module, "verify_executable_launch_support", lambda: None)


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _evidence_context() -> EvidenceContext:
    return EvidenceContext(
        plan_id="plan-test",
        plan_digest="a" * 64,
        authorization_id="authorization-test",
        engagement_id="engagement-test",
        worker_identity="worker-test",
        target="example.test",
    )


def _python_adapter(*, pinned_revision: str | None = None) -> ToolAdapter:
    executable = Path(sys.executable).resolve()
    return ToolAdapter(
        tool="fake-python",
        version="adapter-contract-1",
        binary=str(executable),
        provenance={
            "source": "https://www.python.org/",
            "license": "PSF-2.0",
            "pinned_revision": pinned_revision or platform.python_version(),
        },
        supported_environments=["linux"],
        actions={
            "run": ToolActionDefinition(
                action="run",
                description="Run a fixed fake-tool scenario",
                base_args=[],
                parameters={},
            )
        },
        executable_verification=ExecutableVerification(
            sha256=_sha256(executable),
            version_args=("--version",),
            version_pattern=r"Python (?P<version>[0-9.]+)",
            max_size_bytes=64 * 1024 * 1024,
        ),
    )


def _fake_adapter() -> ToolAdapter:
    return ToolAdapter(
        tool="fake-tool",
        version="1.0.0",
        binary="fake-tool",
        provenance={
            "source": "https://example.invalid/fake-tool",
            "license": "MIT",
            "pinned_revision": "1.0.0",
        },
        supported_environments=["linux", "darwin"],
        actions={
            "run": ToolActionDefinition(
                action="run",
                description="Run a controlled fake-tool result",
                base_args=[],
                parameters={},
            )
        },
        executable_verification=ExecutableVerification(
            sha256="0" * 64,
            version_args=("--version",),
            version_pattern=r"(?P<version>[0-9.]+)",
        ),
    )


def _fake_action_plan(
    tmp_path: Path,
    *,
    timeout_seconds: float = 5,
    max_output_bytes: int = 4096,
    idempotent: bool = False,
    credential_references: list[str] | None = None,
    step_ids: tuple[str, ...] = ("step-fake",),
    cleanup_target: Path | None = None,
) -> ActionPlan:
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json").read_text(
            encoding="utf-8"
        )
    )
    limits = dict(fixture["limits"])
    limits["max_output_bytes"] = max_output_bytes
    limits["max_duration_seconds"] = 30
    operations = [
        {
            "step_id": step_id,
            "tool": "fake-tool",
            "tool_version": "1.0.0",
            "action": "run",
            "arguments": {},
            "timeout_seconds": timeout_seconds,
            "idempotent": idempotent,
            **(
                {
                    "cleanup": {
                        "resource_type": "file",
                        "target": str(cleanup_target),
                        "action": "delete",
                    }
                }
                if cleanup_target is not None
                else {}
            ),
        }
        for step_id in step_ids
    ]
    return ActionPlan.create(
        plan_id=f"plan-fake-{tmp_path.name}",
        engagement_id=fixture["engagement_id"],
        scenario_id=fixture["scenario_id"],
        target=fixture["target"],
        specialist_id=fixture["specialist_id"],
        operations=operations,
        limits=limits,
        credential_references=credential_references or [],
        created_at=fixture["created_at"],
    )


def _fake_worker(
    tmp_path: Path,
    plan: ActionPlan,
    *,
    credential_provider=None,
    credential_grants: list[CredentialGrant] | None = None,
    cleanup_journal_path: Path | None = None,
) -> tuple[IsolatedWorker, str]:
    (tmp_path / "workspace").mkdir(mode=0o700, parents=True, exist_ok=True)
    store = ApprovalStore(tmp_path / "approval.sqlite3")
    if cleanup_journal_path is None:
        journal_root = tmp_path.resolve() / "cleanup-journal"
        journal_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        cleanup_journal_path = journal_root / "cleanup.sqlite3"
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="test-worker-01", valid_hours=2)
    store.store_authorization(auth)
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    registry.register_adapter(_fake_adapter())
    approval_control = TestApprovalControl(store, trust_store, engagement)
    sandbox = TestExecutionSandbox()
    resolver = (
        ScopedCredentialResolver(
            credential_provider,
            credential_grants or [],
            approval_control=approval_control,
        )
        if credential_provider is not None
        else None
    )
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-01"),
        approval_control,
        sandbox,
        adapter_registry=registry,
        credential_resolver=resolver,
        cleanup_journal_path=cleanup_journal_path,
    )
    _TEST_CONTROLS[id(worker)] = approval_control
    _TEST_SANDBOXES[id(worker)] = sandbox
    return worker, auth.authorization_id


def _cleanup_events(worker: IsolatedWorker) -> list[tuple[str, str, dict[str, object]]]:
    assert worker.cleanup_journal is not None
    with sqlite3.connect(worker.cleanup_journal.path) as connection:
        rows = connection.execute(
            "SELECT event_type, effect_id, payload_json FROM cleanup_events ORDER BY sequence"
        ).fetchall()
    return [
        (str(event_type), str(effect_id), json.loads(str(payload_json))) for event_type, effect_id, payload_json in rows
    ]


def _cleanup_run_count(worker: IsolatedWorker) -> int:
    assert worker.cleanup_journal is not None
    with sqlite3.connect(worker.cleanup_journal.path) as connection:
        row = connection.execute("SELECT COUNT(*) FROM cleanup_runs").fetchone()
    assert row is not None
    return int(row[0])


@pytest.mark.parametrize(
    ("program", "expected_code", "timed_out", "overflow"),
    [
        ("print('ok')", 0, False, False),
        ("import sys; print('nonzero-three'); sys.exit(3)", 3, False, False),
        ("import sys; print('failed', file=sys.stderr); sys.exit(9)", 9, False, False),
        ("import time; time.sleep(30)", -9, True, False),
        ("import time; print('x' * 10000, flush=True); time.sleep(30)", -9, False, True),
    ],
    ids=("success", "nonzero-three", "failure", "timeout", "output-overflow"),
)
def test_fake_tool_process_matrix(
    tmp_path: Path,
    program: str,
    expected_code: int,
    timed_out: bool,
    overflow: bool,
) -> None:
    result = run_bounded_process(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=os.environ,
        timeout_seconds=0.2 if timed_out else 5,
        max_output_bytes=64 if overflow else 4096,
    )

    assert result.returncode == expected_code
    assert result.timed_out is timed_out
    assert result.output_limit_exceeded is overflow
    assert result.captured_bytes <= (64 if overflow else 4096)
    if timed_out or overflow:
        assert result.stdout == b""
        assert result.stderr == b""
        assert result.captured_bytes == 0


@pytest.mark.parametrize(
    ("program", "timeout_seconds", "max_output_bytes", "flag"),
    [
        (
            "import sys; sys.stdout.write('password=super'); sys.stdout.flush(); import time; time.sleep(30)",
            0.2,
            4096,
            "timed_out",
        ),
        ("print('password=supersecret')", 5, 12, "output_limit_exceeded"),
    ],
    ids=("timeout-mid-secret", "overflow-mid-secret"),
)
def test_bounded_process_suppresses_unsafe_partial_output(
    tmp_path: Path,
    program: str,
    timeout_seconds: float,
    max_output_bytes: int,
    flag: str,
) -> None:
    result = run_bounded_process(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=os.environ,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )

    assert getattr(result, flag)
    assert result.stdout == b""
    assert result.stderr == b""
    assert result.captured_bytes == 0


@pytest.mark.parametrize(
    ("process_result", "expected_status", "expected_exit_code"),
    [
        (BoundedProcessResult(b"ok\n", b"", 0, False, False), "success", 0),
        (BoundedProcessResult(b"", b"", -9, True, False), "uncertain", 124),
        (BoundedProcessResult(b"x" * 64, b"", -9, False, True), "uncertain", 125),
        (BoundedProcessResult(b"", b"terminated\n", -15, False, False), "failed", 143),
        (BoundedProcessResult(b"", b"failed\n", 9, False, False), "failed", 9),
    ],
    ids=("success", "timeout", "output-overflow", "signal", "failure"),
)
def test_worker_normalizes_fake_tool_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process_result: BoundedProcessResult,
    expected_status: str,
    expected_exit_code: int,
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    _sandbox(worker).result = process_result
    recorded_exit_codes: list[int] = []
    recorded_tool_versions: list[str] = []
    original_record = EvidenceRecorder.record_step_output

    def record_with_exit_code(self, **kwargs):
        recorded_exit_codes.append(kwargs["exit_code"])
        recorded_tool_versions.append(kwargs["tool_version"])
        return original_record(self, **kwargs)

    monkeypatch.setattr(EvidenceRecorder, "record_step_output", record_with_exit_code)

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == expected_status
    assert result.exit_code == expected_exit_code
    assert recorded_exit_codes == [expected_exit_code]
    assert recorded_tool_versions == ["1.0.0"]
    if expected_status == "uncertain":
        assert "automatic repeat disallowed" in result.status_details["reason"]


def test_worker_uses_sandbox_for_version_probe_and_owner_resource_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    worker.config = replace(worker.config, max_wall_time_seconds=1, max_output_bytes=100)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    probe_results = []

    def capture_probe_runner(*args, **kwargs):
        probe_results.append(
            kwargs["process_runner"](
                ["probe"],
                cwd=kwargs["workspace"],
                env=kwargs["env"],
                timeout_seconds=0.1,
                max_output_bytes=100,
            )
        )
        return prepared

    monkeypatch.setattr(worker_module, "prepare_executable", capture_probe_runner)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert result.status == "success"
    assert len(probe_results) == 1
    assert probe_results[0].returncode == 0
    assert [call["command"][0] for call in _sandbox(worker).run_calls] == ["probe", prepared.invocation_path]
    assert all(call["max_output_bytes"] == 100 for call in _sandbox(worker).run_calls)
    assert 0 < _sandbox(worker).run_calls[-1]["timeout_seconds"] <= 1


@pytest.mark.parametrize(
    ("timed_out", "overflow", "expected_exit_code"),
    [(True, False, 124), (False, True, 125)],
)
def test_idempotent_step_timeout_or_overflow_is_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timed_out: bool,
    overflow: bool,
    expected_exit_code: int,
) -> None:
    plan = _fake_action_plan(tmp_path, idempotent=True)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    _sandbox(worker).result = BoundedProcessResult(b"", b"", -9, timed_out, overflow)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert result.status == "partial"
    assert result.exit_code == expected_exit_code


@pytest.mark.parametrize("registered_version", (None, "2.0.0"), ids=("missing", "version-mismatch"))
def test_worker_rejects_adapter_mismatch_before_consuming_approval(
    tmp_path: Path, registered_version: str | None
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    if registered_version is not None:
        adapter = _fake_adapter()
        adapter.version = registered_version
        registry.register_adapter(adapter)
    worker.adapter_registry = registry

    with pytest.raises(worker_module.WorkerExecutionError, match="registered execution adapter|logical version"):
        worker.execute_plan(plan, authorization=authorization_id)

    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"


def test_worker_rejects_unsupported_adapter_environment_before_consuming_approval(tmp_path: Path) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    adapter = worker.adapter_registry.get_adapter("fake-tool")
    adapter.supported_environments = ["darwin" if sys.platform.startswith("linux") else "linux"]

    with pytest.raises(worker_module.WorkerExecutionError, match="incompatible with this worker environment"):
        worker.execute_plan(plan, authorization=authorization_id)

    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"


def test_worker_rejects_unsupported_executable_launch_before_consuming_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)

    def unsupported_launch() -> None:
        raise ExecutableVerificationError("private host path")

    monkeypatch.setattr(worker_module, "verify_executable_launch_support", unsupported_launch)

    with pytest.raises(WorkerIsolationError, match="verified adapter launch is unavailable") as caught:
        worker.execute_plan(plan, authorization=authorization_id)

    assert "private host path" not in str(caught.value)
    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"


@pytest.mark.parametrize("failure_site", ("collector", "evidence"))
def test_worker_marks_post_dispatch_failures_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_site: str
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    launched = 0

    def launch(*args, **kwargs):
        nonlocal launched
        launched += 1
        if failure_site == "collector":
            raise RuntimeError("private collector failure")
        return BoundedProcessResult(b"result", b"", 0, False, False)

    _sandbox(worker).run_callback = launch
    if failure_site == "evidence":

        def fail_capture(self, **kwargs):
            raise EvidenceCaptureError("private evidence failure")

        monkeypatch.setattr(EvidenceRecorder, "record_step_output", fail_capture)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert launched == 1
    assert result.status == "uncertain"
    assert result.exit_code == 1
    assert "automatic repeat disallowed" in result.status_details["reason"]
    assert "private" not in json.dumps(result.to_dict())


def test_bounded_process_reaps_child_if_selector_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = []
    original_popen = process_module.subprocess.Popen

    def start_process(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        launched.append(child)
        return child

    class FailingSelector:
        def register(self, *args, **kwargs):
            raise RuntimeError("selector setup failed")

        def close(self):
            pass

    monkeypatch.setattr(process_module.subprocess, "Popen", start_process)
    monkeypatch.setattr(process_module.selectors, "DefaultSelector", FailingSelector)

    with pytest.raises(RuntimeError, match="selector setup failed"):
        run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            max_output_bytes=4096,
        )

    assert len(launched) == 1
    assert launched[0].poll() is not None
    assert launched[0].stdout is not None and launched[0].stdout.closed
    assert launched[0].stderr is not None and launched[0].stderr.closed


@pytest.mark.parametrize("group_state", ("gone", "gone_after_reap", "live"))
def test_process_group_cleanup_requires_no_live_descendants_after_darwin_permission_race(
    monkeypatch: pytest.MonkeyPatch, group_state: str
) -> None:
    signals = []

    def killpg(group_id: int, signal_number: int) -> None:
        signals.append(signal_number)
        if signal_number:
            raise PermissionError(1, "Operation not permitted")
        if group_state == "gone" or (group_state == "gone_after_reap" and len(signals) == 4):
            raise ProcessLookupError(3, "No such process")

    monkeypatch.setattr(process_module.os, "killpg", killpg)
    exited_leader = SimpleNamespace(poll=lambda: -9)

    if group_state != "live":
        process_module._terminate_process_group(exited_leader, 12345)
    else:
        with pytest.raises(PermissionError):
            process_module._terminate_process_group(exited_leader, 12345)

    if group_state == "gone":
        assert signals == [9, 0]
    elif group_state == "gone_after_reap":
        assert signals == [9, 0, 9, 0]
    else:
        assert len(signals) >= 4
        assert signals[:4] == [9, 0, 9, 0]


@pytest.mark.parametrize(
    ("idempotent", "expected_status"),
    ((False, "uncertain"), (True, "partial")),
    ids=("non-idempotent", "idempotent"),
)
def test_worker_preserves_dispatch_evidence_when_executable_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, idempotent: bool, expected_status: str
) -> None:
    plan = _fake_action_plan(tmp_path, idempotent=idempotent)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "workspace"
    launched = 0

    def fail_remove() -> None:
        raise OSError("private executable cleanup path")

    def launch(*args, **kwargs):
        nonlocal launched
        launched += 1
        return BoundedProcessResult(b"observed result\n", b"", 0, False, False)

    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=fail_remove)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    _sandbox(worker).run_callback = launch

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert launched == 1
    assert result.status == expected_status
    assert result.exit_code == 1
    assert len(result.artifacts) == 2
    assert (workspace / result.artifacts[0]["path"]).read_bytes() == b"observed result\n"
    assert len(result.evidence_records) >= 3
    assert "private executable cleanup path" not in json.dumps(result.to_dict())
    if not idempotent:
        assert "automatic repeat disallowed" in result.status_details["reason"]


def _inert_action_plan(tmp_path: Path) -> ActionPlan:
    fake = _fake_action_plan(tmp_path)
    fake_data = fake.to_dict()
    return ActionPlan.create(
        plan_id=fake.plan_id,
        engagement_id=fake.engagement_id,
        scenario_id=fake.scenario_id,
        target=fake.target,
        specialist_id=fake.specialist_id,
        operations=[
            {
                "step_id": "step-inert",
                "tool": "inert",
                "tool_version": "0.7.0",
                "action": "print_status",
                "arguments": {"message": "portable result"},
                "timeout_seconds": 5,
            }
        ],
        limits=fake_data["limits"],
        credential_references=fake_data["credential_references"],
        platform_prerequisites=fake_data["platform_prerequisites"],
        batch=fake_data["batch"],
        created_at=fake.created_at,
    )


def test_worker_portable_inert_execution_uses_ephemeral_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _inert_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    monkeypatch.setattr(worker_module, "_supports_secure_evidence_dirs", lambda: False)

    recorded_lifecycles: list[dict] = []
    evidence_workspaces: list[Path] = []
    original_record = EvidenceRecorder.record_step_output

    def capture_lifecycle(self, **kwargs):
        captured = original_record(self, **kwargs)
        recorded_lifecycles.append(self.evidence_records[-1]["payload"]["lifecycle"]["redacted"])
        evidence_workspaces.append(self.workspace_dir)
        return captured

    monkeypatch.setattr(EvidenceRecorder, "record_step_output", capture_lifecycle)
    result = worker.execute_plan(plan, authorization=authorization_id)

    assert result.status == "partial"
    assert result.cleanup_status == "failed"
    assert len(result.artifacts) == 2
    assert len(result.evidence_records) >= 3
    assert recorded_lifecycles[0]["storage"] == "worker_ephemeral_workspace"
    assert recorded_lifecycles[0]["retention_controller"] == "workspace_owner"
    assert recorded_lifecycles[0]["automatic_deletion"] is False
    assert evidence_workspaces and not evidence_workspaces[0].exists()
    assert worker.last_cleanup_receipt is not None
    workspace_unknown = next(
        effect
        for effect in worker.last_cleanup_receipt.unresolved_effects
        if effect["target"] == str(evidence_workspaces[0])
    )
    quarantined_workspace = Path(workspace_unknown["quarantine_target"])
    assert quarantined_workspace.is_dir()
    assert any((quarantined_workspace / "artifacts").iterdir())


def test_worker_persists_provenance_bound_evidence_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "workspace"
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    _sandbox(worker).result = BoundedProcessResult(b"observed result\n", b"", 0, False, False)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert result.status == "success"
    assert len(result.artifacts) == 2
    envelope_artifact = next(artifact for artifact in result.artifacts if artifact["path"].endswith("_evidence.json"))
    envelope_path = workspace / envelope_artifact["path"]
    envelope_bytes = envelope_path.read_bytes()
    assert envelope_artifact["sha256"] == hashlib.sha256(envelope_bytes).hexdigest()
    assert envelope_artifact["sha256"] in result.evidence_records
    assert stat.S_IMODE(envelope_path.stat().st_mode) == 0o600
    provenance = json.loads(envelope_bytes)["payload"]["provenance"]
    assert provenance == {
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "authorization_id": authorization_id,
        "engagement_id": plan.engagement_id,
        "worker_identity": worker.config.worker_id,
        "target": plan.target,
        "step_id": "step-fake",
        "tool": "fake-tool",
        "tool_version": "1.0.0",
        "action": "run",
    }
    lifecycle = json.loads(envelope_bytes)["payload"]["lifecycle"]["redacted"]
    assert lifecycle["storage"] == "owner_only_workspace"
    assert lifecycle["automatic_deletion"] is False


def test_worker_resolves_credential_only_for_approved_operation_and_redacts_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    secret = "opaque-COPS-operation-secret-unique"
    plan = _fake_action_plan(tmp_path, credential_references=[reference])
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def __init__(self) -> None:
            self.lookups: list[str] = []

        def resolve(self, requested_reference: str, *, deadline: float | None = None) -> str:
            assert deadline is not None
            self.lookups.append(requested_reference)
            return secret

    provider = Provider()
    worker, authorization_id = _fake_worker(
        tmp_path,
        plan,
        credential_provider=provider,
        credential_grants=[grant],
    )
    workspace = tmp_path / "workspace"
    probe_environments: list[dict[str, str]] = []
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)

    def capture_probe(*args, **kwargs):
        probe_environments.append(dict(kwargs["env"]))
        assert provider.lookups == []
        return prepared

    monkeypatch.setattr(worker_module, "prepare_executable", capture_probe)
    _sandbox(worker).result = BoundedProcessResult(
        f"stdout {secret}\n".encode(),
        f"stderr {secret}\n".encode(),
        0,
        False,
        False,
    )
    operation_workspaces: list[Path] = []

    def write_sensitive_scratch(_command, **kwargs):
        operation_workspace = kwargs["cwd"]
        operation_workspaces.append(operation_workspace)
        assert operation_workspace != workspace
        assert workspace not in operation_workspace.parents
        (operation_workspace / "raw-secret.txt").write_text(secret)
        return _sandbox(worker).result

    _sandbox(worker).run_callback = write_sensitive_scratch

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert result.status == "uncertain"
    assert result.cleanup_status == "failed"
    assert provider.lookups == [reference]
    assert len(operation_workspaces) == 1
    assert not operation_workspaces[0].exists()
    assert not (workspace / "raw-secret.txt").exists()
    assert worker.last_cleanup_receipt is not None
    scratch_unknown = next(
        effect
        for effect in worker.last_cleanup_receipt.unresolved_effects
        if effect["target"] == str(operation_workspaces[0])
    )
    quarantined_scratch = Path(scratch_unknown["quarantine_target"])
    assert quarantined_scratch.is_dir()
    assert (quarantined_scratch / "raw-secret.txt").read_text(encoding="utf-8") == secret
    assert probe_environments
    assert all(secret not in json.dumps(env) for env in probe_environments)
    assert len(_sandbox(worker).run_calls) == 1
    launch = _sandbox(worker).run_calls[0]
    assert secret not in json.dumps(launch["env"])
    assert launch["operation_env"] == {"COPS_CREDENTIAL_SERVICE_TOKEN": secret}
    assert secret not in json.dumps(result.to_dict())
    assert len(result.artifacts) == 2
    for artifact in result.artifacts:
        persisted = (workspace / artifact["path"]).read_bytes()
        assert secret.encode() not in persisted
        assert artifact["sha256"] == hashlib.sha256(persisted).hexdigest()
    output_artifact = next(artifact for artifact in result.artifacts if artifact["path"].endswith("_output.txt"))
    assert b"[REDACTED:SECRET]" in (workspace / output_artifact["path"]).read_bytes()


def test_credential_free_steps_share_workspace_around_credential_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    secret = "private-operation-value"
    plan = _fake_action_plan(
        tmp_path,
        credential_references=[reference],
        step_ids=("step-before", "step-secret", "step-after"),
    )
    operation = plan.operations[1]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=1,
        operation_digest=digest(plan.approved_snapshot()["operations"][1]),
    )

    class Provider:
        def resolve(self, requested_reference: str) -> str:
            assert requested_reference == reference
            return secret

    worker, authorization_id = _fake_worker(tmp_path, plan, credential_provider=Provider(), credential_grants=[grant])
    workspace = tmp_path / "workspace"
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    prepare_calls: list[dict[str, object]] = []

    def capture_prepare_executable(*args, **kwargs):
        prepare_calls.append(dict(kwargs))
        return prepared

    monkeypatch.setattr(worker_module, "prepare_executable", capture_prepare_executable)
    credential_workspace: list[Path] = []
    scratch_fds: set[int] = set()
    closed_scratch_fds: set[int] = set()
    create_directory = worker_module.create_directory_exclusive_no_symlinks
    close_fd = os.close

    def track_directory(path: Path) -> int:
        fd = create_directory(path)
        if path.name.startswith("cops-credential-operation-"):
            scratch_fds.add(fd)
        return fd

    def track_close(fd: int) -> None:
        if fd in scratch_fds:
            closed_scratch_fds.add(fd)
        close_fd(fd)

    monkeypatch.setattr(worker_module, "create_directory_exclusive_no_symlinks", track_directory)
    monkeypatch.setattr(os, "close", track_close)

    def observe_step(_command, **kwargs):
        call_number = len(_sandbox(worker).run_calls)
        if call_number == 1:
            assert kwargs["cwd"] == workspace
            assert kwargs.get("operation_env") is None
            (workspace / "shared-state.txt").write_text("from first step")
        elif call_number == 2:
            assert kwargs["cwd"] != workspace
            assert kwargs["operation_env"] == {"COPS_CREDENTIAL_SERVICE_TOKEN": secret}
            credential_workspace.append(kwargs["cwd"])
        else:
            assert call_number == 3
            assert scratch_fds == closed_scratch_fds
            assert kwargs["cwd"] == workspace
            assert (workspace / "shared-state.txt").read_text() == "from first step"
            assert kwargs.get("operation_env") is None
        return _sandbox(worker).result

    _sandbox(worker).run_callback = observe_step
    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert result.status == "success"
    assert len(_sandbox(worker).run_calls) == 3
    assert len(credential_workspace) == 1
    assert scratch_fds == closed_scratch_fds
    assert not credential_workspace[0].exists()
    assert len(prepare_calls) == 3
    assert all(call["cleanup_manager"] is not None for call in prepare_calls)
    assert prepare_calls[0]["credential_scratch_root"] is None
    assert prepare_calls[1]["credential_scratch_root"] == credential_workspace[0]
    assert prepare_calls[2]["credential_scratch_root"] is None


def test_worker_cleans_tracked_staged_file_without_claiming_preexisting_caller_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "workspace"
    staging_dir = workspace / ".executables"
    staging_dir.mkdir(mode=0o700)
    marker = staging_dir / "caller-owned.txt"
    marker.write_text("retain", encoding="utf-8")
    worker.adapter_registry.register_adapter(
        replace(
            _python_adapter(),
            tool="fake-tool",
            version="1.0.0",
            supported_environments=["linux", "darwin"],
        )
    )
    monkeypatch.setattr(executable_module, "verify_executable_launch_support", lambda: None)

    def run_staged_executable(command, **_kwargs):
        if tuple(command)[1:] == ("--version",):
            return BoundedProcessResult(
                stdout=f"Python {platform.python_version()}\n".encode(),
                stderr=b"",
                returncode=0,
                timed_out=False,
                output_limit_exceeded=False,
            )
        return _sandbox(worker).result

    _sandbox(worker).run_callback = run_staged_executable
    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert result.status == "success"
    assert staging_dir.is_dir()
    assert marker.read_text(encoding="utf-8") == "retain"
    assert list(staging_dir.iterdir()) == [marker]

    events = _cleanup_events(worker)
    recorded = [event for event in events if event[0] == "effect_recorded"]
    staged_files = [
        event
        for event in recorded
        if event[2]["metadata"].get("purpose") == "staged_adapter_executable" and event[2]["resource_type"] == "file"
    ]
    assert len(staged_files) == 1
    staged_effect_id = staged_files[0][1]
    assert Path(str(staged_files[0][2]["target"])).parent == staging_dir
    assert not any(
        event[2]["metadata"].get("purpose") == "staged_adapter_executable" and event[2]["resource_type"] == "directory"
        for event in recorded
    )
    assert any(
        event_type == "creation_identity_recorded" and effect_id == staged_effect_id
        for event_type, effect_id, _payload in events
    )
    assert any(
        event_type == "cleanup_transition" and effect_id == staged_effect_id and payload["status"] == "cleaned"
        for event_type, effect_id, payload in events
    )


def test_worker_tracks_and_cleans_credential_scratch_executable_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    plan = _fake_action_plan(tmp_path, credential_references=[reference])
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def resolve(self, requested_reference: str) -> str:
            assert requested_reference == reference
            return "private-operation-value"

    worker, authorization_id = _fake_worker(
        tmp_path,
        plan,
        credential_provider=Provider(),
        credential_grants=[grant],
    )
    worker.adapter_registry.register_adapter(
        replace(
            _python_adapter(),
            tool="fake-tool",
            version="1.0.0",
            supported_environments=["linux", "darwin"],
        )
    )
    monkeypatch.setattr(executable_module, "verify_executable_launch_support", lambda: None)
    operation_workspaces: list[Path] = []

    def run_staged_executable(command, **kwargs):
        if tuple(command)[1:] == ("--version",):
            return BoundedProcessResult(
                stdout=f"Python {platform.python_version()}\n".encode(),
                stderr=b"",
                returncode=0,
                timed_out=False,
                output_limit_exceeded=False,
            )
        operation_workspaces.append(Path(kwargs["cwd"]))
        return _sandbox(worker).result

    _sandbox(worker).run_callback = run_staged_executable
    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "success"
    assert len(operation_workspaces) == 1
    scratch = operation_workspaces[0]
    assert not scratch.exists()

    events = _cleanup_events(worker)
    recorded = [event for event in events if event[0] == "effect_recorded"]
    credential_effects = [
        event
        for event in recorded
        if event[2]["metadata"].get("purpose") in {"credential_operation_scratch", "staged_adapter_executable"}
    ]
    assert {(event[2]["metadata"]["purpose"], event[2]["resource_type"]) for event in credential_effects} == {
        ("credential_operation_scratch", "directory"),
        ("staged_adapter_executable", "directory"),
        ("staged_adapter_executable", "file"),
    }
    staged_effects = [
        event for event in credential_effects if event[2]["metadata"]["purpose"] == "staged_adapter_executable"
    ]
    assert all(Path(str(event[2]["target"])).is_relative_to(scratch) for event in staged_effects)
    assert all(event[2]["metadata"]["credential_scratch_root"] == str(scratch) for event in staged_effects)
    tracked_effect_ids = {event[1] for event in credential_effects}
    assert {
        effect_id
        for event_type, effect_id, _payload in events
        if event_type == "creation_identity_recorded" and effect_id in tracked_effect_ids
    } == tracked_effect_ids
    assert {
        effect_id
        for event_type, effect_id, payload in events
        if event_type == "cleanup_transition" and payload["status"] == "cleaned" and effect_id in tracked_effect_ids
    } == tracked_effect_ids


def test_credential_scratch_deletion_failure_marks_run_cleanup_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    plan = _fake_action_plan(tmp_path, credential_references=[reference], idempotent=True)
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def resolve(self, requested_reference: str) -> str:
            assert requested_reference == reference
            return "private-operation-value"

    worker, authorization_id = _fake_worker(tmp_path, plan, credential_provider=Provider(), credential_grants=[grant])
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    scratch: list[Path] = []

    def observe_step(_command, **kwargs):
        scratch.append(kwargs["cwd"])
        return _sandbox(worker).result

    _sandbox(worker).run_callback = observe_step
    original_rmdir = os.rmdir

    def fail_scratch_deletion(path, *args, **kwargs):
        if scratch and Path(path) == Path("resource") and kwargs.get("dir_fd") is not None:
            raise OSError("simulated scratch deletion failure")
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(cleanup_module.os, "rmdir", fail_scratch_deletion)
    try:
        result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")
        assert result.status == "failed"
        assert result.cleanup_status == "failed"
        assert "credential operation scratch cleanup failed" in result.status_details["reason"]
    finally:
        monkeypatch.setattr(cleanup_module.os, "rmdir", original_rmdir)
        for directory in scratch:
            shutil.rmtree(directory, ignore_errors=True)


def test_credential_scratch_preserves_unresolved_plan_declared_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    scratch_nonce = hashlib.sha256(os.fsencode(tmp_path)).hexdigest()[:32]
    scratch_path = Path(worker_module.tempfile.gettempdir()).resolve(strict=True) / (
        f"cops-credential-operation-0-{scratch_nonce}"
    )
    cleanup_target = scratch_path / "plan-declared.txt"
    plan = _fake_action_plan(
        tmp_path,
        credential_references=[reference],
        idempotent=True,
        cleanup_target=cleanup_target,
    )
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def resolve(self, requested_reference: str) -> str:
            assert requested_reference == reference
            return "private-operation-value"

    worker, authorization_id = _fake_worker(
        tmp_path,
        plan,
        credential_provider=Provider(),
        credential_grants=[grant],
    )
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    monkeypatch.setattr(
        worker_module,
        "uuid",
        SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=scratch_nonce)),
    )

    def create_plan_declared_descendant(_command, **kwargs):
        assert kwargs["cwd"] == scratch_path
        cleanup_target.write_text("preserve me", encoding="utf-8")
        return _sandbox(worker).result

    _sandbox(worker).run_callback = create_plan_declared_descendant
    try:
        result = worker.execute_plan(
            plan,
            authorization=authorization_id,
            workspace_dir=tmp_path / "workspace",
        )

        assert result.status == "failed"
        assert result.cleanup_status == "failed"
        assert "credential operation scratch cleanup failed" in result.status_details["reason"]
        assert scratch_path.is_dir()
        assert cleanup_target.read_text(encoding="utf-8") == "preserve me"

        assert worker.last_cleanup_receipt is not None
        unresolved_targets = {item["target"] for item in worker.last_cleanup_receipt.unresolved_effects}
        assert str(cleanup_target) in unresolved_targets
        assert str(scratch_path) in unresolved_targets

        with sqlite3.connect(worker.cleanup_journal.path) as connection:
            durable_row = connection.execute(
                "SELECT payload_json FROM cleanup_events "
                "WHERE event_type = 'cleanup_receipt' ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        assert durable_row is not None
        durable_receipt = json.loads(durable_row[0])
        assert {str(cleanup_target), str(scratch_path)} <= {
            item["target"] for item in durable_receipt["unresolved_effects"]
        }
    finally:
        shutil.rmtree(scratch_path, ignore_errors=True)


def test_credential_scratch_cleanup_transition_failure_preserves_uncertain_audit_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    plan = _fake_action_plan(tmp_path, credential_references=[reference], idempotent=False)
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="test-worker-01",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def resolve(self, requested_reference: str) -> str:
            assert requested_reference == reference
            return "private-operation-value"

    journal_root = tmp_path.resolve() / "cleanup-journal"
    journal_root.mkdir(mode=0o700)
    journal_path = journal_root / "cleanup.sqlite3"
    worker, authorization_id = _fake_worker(
        tmp_path,
        plan,
        credential_provider=Provider(),
        credential_grants=[grant],
        cleanup_journal_path=journal_path,
    )
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    scratch: list[Path] = []

    def observe_step(_command, **kwargs):
        scratch.append(kwargs["cwd"])
        return _sandbox(worker).result

    _sandbox(worker).run_callback = observe_step
    assert worker.cleanup_journal is not None
    original_transition = worker.cleanup_journal.transition

    def fail_scratch_cleaned_transition(run_id, effect, status, *, details=None):
        if effect.metadata.get("purpose") == "credential_operation_scratch" and status == "cleaned":
            raise CleanupPersistenceError("injected scratch transition failure")
        return original_transition(run_id, effect, status, details=details)

    monkeypatch.setattr(worker.cleanup_journal, "transition", fail_scratch_cleaned_transition)
    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "uncertain"
    assert result.cleanup_status == "failed"
    assert "credential operation scratch cleanup audit persistence failed" in result.status_details["reason"]
    assert "automatic repeat disallowed" in result.status_details["reason"]
    assert len(scratch) == 1
    assert not scratch[0].exists()

    recovered = CleanupJournal(journal_path).recoverable_runs("test-worker-01")
    assert len(recovered) == 1
    scratch_effect = next(
        effect for effect in recovered[0].effects if effect.metadata.get("purpose") == "credential_operation_scratch"
    )
    assert scratch_effect.status == "unknown"
    assert scratch_effect.creation_identity is not None

    recovered_run = recovered[0]
    recovery_journal = CleanupJournal(journal_path)
    recovered_ledger = SideEffectLedger(
        recovered_run.plan_id,
        recovered_run.engagement_id,
        recovered_run.worker_identity,
        journal=recovery_journal,
        run_id=recovered_run.run_id,
        workspace_dir=recovered_run.workspace_dir,
        recovered_effects=recovered_run.effects,
        start_run=False,
    )
    recovery_receipt = CleanupManager(
        recovered_ledger,
        worker_identity=recovered_run.worker_identity,
        workspace_dir=recovered_run.workspace_dir,
    ).rollback(recovered=True)
    recovered_scratch = next(
        item for item in recovery_receipt.unresolved_effects if item["effect_id"] == scratch_effect.effect_id
    )
    assert recovery_receipt.status == "failed"
    assert "unknown" in recovered_scratch["reason"].lower()

    with sqlite3.connect(journal_path) as connection:
        durable_row = connection.execute(
            "SELECT payload_json FROM cleanup_events "
            "WHERE event_type = 'cleanup_receipt' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
    assert durable_row is not None
    durable_receipt = json.loads(durable_row[0])
    assert any(item["effect_id"] == scratch_effect.effect_id for item in durable_receipt["unresolved_effects"])


def test_worker_rejects_credential_plan_without_resolver_before_approval_consumption(
    tmp_path: Path,
) -> None:
    plan = _fake_action_plan(tmp_path, credential_references=["corp_service_account_token_ref"])
    worker, authorization_id = _fake_worker(tmp_path, plan)

    with pytest.raises(WorkerIsolationError, match="scoped credential resolver"):
        worker.execute_plan(plan, authorization=authorization_id)

    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"
    assert _sandbox(worker).run_calls == []


def test_worker_rejects_mismatched_credential_grant_before_provider_lookup_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = "corp_service_account_token_ref"
    plan = _fake_action_plan(tmp_path, credential_references=[reference])
    operation = plan.operations[0]
    grant = CredentialGrant(
        reference=reference,
        environment_variable="COPS_CREDENTIAL_SERVICE_TOKEN",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity="a-different-worker",
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
        operation_index=0,
        operation_digest=digest(plan.approved_snapshot()["operations"][0]),
    )

    class Provider:
        def __init__(self) -> None:
            self.lookups: list[str] = []

        def resolve(self, requested_reference: str) -> str:
            self.lookups.append(requested_reference)
            return "should-never-be-resolved"

    provider = Provider()
    worker, authorization_id = _fake_worker(
        tmp_path,
        plan,
        credential_provider=provider,
        credential_grants=[grant],
    )
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)

    result = worker.execute_plan(plan, authorization=authorization_id)

    assert result.status == "failed"
    assert provider.lookups == []
    assert _sandbox(worker).run_calls == []
    assert "should-never-be-resolved" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("inert", (False, True), ids=("external-adapter", "caller-workspace"))
def test_worker_rejects_unsafe_nonposix_execution_before_consuming_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inert: bool
) -> None:
    plan = _inert_action_plan(tmp_path) if inert else _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    monkeypatch.setattr(worker_module, "_supports_secure_evidence_dirs", lambda: False)

    with pytest.raises(WorkerIsolationError, match="secure directory descriptors|ephemeral workspace"):
        worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"


def test_worker_reuses_workspace_with_unique_reserved_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir(mode=0o700)
    second_root.mkdir(mode=0o700)
    first_plan = _fake_action_plan(first_root)
    second_plan = _fake_action_plan(second_root)
    first_worker, first_authorization = _fake_worker(first_root, first_plan)
    second_worker, second_authorization = _fake_worker(second_root, second_plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    process_results = iter(
        (
            BoundedProcessResult(b"first\n", b"", 0, False, False),
            BoundedProcessResult(b"second\n", b"", 0, False, False),
        )
    )
    launch_count = 0

    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)

    def launch(*args, **kwargs):
        nonlocal launch_count
        launch_count += 1
        return next(process_results)

    _sandbox(first_worker).run_callback = launch
    _sandbox(second_worker).run_callback = launch

    first = first_worker.execute_plan(first_plan, authorization=first_authorization, workspace_dir=workspace)
    first_path = workspace / first.artifacts[0]["path"]
    first_bytes = first_path.read_bytes()
    second = second_worker.execute_plan(second_plan, authorization=second_authorization, workspace_dir=workspace)
    second_path = workspace / second.artifacts[0]["path"]

    assert first.status == second.status == "success"
    assert launch_count == 2
    assert first_path != second_path
    assert first_path.read_bytes() == first_bytes == b"first\n"
    assert second_path.read_bytes() == b"second\n"


def test_worker_fails_before_launch_when_evidence_reservation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)

    def fail_reservation(*args, **kwargs):
        raise EvidenceCaptureError("cannot reserve /private/host/path")

    def unexpected(*args, **kwargs):
        raise AssertionError("failed evidence reservation must prevent executable work")

    monkeypatch.setattr(EvidenceRecorder, "reserve_step_output", fail_reservation)
    monkeypatch.setattr(worker_module, "prepare_executable", unexpected)
    _sandbox(worker).run_callback = unexpected

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.status_details["reason"] == "adapter execution failed at step 'step-fake'"
    assert "/private/host/path" not in json.dumps(result.to_dict())


def test_worker_reports_post_redaction_artifact_truncation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _fake_action_plan(tmp_path, max_output_bytes=3)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)

    class ExpandingRedactor:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def clear_secrets(self) -> None:
            pass

        def redact_bytes(self, value: bytes) -> bytes:
            return b"expanded-output" if value else b""

        def redact_string(self, value: str) -> str:
            return value

    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    _sandbox(worker).result = BoundedProcessResult(b"x", b"", 0, False, False)
    monkeypatch.setattr("cops.execution.redaction.StreamRedactor", ExpandingRedactor)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert result.status == "partial"
    assert result.exit_code == 125
    assert "post-redaction evidence" in result.status_details["reason"]
    assert result.artifacts[0]["size_bytes"] == 3
    assert result.artifacts[0]["truncated_bytes"] == len(b"expanded-output") - 3
    assert (tmp_path / "workspace" / result.artifacts[0]["path"]).read_bytes() == b"exp"


def test_worker_counts_executable_preparation_against_step_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path, timeout_seconds=1)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    monotonic_values = iter((100.0, 102.0))
    monkeypatch.setattr(worker_module, "monotonic", lambda: next(monotonic_values))

    def unexpected_launch(*args, **kwargs):
        raise AssertionError("operation must not launch after preparation consumes its deadline")

    _sandbox(worker).run_callback = unexpected_launch

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "partial"
    assert result.exit_code == 124


def test_worker_normalizes_executable_preparation_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _fake_action_plan(tmp_path, timeout_seconds=1)
    worker, authorization_id = _fake_worker(tmp_path, plan)

    def expired_preparation(*args, **kwargs):
        raise ExecutablePreparationTimeoutError("adapter executable preparation exceeded the step timeout")

    monkeypatch.setattr(worker_module, "prepare_executable", expired_preparation)

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "partial"
    assert result.exit_code == 124
    assert "timed out during adapter executable preparation" in result.status_details["reason"]


def test_bounded_collector_closes_pipe_held_by_descendant(tmp_path: Path) -> None:
    program = "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])"
    started = time.monotonic()

    result = run_bounded_process(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=os.environ,
        timeout_seconds=0.2,
        max_output_bytes=4096,
    )

    assert result.timed_out
    assert time.monotonic() - started < 2


def test_echo_adapter_compares_probe_to_provenance_revision() -> None:
    adapter = ToolAdapterRegistry().get_adapter("echo")
    contract = adapter.executable_verification
    assert contract is not None
    match = __import__("re").search(contract.version_pattern, "echo (GNU coreutils) 9.4")

    assert match is not None
    assert adapter.version == "coreutils-9.4"
    assert match.group("version") == adapter.provenance["pinned_revision"] == "9.4"


def test_nmap_adapter_rejects_development_version_suffix() -> None:
    adapter = ToolAdapterRegistry().get_adapter("nmap")
    contract = adapter.executable_verification
    assert contract is not None
    import re

    match = re.search(contract.version_pattern, "Nmap version 7.94 ( https://nmap.org )")
    assert match is not None
    assert match.group("version") == "7.94"
    assert re.search(contract.version_pattern, "Nmap version 7.94SVN ( https://nmap.org )") is None


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_version_mismatch(tmp_path: Path) -> None:
    adapter = _python_adapter(pinned_revision="0.0.0")

    with pytest.raises(ExecutableVerificationError, match="version mismatch"):
        prepare_executable(
            adapter,
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            process_runner=run_bounded_process,
        )


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_expired_shared_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executable_module, "monotonic", lambda: 2.0)

    def unexpected_probe(*args, **kwargs):
        raise AssertionError("version probe must not run after staging consumes the deadline")

    with pytest.raises(ExecutableVerificationError, match="exceeded the step timeout"):
        prepare_executable(
            _python_adapter(),
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            deadline=1.0,
            process_runner=unexpected_probe,
        )


def test_executable_copy_enforces_shared_deadline_while_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"verified executable bytes")
    source_fd = os.open(source, os.O_RDONLY)
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    clock = iter((0.0, 2.0))
    monkeypatch.setattr(executable_module, "monotonic", lambda: next(clock, 2.0))

    try:
        with pytest.raises(
            ExecutablePreparationTimeoutError,
            match="preparation exceeded the step timeout",
        ):
            executable_module._copy_from_open_descriptor(
                source_fd,
                destination_fd,
                4096,
                deadline=1.0,
            )
    finally:
        os.close(source_fd)
        os.close(destination_fd)


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_removes_partial_stage_after_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt_copy(source_fd, destination_fd, max_size_bytes, *, deadline=None):
        os.write(destination_fd, b"partial executable")
        raise KeyboardInterrupt

    monkeypatch.setattr(executable_module, "_copy_from_open_descriptor", interrupt_copy)

    with pytest.raises(KeyboardInterrupt):
        prepare_executable(
            _python_adapter(),
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            process_runner=run_bounded_process,
        )

    assert list((tmp_path / ".executables").iterdir()) == []


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepared_executable_is_bound_to_verified_inode_after_path_swap(tmp_path: Path) -> None:
    prepared = prepare_executable(
        _python_adapter(),
        workspace=tmp_path,
        env=os.environ,
        timeout_seconds=5,
        process_runner=run_bounded_process,
    )
    replacement = prepared.path.with_name("replacement")
    try:
        shutil.copy2("/bin/false", replacement)
        replacement.chmod(0o500)
        os.replace(replacement, prepared.path)

        result = run_bounded_process(
            [prepared.invocation_path, "-c", "print('verified inode')"],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            max_output_bytes=4096,
            pass_fds=prepared.pass_fds,
        )

        assert result.returncode == 0
        assert result.stdout == b"verified inode\n"
    finally:
        with pytest.raises(ExecutableVerificationError, match="staged executable name changed"):
            prepared.remove()
        prepared.path.unlink(missing_ok=True)
        replacement.unlink(missing_ok=True)


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepared_executable_cleanup_uses_held_staging_directory_after_replacement(tmp_path: Path) -> None:
    prepared = prepare_executable(
        _python_adapter(),
        workspace=tmp_path,
        env=os.environ,
        timeout_seconds=5,
        process_runner=run_bounded_process,
    )
    original_stage = tmp_path / ".executables"
    moved_stage = tmp_path / ".executables-moved"
    original_stage.rename(moved_stage)
    original_stage.mkdir(mode=0o700)
    marker = original_stage / prepared.filename
    marker.write_bytes(b"replacement must remain intact")

    with pytest.raises(ExecutableVerificationError, match="staging directory identity changed"):
        prepared.remove()

    assert not (moved_stage / prepared.filename).exists()
    assert marker.read_bytes() == b"replacement must remain intact"


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_symlink_source(tmp_path: Path) -> None:
    adapter = _python_adapter()
    link = tmp_path / "fake-python"
    link.symlink_to(sys.executable)
    adapter.binary = str(link)

    with pytest.raises(ExecutableVerificationError, match="without following symbolic links") as caught:
        prepare_executable(
            adapter,
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            process_runner=run_bounded_process,
        )

    assert str(link) not in str(caught.value)


@pytest.mark.skipif(HAS_PROC_FD, reason="only exercises the unsupported-platform boundary")
def test_prepare_executable_fails_closed_without_linux_proc(tmp_path: Path) -> None:
    with pytest.raises(ExecutableVerificationError, match="requires Linux /proc/self/fd"):
        prepare_executable(
            _python_adapter(),
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            process_runner=run_bounded_process,
        )


def test_evidence_rejects_symlinked_artifact_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "artifacts").symlink_to(outside, target_is_directory=True)
    recorder = EvidenceRecorder(tmp_path, context=_evidence_context())

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact reservation failed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            tool_version="1.0.0",
            action="run",
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
        )

    assert list(outside.iterdir()) == []


def test_evidence_rejects_replaced_workspace_before_artifact_creation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    expected_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    try:
        workspace.rename(tmp_path / "original-workspace")
        workspace.mkdir(mode=0o700)
        recorder = EvidenceRecorder(
            workspace,
            context=_evidence_context(),
            expected_workspace_fd=expected_fd,
        )

        with pytest.raises(EvidenceCaptureError, match="workspace changed after preflight"):
            recorder.reserve_step_output("step-1")

        assert list(workspace.iterdir()) == []
    finally:
        os.close(expected_fd)


def test_evidence_retries_name_claimed_between_check_and_exclusive_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    ledger = SideEffectLedger("plan", "engagement", "worker", workspace_dir=workspace)
    manager = CleanupManager(ledger, "worker", workspace)
    recorder = EvidenceRecorder(workspace, context=_evidence_context(), cleanup_manager=manager)
    original_open = os.open
    raced = False

    def claim_first_name(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if path == "step-1_output.txt" and flags & os.O_EXCL and not raced:
            raced = True
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            try:
                os.write(fd, b"racer-owned evidence")
            finally:
                os.close(fd)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(evidence_module.os, "open", claim_first_name)
    reservation = recorder.reserve_step_output("step-1")

    assert raced
    assert reservation.name != "step-1_output.txt"
    assert (workspace / "artifacts" / "step-1_output.txt").read_bytes() == b"racer-owned evidence"
    collision = next(effect for effect in ledger.get_effects() if effect.target.endswith("/step-1_output.txt"))
    assert collision.status == "cleaned"
    assert collision.creation_identity is None
    recorder.discard_pending_reservations()


def test_evidence_rejects_artifact_directory_replacement_after_reservation(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path, context=_evidence_context())
    reservation = recorder.reserve_step_output("step-1")
    original_artifacts = tmp_path / "artifacts"
    moved_artifacts = tmp_path / "artifacts-moved"
    original_artifacts.rename(moved_artifacts)
    original_artifacts.mkdir(mode=0o700)
    marker = original_artifacts / reservation.name
    marker.write_bytes(b"replacement must remain intact")

    with pytest.raises(EvidenceCaptureError, match="artifact directory identity changed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            tool_version="1.0.0",
            action="run",
            exit_code=0,
            stdout=b"new evidence",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
            reservation=reservation,
        )

    assert not (moved_artifacts / reservation.name).exists()
    assert marker.read_bytes() == b"replacement must remain intact"


def test_evidence_rejects_symlinked_workspace_parent_before_creation(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "workspace-link"
    link.symlink_to(outside, target_is_directory=True)
    recorder = EvidenceRecorder(link / "new-workspace", context=_evidence_context())

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact reservation failed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            tool_version="1.0.0",
            action="run",
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
        )

    assert not (outside / "new-workspace").exists()


def test_worker_rejects_symlinked_workspace_parent_before_creation(tmp_path: Path) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "workspace-link"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(WorkerIsolationError, match="symbolic-link components"):
        worker.execute_plan(
            plan,
            authorization=authorization_id,
            workspace_dir=link / "new-workspace",
        )

    assert not (outside / "new-workspace").exists()
    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"
    assert _cleanup_run_count(worker) == 0
    assert _cleanup_events(worker) == []


def test_worker_rejects_missing_caller_workspace_before_creation(tmp_path: Path) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "missing-caller-workspace"

    with pytest.raises(WorkerIsolationError, match="must already exist"):
        worker.execute_plan(
            plan,
            authorization=authorization_id,
            workspace_dir=workspace,
        )

    assert not workspace.exists()
    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"
    assert _cleanup_run_count(worker) == 0
    assert _cleanup_events(worker) == []

    workspace.mkdir(mode=0o700)
    worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=workspace,
    )

    assert _approval_control(worker).store.get_authorization(authorization_id).status == "consumed"
    assert _cleanup_run_count(worker) == 1


def test_worker_rejects_caller_workspace_replacement_before_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "workspace"
    original_workspace = tmp_path / "original-workspace"
    open_workspace = worker_module._open_caller_workspace
    open_count = 0

    def replace_before_reopen(path: Path) -> int:
        nonlocal open_count
        open_count += 1
        if open_count == 2:
            workspace.rename(original_workspace)
            workspace.mkdir(mode=0o700)
        return open_workspace(path)

    monkeypatch.setattr(worker_module, "_open_caller_workspace", replace_before_reopen)

    with pytest.raises(WorkerIsolationError, match="changed after preflight"):
        worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert original_workspace.is_dir()
    assert list(workspace.iterdir()) == []
    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"
    assert _sandbox(worker).run_calls == []


def test_worker_rejects_caller_workspace_replacement_after_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    workspace = tmp_path / "workspace"
    original_workspace = tmp_path / "original-workspace"
    approval = _approval_control(worker)
    consume = approval.consume_authorization

    def replace_after_consume(*args: object, **kwargs: object) -> object:
        receipt = consume(*args, **kwargs)
        workspace.rename(original_workspace)
        workspace.mkdir(mode=0o700)
        return receipt

    monkeypatch.setattr(approval, "consume_authorization", replace_after_consume)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=workspace)

    assert result.status == "failed"
    assert original_workspace.is_dir()
    assert list(workspace.iterdir()) == []
    assert approval.store.get_authorization(authorization_id).status == "consumed"
    assert _sandbox(worker).run_calls == []


def test_worker_rejects_workspace_parent_traversal_before_creation(tmp_path: Path) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "workspace-link"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(WorkerIsolationError, match="symbolic-link components"):
        worker.execute_plan(
            plan,
            authorization=authorization_id,
            workspace_dir=link / ".." / "escaped",
        )

    assert not (tmp_path / "escaped").exists()
    assert not (outside / "escaped").exists()
    assert _approval_control(worker).store.get_authorization(authorization_id).status == "approved"


@pytest.mark.parametrize("invalid_execution", ([], {"sha256": 42}, {"sha256": ["0" * 64]}))
def test_registry_rejects_malformed_execution_metadata(tmp_path: Path, invalid_execution: object) -> None:
    definitions = tmp_path / "definitions"
    definitions.mkdir()
    source = Path(__file__).resolve().parents[1] / "cops/adapters/definitions/echo.json"
    definition = json.loads(source.read_text(encoding="utf-8"))
    definition["execution"] = invalid_execution
    (definitions / "invalid.json").write_text(json.dumps(definition), encoding="utf-8")

    with pytest.raises(AdapterError):
        ToolAdapterRegistry(definitions_path=definitions)


class _RemovingRedactor:
    def redact_bytes(self, value: bytes) -> bytes:
        return value.replace(b"secret", b"")

    def redact_string(self, value: str) -> str:
        return value.replace("secret", "")


def test_evidence_reports_redaction_before_truncation(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(
        tmp_path,
        redactor=_RemovingRedactor(),  # type: ignore[arg-type]
        context=_evidence_context(),
    )
    _, artifact = recorder.record_step_output(
        step_id="step-1",
        tool="fake",
        tool_version="1.0.0",
        action="run",
        exit_code=0,
        stdout=b"secret0123456789",
        stderr=b"",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        max_output_bytes=3,
    )

    telemetry = recorder.step_telemetry[-1]
    assert telemetry.redacted_characters == 6
    assert telemetry.truncated_bytes == 7
    assert telemetry.output_length == 3
    assert artifact.size_bytes == 3
    assert artifact.truncated_bytes == 7


def test_evidence_rejects_reserved_artifact_replacement(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path, context=_evidence_context())
    reservation = recorder.reserve_step_output("step-1")
    artifact_path = tmp_path / reservation.path
    artifact_path.unlink()
    artifact_path.write_bytes(b"replacement must remain intact")
    artifact_path.chmod(0o600)
    replacement = artifact_path.stat()
    assert (replacement.st_dev, replacement.st_ino) != (reservation.device, reservation.inode)

    with pytest.raises(EvidenceCleanupError, match="residual artifact may remain"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            tool_version="1.0.0",
            action="run",
            exit_code=0,
            stdout=b"new evidence",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
            reservation=reservation,
        )

    assert artifact_path.read_bytes() == b"replacement must remain intact"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO replacement requires POSIX")
def test_evidence_rejects_fifo_replacement_without_blocking(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path, context=_evidence_context())
    reservation = recorder.reserve_step_output("step-1")
    artifact_path = tmp_path / reservation.path
    artifact_path.unlink()
    os.mkfifo(artifact_path, 0o600)

    with pytest.raises(EvidenceCleanupError, match="residual artifact may remain"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            tool_version="1.0.0",
            action="run",
            exit_code=0,
            stdout=b"new evidence",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
            reservation=reservation,
        )

    assert stat.S_ISFIFO(artifact_path.stat().st_mode)
