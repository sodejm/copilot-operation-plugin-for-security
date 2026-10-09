"""Adversarial coverage for verified adapter executable launches."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

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
from cops.execution import ApprovalStore, IsolatedWorker, WorkerIsolationError
from cops.execution.evidence import EvidenceCaptureError, EvidenceRecorder
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
) -> ActionPlan:
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json").read_text(
            encoding="utf-8"
        )
    )
    limits = dict(fixture["limits"])
    limits["max_output_bytes"] = max_output_bytes
    limits["max_duration_seconds"] = 30
    return ActionPlan.create(
        plan_id=f"plan-fake-{tmp_path.name}",
        engagement_id=fixture["engagement_id"],
        scenario_id=fixture["scenario_id"],
        target=fixture["target"],
        specialist_id=fixture["specialist_id"],
        operations=[
            {
                "step_id": "step-fake",
                "tool": "fake-tool",
                "tool_version": "1.0.0",
                "action": "run",
                "arguments": {},
                "timeout_seconds": timeout_seconds,
                "idempotent": idempotent,
            }
        ],
        limits=limits,
        credential_references=[],
        created_at=fixture["created_at"],
    )


def _fake_worker(tmp_path: Path, plan: ActionPlan) -> tuple[IsolatedWorker, str]:
    auth, trust_store, engagement = authorize_test_plan(plan, worker_identity="test-worker-01", valid_hours=2)
    store = ApprovalStore(tmp_path / "approval.sqlite3")
    store.store_authorization(auth)
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    registry.register_adapter(_fake_adapter())
    approval_control = TestApprovalControl(store, trust_store, engagement)
    sandbox = TestExecutionSandbox()
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-01"),
        approval_control,
        sandbox,
        adapter_registry=registry,
    )
    _TEST_CONTROLS[id(worker)] = approval_control
    _TEST_SANDBOXES[id(worker)] = sandbox
    return worker, auth.authorization_id


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
    original_record = EvidenceRecorder.record_step_output

    def record_with_exit_code(self, **kwargs):
        recorded_exit_codes.append(kwargs["exit_code"])
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
    if expected_status == "uncertain":
        assert "automatic repeat disallowed" in result.status_details["reason"]


def test_worker_uses_sandbox_for_version_probe_and_owner_resource_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    worker.config = replace(worker.config, max_wall_time_seconds=1, max_output_bytes=100)
    prepared = SimpleNamespace(invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None)
    probe_runners = []

    def capture_probe_runner(*args, **kwargs):
        probe_runners.append(kwargs["process_runner"])
        return prepared

    monkeypatch.setattr(worker_module, "prepare_executable", capture_probe_runner)

    result = worker.execute_plan(plan, authorization=authorization_id, workspace_dir=tmp_path / "workspace")

    assert result.status == "success"
    assert probe_runners == [_sandbox(worker).run]
    assert len(_sandbox(worker).run_calls) == 1
    assert _sandbox(worker).run_calls[0]["max_output_bytes"] == 100
    assert 0 < _sandbox(worker).run_calls[0]["timeout_seconds"] <= 1


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
    assert len(result.artifacts) == 1
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

    result = worker.execute_plan(plan, authorization=authorization_id)

    assert result.status == "success"
    assert result.cleanup_status == "completed"
    assert len(result.artifacts) == 1
    assert len(result.evidence_records) >= 3


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
    first_plan = _fake_action_plan(tmp_path / "first")
    second_plan = _fake_action_plan(tmp_path / "second")
    first_worker, first_authorization = _fake_worker(tmp_path / "first", first_plan)
    second_worker, second_authorization = _fake_worker(tmp_path / "second", second_plan)
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
    recorder = EvidenceRecorder(tmp_path)

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact reservation failed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
            action="run",
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            max_output_bytes=100,
        )

    assert list(outside.iterdir()) == []


def test_evidence_rejects_artifact_directory_replacement_after_reservation(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path)
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
    recorder = EvidenceRecorder(link / "new-workspace")

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact reservation failed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
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


def test_evidence_reports_redaction_before_truncation(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path, redactor=_RemovingRedactor())  # type: ignore[arg-type]
    _, artifact = recorder.record_step_output(
        step_id="step-1",
        tool="fake",
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
    recorder = EvidenceRecorder(tmp_path)
    reservation = recorder.reserve_step_output("step-1")
    artifact_path = tmp_path / reservation.path
    artifact_path.unlink()
    artifact_path.write_bytes(b"replacement must remain intact")
    artifact_path.chmod(0o600)
    replacement = artifact_path.stat()
    assert (replacement.st_dev, replacement.st_ino) != (reservation.device, reservation.inode)

    with pytest.raises(EvidenceCaptureError, match="reservation identity changed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
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
    recorder = EvidenceRecorder(tmp_path)
    reservation = recorder.reserve_step_output("step-1")
    artifact_path = tmp_path / reservation.path
    artifact_path.unlink()
    os.mkfifo(artifact_path, 0o600)

    with pytest.raises(EvidenceCaptureError, match="reservation identity changed"):
        recorder.record_step_output(
            step_id="step-1",
            tool="fake",
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
