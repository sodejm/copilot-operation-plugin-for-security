"""Adversarial coverage for verified adapter executable launches."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import cops.execution.executable as executable_module
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
from tests.auth_testkit import authorize_test_plan, worker_inventory_for_plan

HAS_PROC_FD = Path("/proc/self/fd").is_dir()


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


def _fake_action_plan(tmp_path: Path, *, timeout_seconds: float = 5) -> ActionPlan:
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "cops/contracts/fixtures/valid_action_plan.json").read_text(
            encoding="utf-8"
        )
    )
    limits = dict(fixture["limits"])
    limits["max_output_bytes"] = 4096
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
            }
        ],
        limits=limits,
        credential_references=[],
        created_at=fixture["created_at"],
    )


def _fake_worker(tmp_path: Path, plan: ActionPlan) -> tuple[IsolatedWorker, str]:
    auth, trust_store, engagement = authorize_test_plan(
        plan, worker_identity="test-worker-01", valid_hours=2
    )
    store = ApprovalStore(tmp_path / "approval.sqlite3")
    store.store_authorization(auth)
    registry = ToolAdapterRegistry(definitions_path=tmp_path / "no-definitions")
    registry.register_adapter(_fake_adapter())
    worker = IsolatedWorker(
        worker_inventory_for_plan(plan, worker_identity="test-worker-01"),
        store=store,
        trust_store=trust_store,
        engagement=engagement,
        adapter_registry=registry,
    )
    return worker, auth.authorization_id


@pytest.mark.parametrize(
    ("program", "expected_code", "timed_out", "overflow"),
    [
        ("print('ok')", 0, False, False),
        ("import sys; print('nonzero-three'); sys.exit(3)", 3, False, False),
        ("import sys; print('failed', file=sys.stderr); sys.exit(9)", 9, False, False),
        ("import time; time.sleep(30)", -9, True, False),
        ("print('x' * 10000)", -9, False, True),
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


@pytest.mark.parametrize(
    ("process_result", "expected_status", "expected_exit_code"),
    [
        (BoundedProcessResult(b"ok\n", b"", 0, False, False), "success", 0),
        (BoundedProcessResult(b"", b"", -9, True, False), "partial", 124),
        (BoundedProcessResult(b"x" * 64, b"", -9, False, True), "partial", 125),
        (BoundedProcessResult(b"", b"failed\n", 9, False, False), "failed", 9),
    ],
    ids=("success", "timeout", "output-overflow", "failure"),
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
    prepared = SimpleNamespace(
        invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None
    )
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    monkeypatch.setattr(
        worker_module, "run_bounded_process", lambda *args, **kwargs: process_result
    )

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == expected_status
    assert result.exit_code == expected_exit_code


def test_worker_counts_executable_preparation_against_step_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path, timeout_seconds=1)
    worker, authorization_id = _fake_worker(tmp_path, plan)
    prepared = SimpleNamespace(
        invocation_path="/proc/self/fd/7", pass_fds=(), remove=lambda: None
    )
    monkeypatch.setattr(worker_module, "prepare_executable", lambda *args, **kwargs: prepared)
    monotonic_values = iter((100.0, 102.0))
    monkeypatch.setattr(worker_module, "monotonic", lambda: next(monotonic_values))

    def unexpected_launch(*args, **kwargs):
        raise AssertionError("operation must not launch after preparation consumes its deadline")

    monkeypatch.setattr(worker_module, "run_bounded_process", unexpected_launch)

    result = worker.execute_plan(
        plan,
        authorization=authorization_id,
        workspace_dir=tmp_path / "workspace",
    )

    assert result.status == "partial"
    assert result.exit_code == 124


def test_worker_normalizes_executable_preparation_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fake_action_plan(tmp_path, timeout_seconds=1)
    worker, authorization_id = _fake_worker(tmp_path, plan)

    def expired_preparation(*args, **kwargs):
        raise ExecutablePreparationTimeoutError(
            "adapter executable preparation exceeded the step timeout"
        )

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
    program = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])"
    )
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


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_version_mismatch(tmp_path: Path) -> None:
    adapter = _python_adapter(pinned_revision="0.0.0")

    with pytest.raises(ExecutableVerificationError, match="version mismatch"):
        prepare_executable(
            adapter,
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
        )


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_expired_shared_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(executable_module, "monotonic", lambda: 2.0)

    def unexpected_probe(*args, **kwargs):
        raise AssertionError("version probe must not run after staging consumes the deadline")

    monkeypatch.setattr(executable_module, "run_bounded_process", unexpected_probe)

    with pytest.raises(ExecutableVerificationError, match="exceeded the step timeout"):
        prepare_executable(
            _python_adapter(),
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            deadline=1.0,
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
def test_prepared_executable_is_bound_to_verified_inode_after_path_swap(tmp_path: Path) -> None:
    prepared = prepare_executable(
        _python_adapter(),
        workspace=tmp_path,
        env=os.environ,
        timeout_seconds=5,
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
        prepared.remove()
        replacement.unlink(missing_ok=True)


@pytest.mark.skipif(not HAS_PROC_FD, reason="stable executable launch requires Linux /proc")
def test_prepare_executable_rejects_symlink_source(tmp_path: Path) -> None:
    adapter = _python_adapter()
    link = tmp_path / "fake-python"
    link.symlink_to(sys.executable)
    adapter.binary = str(link)

    with pytest.raises(ExecutableVerificationError, match="without following symlinks"):
        prepare_executable(adapter, workspace=tmp_path, env=os.environ, timeout_seconds=5)


@pytest.mark.skipif(HAS_PROC_FD, reason="only exercises the unsupported-platform boundary")
def test_prepare_executable_fails_closed_without_linux_proc(tmp_path: Path) -> None:
    with pytest.raises(ExecutableVerificationError, match="requires Linux /proc/self/fd"):
        prepare_executable(
            _python_adapter(),
            workspace=tmp_path,
            env=os.environ,
            timeout_seconds=5,
        )


def test_evidence_rejects_symlinked_artifact_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "artifacts").symlink_to(outside, target_is_directory=True)
    recorder = EvidenceRecorder(tmp_path)

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact write failed"):
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


def test_evidence_rejects_symlinked_workspace_parent_before_creation(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "workspace-link"
    link.symlink_to(outside, target_is_directory=True)
    recorder = EvidenceRecorder(link / "new-workspace")

    with pytest.raises(EvidenceCaptureError, match="secure evidence artifact write failed"):
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


@pytest.mark.parametrize("invalid_execution", ([], {"sha256": 42}, {"sha256": ["0" * 64]}))
def test_registry_rejects_malformed_execution_metadata(
    tmp_path: Path, invalid_execution: object
) -> None:
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
