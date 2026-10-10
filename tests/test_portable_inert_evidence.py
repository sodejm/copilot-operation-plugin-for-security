from __future__ import annotations

from pathlib import Path

import pytest

from cops.execution.evidence import EvidenceCaptureError, EvidenceCleanupError, EvidenceRecorder


def _record(recorder: EvidenceRecorder, *, reservation=None, tool: str = "inert"):
    return recorder.record_step_output(
        step_id="step-1",
        tool=tool,
        action="simulate",
        stdout=b"portable output",
        stderr=b"",
        exit_code=0,
        started_at="2026-10-08T12:00:00Z",
        finished_at="2026-10-08T12:00:01Z",
        reservation=reservation,
    )


def test_portable_inert_capture_does_not_require_posix_descriptor_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)

    def fail_posix_flags() -> tuple[int, int]:
        raise AssertionError("portable mode used POSIX flags")

    monkeypatch.setattr(recorder, "_required_posix_flags", fail_posix_flags)

    redacted, artifact = _record(recorder)

    assert redacted == b"portable output"
    assert (tmp_path / artifact.path).read_bytes() == redacted
    assert artifact.path == "artifacts/step-1_output.txt"


def test_portable_inert_capture_rejects_external_tools_before_reservation(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)

    with pytest.raises(EvidenceCaptureError, match="restricted to inert operations"):
        _record(recorder, tool="nmap")

    assert not (tmp_path / "artifacts").exists()


def test_portable_inert_reservation_never_overwrites_a_collision(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(mode=0o700)
    collision = artifacts / "step-1_output.txt"
    collision.write_bytes(b"existing evidence")
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)

    reservation = recorder.reserve_step_output("step-1")
    _, artifact = _record(recorder, reservation=reservation)

    assert reservation.name != collision.name
    assert collision.read_bytes() == b"existing evidence"
    assert (tmp_path / artifact.path).read_bytes() == b"portable output"


def test_portable_inert_rejects_replaced_reservation_without_deleting_replacement(
    tmp_path: Path,
) -> None:
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)
    reservation = recorder.reserve_step_output("step-1")
    reserved_path = tmp_path / reservation.path
    reserved_path.unlink()
    reserved_path.write_bytes(b"replacement")
    reserved_path.chmod(0o600)

    with pytest.raises(EvidenceCleanupError, match="residual artifact may remain"):
        _record(recorder, reservation=reservation)

    assert reserved_path.read_bytes() == b"replacement"


def test_portable_inert_rejects_symlinked_artifact_directory(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(mode=0o700)
    (tmp_path / "artifacts").symlink_to(outside, target_is_directory=True)
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)

    with pytest.raises(EvidenceCaptureError, match="not a real directory"):
        recorder.reserve_step_output("step-1")

    assert list(outside.iterdir()) == []


def test_portable_inert_discard_closes_before_removing_reserved_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    recorder = EvidenceRecorder(tmp_path, portable_inert=True)
    reservation = recorder.reserve_step_output("step-1")
    reserved_path = tmp_path / reservation.path
    held_handle = recorder._reservation_handles[reservation.path]
    real_unlink = Path.unlink

    def unlink_after_close(path: Path, *args, **kwargs) -> None:
        assert held_handle.closed
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink_after_close)

    recorder.discard_reservation(reservation)

    assert not reserved_path.exists()
    assert recorder._reservations == {}
    assert recorder._reservation_handles == {}
