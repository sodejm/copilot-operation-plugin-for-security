"""Native portability acceptance for active-discovery checkpoint journals."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cops.discovery import ActiveScanSession, ActiveServiceAssessment, ScanBudget
from cops.discovery.active_scanner import ActiveScanError, _live_checkpoint_lock


def _session() -> ActiveScanSession:
    return ActiveScanSession(
        session_id="native-checkpoint-portability",
        scope_reference="approved-engagement",
        approved_targets=["127.0.0.1"],
        approved_ports=[65000, 65001],
        budget=ScanBudget(max_probes=2),
    )


def _assessment(session: ActiveScanSession, port: int) -> ActiveServiceAssessment:
    return ActiveServiceAssessment(
        probe_id=f"native-checkpoint-{port}",
        target_host="127.0.0.1",
        resolved_ip="127.0.0.1",
        port=port,
        vantage=session.vantage,
    )


def test_native_checkpoint_replays_resumes_compacts_and_removes_journal(tmp_path: Path):
    session = _session()
    checkpoint = tmp_path / "checkpoint.json"
    journal = session.checkpoint_journal_path(checkpoint)
    first = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
    second = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65001)

    session.save_checkpoint(checkpoint)
    session.append_probe_reservations(checkpoint, [first, second])
    session.append_probe_completion(checkpoint, first, _assessment(session, 65000))

    resumed = ActiveScanSession.load_checkpoint(checkpoint)
    assert resumed.completed_probe_keys == {first}
    assert resumed.pending_probe_keys == {second}
    assert resumed.total_probes_dispatched == 2
    assert resumed.total_side_effects == 1

    resumed.append_probe_completion(checkpoint, second, _assessment(resumed, 65001))
    replayed = ActiveScanSession.load_checkpoint(checkpoint)
    assert replayed.completed_probe_keys == {first, second}
    assert replayed.pending_probe_keys == set()
    assert replayed.total_probes_dispatched == 2
    assert replayed.total_side_effects == 2

    replayed.save_checkpoint(checkpoint)
    assert not journal.exists()

    compacted = ActiveScanSession.load_checkpoint(checkpoint)
    assert compacted.completed_probe_keys == {first, second}
    assert compacted.pending_probe_keys == set()
    assert compacted.total_probes_dispatched == 2
    assert compacted.total_side_effects == 2
    assert [assessment.port for assessment in compacted.assessments] == [65000, 65001]


def test_native_checkpoint_rejects_symlink_or_reparse_journal(tmp_path: Path):
    session = _session()
    checkpoint = tmp_path / "checkpoint.json"
    victim = tmp_path / "victim"
    session.save_checkpoint(checkpoint)
    victim.write_bytes(b"unchanged")
    victim.chmod(0o600)
    journal = session.checkpoint_journal_path(checkpoint)
    try:
        journal.symlink_to(victim)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink or reparse-point creation unavailable: {error}")

    key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
    with pytest.raises(ValueError, match="unsafe"):
        session.append_probe_reservation(checkpoint, key)
    with pytest.raises(ValueError, match="unsafe"):
        ActiveScanSession.load_checkpoint(checkpoint)

    assert victim.read_bytes() == b"unchanged"
    assert journal.is_symlink()


def test_native_checkpoint_rejects_hard_link_journal(tmp_path: Path):
    session = _session()
    checkpoint = tmp_path / "checkpoint.json"
    victim = tmp_path / "victim"
    session.save_checkpoint(checkpoint)
    victim.write_bytes(b"unchanged")
    victim.chmod(0o600)
    journal = session.checkpoint_journal_path(checkpoint)
    try:
        os.link(victim, journal)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hard-link creation unavailable: {error}")

    key = session.make_probe_key(session.vantage, "tcp", "127.0.0.1", 65000)
    with pytest.raises(ValueError, match="hard links"):
        session.append_probe_reservation(checkpoint, key)
    with pytest.raises(ValueError, match="hard links"):
        ActiveScanSession.load_checkpoint(checkpoint)

    assert victim.read_bytes() == b"unchanged"
    assert journal.exists()


def test_native_controller_lock_acquires_and_releases(tmp_path: Path):
    checkpoint = tmp_path / "checkpoint.json"

    with _live_checkpoint_lock(checkpoint):
        assert checkpoint.with_name(f"{checkpoint.name}.lock").exists()
    with _live_checkpoint_lock(checkpoint):
        pass


def test_native_controller_lock_rejects_symlink_or_reparse_without_modifying_victim(tmp_path: Path):
    checkpoint = tmp_path / "checkpoint.json"
    victim = tmp_path / "lock-victim"
    victim.write_bytes(b"")
    victim.chmod(0o600)
    lock_path = checkpoint.with_name(f"{checkpoint.name}.lock")
    try:
        lock_path.symlink_to(victim)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink or reparse-point creation unavailable: {error}")

    with pytest.raises(ActiveScanError, match="unsafe"):
        with _live_checkpoint_lock(checkpoint):
            pytest.fail("unsafe lock path was acquired")

    assert victim.read_bytes() == b""
    assert lock_path.is_symlink()


def test_native_controller_lock_rejects_hard_link_without_modifying_victim(tmp_path: Path):
    checkpoint = tmp_path / "checkpoint.json"
    victim = tmp_path / "lock-victim"
    victim.write_bytes(b"")
    victim.chmod(0o600)
    lock_path = checkpoint.with_name(f"{checkpoint.name}.lock")
    try:
        os.link(victim, lock_path)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"hard-link creation unavailable: {error}")

    with pytest.raises(ActiveScanError, match="unsafe"):
        with _live_checkpoint_lock(checkpoint):
            pytest.fail("unsafe lock path was acquired")

    assert victim.read_bytes() == b""
    assert lock_path.exists()
