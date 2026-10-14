"""Regression tests for the owner-only laboratory dispatch journal."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from cops.laboratory import LaboratoryCaseJournal, LaboratoryGateError
from cops.laboratory import journal as journal_module


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def _legacy_journal(path: Path, rows: list[tuple[str, str]]) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE cases (
            attempt_id TEXT PRIMARY KEY,
            result_id TEXT UNIQUE,
            environment_id TEXT NOT NULL,
            state TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            result_json TEXT
        )"""
    )
    connection.executemany(
        "INSERT INTO cases (attempt_id, environment_id, state, payload_json) VALUES (?, 'lab-owner', 'dispatching', ?)",
        [(attempt_id, json.dumps({"authorization_id": authorization_id})) for attempt_id, authorization_id in rows],
    )
    connection.commit()
    connection.close()
    os.chmod(path, 0o600)


def test_legacy_journal_migrates_authorization_reservations(tmp_path: Path) -> None:
    journal_path = _private_directory(tmp_path / "journal") / "cases.sqlite3"
    _legacy_journal(journal_path, [("old-attempt", "authorization-old")])

    journal = LaboratoryCaseJournal(journal_path)

    assert journal.authorization_attempted("authorization-old") is True
    with pytest.raises(LaboratoryGateError, match="already been used"):
        journal.begin(
            "new-attempt",
            "lab-owner",
            {"authorization_id": "authorization-old"},
        )
    connection = sqlite3.connect(journal_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(cases)")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(cases)")}
    finally:
        connection.close()
    assert "authorization_id" in columns
    assert "cases_authorization_id_unique" in indexes


def test_legacy_duplicate_authorizations_fail_migration(tmp_path: Path) -> None:
    journal_path = _private_directory(tmp_path / "journal") / "cases.sqlite3"
    _legacy_journal(
        journal_path,
        [("attempt-one", "authorization-reused"), ("attempt-two", "authorization-reused")],
    )

    with pytest.raises(LaboratoryGateError, match="invalid or unavailable"):
        LaboratoryCaseJournal(journal_path)


def test_begin_atomically_reserves_authorization_across_connections(tmp_path: Path) -> None:
    journal_path = _private_directory(tmp_path / "journal") / "cases.sqlite3"
    first = LaboratoryCaseJournal(journal_path)
    second = LaboratoryCaseJournal(journal_path)
    barrier = threading.Barrier(2)

    def reserve(journal: LaboratoryCaseJournal, attempt_id: str) -> str:
        barrier.wait()
        try:
            journal.begin(
                attempt_id,
                "lab-owner",
                {"authorization_id": "authorization-shared"},
            )
        except LaboratoryGateError as err:
            return str(err)
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda item: reserve(*item),
                [(first, "attempt-one"), (second, "attempt-two")],
            )
        )

    assert outcomes.count("reserved") == 1
    assert outcomes.count("execution authorization has already been used for a dispatch attempt") == 1
    assert len(first.records()) == 1


def test_parent_replacement_during_sqlite_open_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal_parent = _private_directory(tmp_path / "journal")
    journal_path = journal_parent / "cases.sqlite3"
    journal = LaboratoryCaseJournal(journal_path)
    journal.begin("attempt-one", "lab-owner", {"authorization_id": "authorization-one"})

    moved_parent = tmp_path / "journal-original"
    replacement_parent = _private_directory(tmp_path / "journal-replacement")
    replacement_path = replacement_parent / journal_path.name
    _legacy_journal(replacement_path, [("attacker-attempt", "attacker-authorization")])
    real_connect = sqlite3.connect
    replaced = False

    def replace_then_connect(*args, **kwargs):
        nonlocal replaced
        if not replaced:
            journal_parent.rename(moved_parent)
            journal_parent.symlink_to(replacement_parent, target_is_directory=True)
            replaced = True
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(journal_module.sqlite3, "connect", replace_then_connect)
    try:
        with pytest.raises(LaboratoryGateError, match="cannot protect|identity changed"):
            journal.records()
    finally:
        if journal_parent.is_symlink():
            journal_parent.unlink()
        if moved_parent.exists():
            moved_parent.rename(journal_parent)

    assert journal.authorization_attempted("authorization-one") is True
    assert journal.authorization_attempted("attacker-authorization") is False


def test_connection_is_closed_when_post_open_path_check_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = _private_directory(tmp_path / "journal") / "cases.sqlite3"
    journal = LaboratoryCaseJournal(journal_path)
    real_connect = sqlite3.connect
    real_check_path = journal._check_path
    opened_connections = []

    class TrackingConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection
            self.closed = False

        def close(self) -> None:
            self.closed = True
            self.connection.close()

        def __getattr__(self, name: str):
            return getattr(self.connection, name)

    def tracking_connect(*args, **kwargs):
        connection = TrackingConnection(real_connect(*args, **kwargs))
        opened_connections.append(connection)
        return connection

    checks = 0

    def fail_post_open_check():
        nonlocal checks
        checks += 1
        if checks == 2:
            raise LaboratoryGateError("laboratory case journal parent identity changed")
        return real_check_path()

    monkeypatch.setattr(journal_module.sqlite3, "connect", tracking_connect)
    monkeypatch.setattr(journal, "_check_path", fail_post_open_check)

    with pytest.raises(LaboratoryGateError, match="parent identity changed"):
        journal.records()

    assert len(opened_connections) == 1
    assert opened_connections[0].closed is True
