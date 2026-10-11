"""Owner-only journal for laboratory dispatch and case classification."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any

from cops.execution.filesystem import SecureDirectoryError, open_directory_no_symlinks

from .models import LaboratoryGateError


class LaboratoryCaseJournal:
    """Persist dispatch intent and terminal results outside worker workspaces."""

    def __init__(self, path: Path | str) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise LaboratoryGateError("laboratory case journal path must be absolute")
        self.path = Path(os.path.abspath(os.fspath(candidate)))
        self._check_path()
        if not self.path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.path, flags, 0o600)
                os.close(descriptor)
            except FileExistsError:
                pass
            except OSError as err:
                raise LaboratoryGateError("cannot create laboratory case journal") from err
        self._check_path()
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS cases (
                        attempt_id TEXT PRIMARY KEY,
                        result_id TEXT UNIQUE,
                        environment_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        result_json TEXT
                    )"""
                )
                for row in connection.execute("SELECT attempt_id, state, payload_json FROM cases WHERE state IN ('dispatching', 'pending')"):
                    payload = json.loads(row["payload_json"])
                    if row["state"] == "pending":
                        result = payload["failure_result"]
                        result["details"]["failure_reason"] = "operator case observation missing after controller restart"
                        connection.execute(
                            "UPDATE cases SET state = 'failed', result_json = ? WHERE attempt_id = ?",
                            (json.dumps(result, sort_keys=True), row["attempt_id"]),
                        )
                    else:
                        payload["failure_reason"] = "dispatch outcome unknown after controller restart"
                        connection.execute(
                            "UPDATE cases SET state = 'unknown', payload_json = ? WHERE attempt_id = ?",
                            (json.dumps(payload, sort_keys=True), row["attempt_id"]),
                        )
        except (sqlite3.Error, ValueError, KeyError, TypeError) as err:
            raise LaboratoryGateError("laboratory case journal is invalid or unavailable") from err

    def _check_path(self) -> None:
        parent_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(self.path.parent)
            parent_stat = os.fstat(parent_fd)
            if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
                raise LaboratoryGateError("laboratory case journal parent must be owned by the operator")
            if stat.S_IMODE(parent_stat.st_mode) & 0o077:
                raise LaboratoryGateError("laboratory case journal parent must be owner-only")
            if self.path.is_symlink():
                raise LaboratoryGateError("laboratory case journal must not be a symbolic link")
            if self.path.exists():
                file_stat = self.path.stat()
                if not stat.S_ISREG(file_stat.st_mode):
                    raise LaboratoryGateError("laboratory case journal must be a regular file")
                if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
                    raise LaboratoryGateError("laboratory case journal must be owned by the operator")
                if stat.S_IMODE(file_stat.st_mode) & 0o077:
                    raise LaboratoryGateError("laboratory case journal must be owner-only")
        except (OSError, SecureDirectoryError) as err:
            raise LaboratoryGateError("cannot protect laboratory case journal") from err
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    def _connect(self) -> sqlite3.Connection:
        self._check_path()
        try:
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as err:
            raise LaboratoryGateError("cannot open laboratory case journal") from err

    def begin(self, attempt_id: str, environment_id: str, payload: dict[str, Any]) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO cases (attempt_id, environment_id, state, payload_json) VALUES (?, ?, 'dispatching', ?)",
                    (attempt_id, environment_id, json.dumps(payload, sort_keys=True)),
                )
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record laboratory dispatch intent") from err

    def bind(self, attempt_id: str, result_id: str, failure_result: dict[str, Any]) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "UPDATE cases SET state = 'pending', result_id = ?, payload_json = ? "
                    "WHERE attempt_id = ? AND state = 'dispatching'",
                    (result_id, json.dumps({"failure_result": failure_result}, sort_keys=True), attempt_id),
                )
                if cursor.rowcount != 1:
                    raise LaboratoryGateError("laboratory dispatch intent is missing")
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record laboratory dispatch result") from err

    def mark_unknown(self, attempt_id: str, reason: str) -> None:
        """Preserve an uncertain dispatch instead of claiming it did not run."""
        try:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    "SELECT payload_json FROM cases WHERE attempt_id = ? AND state = 'dispatching'",
                    (attempt_id,),
                ).fetchone()
                if row is None:
                    raise LaboratoryGateError("laboratory dispatch intent is missing")
                payload = json.loads(row["payload_json"])
                payload["failure_reason"] = reason
                connection.execute(
                    "UPDATE cases SET state = 'unknown', payload_json = ? WHERE attempt_id = ?",
                    (json.dumps(payload, sort_keys=True), attempt_id),
                )
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record uncertain laboratory dispatch") from err

    def finish(self, result_id: str, result: dict[str, Any], *, state: str) -> None:
        if state not in ("classified", "failed"):
            raise LaboratoryGateError("invalid laboratory case journal state")
        try:
            with closing(self._connect()) as connection, connection:
                cursor = connection.execute(
                    "UPDATE cases SET state = ?, result_json = ? WHERE result_id = ? AND state = 'pending'",
                    (state, json.dumps(result, sort_keys=True), result_id),
                )
                if cursor.rowcount != 1:
                    raise LaboratoryGateError("laboratory case is no longer pending")
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record laboratory case outcome") from err

    def fail(self, result_id: str, reason: str) -> dict[str, Any]:
        """Record a terminal failure for a dispatched case lacking valid observation."""
        try:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    "SELECT payload_json FROM cases WHERE result_id = ? AND state = 'pending'",
                    (result_id,),
                ).fetchone()
                if row is None:
                    raise LaboratoryGateError("laboratory case is no longer pending")
                result = json.loads(row["payload_json"])["failure_result"]
                result["details"]["failure_reason"] = reason
                connection.execute(
                    "UPDATE cases SET state = 'failed', result_json = ? WHERE result_id = ?",
                    (json.dumps(result, sort_keys=True), result_id),
                )
                return result
        except (sqlite3.Error, TypeError, ValueError, KeyError) as err:
            raise LaboratoryGateError("cannot record laboratory case failure") from err

    def records(self) -> list[dict[str, Any]]:
        """Return persisted attempts, including unknown dispatches and case outcomes."""
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    "SELECT attempt_id, result_id, environment_id, state, payload_json, result_json "
                    "FROM cases ORDER BY rowid"
                ).fetchall()
            return [
                {
                    "attempt_id": row["attempt_id"],
                    "result_id": row["result_id"],
                    "environment_id": row["environment_id"],
                    "state": row["state"],
                    "payload": json.loads(row["payload_json"]),
                    "result": json.loads(row["result_json"]) if row["result_json"] else None,
                }
                for row in rows
            ]
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot read laboratory case journal") from err
