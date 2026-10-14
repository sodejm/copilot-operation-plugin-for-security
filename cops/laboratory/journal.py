"""Owner-only journal for laboratory dispatch and case classification."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cops.execution.filesystem import (
    SecureDirectoryError,
    open_directory_no_symlinks,
    same_directory_identity,
)

from .models import LaboratoryGateError


class LaboratoryCaseJournal:
    """Persist dispatch intent and terminal results outside worker workspaces."""

    def __init__(self, path: Path | str) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise LaboratoryGateError("laboratory case journal path must be absolute")
        self.path = Path(os.path.abspath(os.fspath(candidate)))
        self._parent_fd = self._open_parent()
        if not self._entry_exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.path.name, flags, 0o600, dir_fd=self._parent_fd)
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
                        result_json TEXT,
                        authorization_id TEXT
                    )"""
                )
                self._migrate_authorization_ids(connection)
                for row in connection.execute(
                    "SELECT attempt_id, state, payload_json FROM cases WHERE state IN ('dispatching', 'pending')"
                ):
                    payload = json.loads(row["payload_json"])
                    if row["state"] == "pending":
                        result = payload["failure_result"]
                        result["details"]["failure_reason"] = (
                            "operator case observation missing after controller restart"
                        )
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

    def __del__(self) -> None:
        parent_fd = getattr(self, "_parent_fd", -1)
        if parent_fd >= 0:
            os.close(parent_fd)
            self._parent_fd = -1

    def _open_parent(self) -> int:
        try:
            parent_fd = open_directory_no_symlinks(self.path.parent)
            parent_stat = os.fstat(parent_fd)
            if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
                raise LaboratoryGateError("laboratory case journal parent must be owned by the operator")
            if stat.S_IMODE(parent_stat.st_mode) & 0o077:
                raise LaboratoryGateError("laboratory case journal parent must be owner-only")
            return parent_fd
        except (OSError, SecureDirectoryError) as err:
            raise LaboratoryGateError("cannot protect laboratory case journal") from err
        except Exception:
            if "parent_fd" in locals():
                os.close(parent_fd)
            raise

    def _entry_exists(self) -> bool:
        try:
            os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        except OSError as err:
            raise LaboratoryGateError("cannot protect laboratory case journal") from err

    def _check_path(self) -> os.stat_result:
        reopened_parent = -1
        try:
            reopened_parent = open_directory_no_symlinks(self.path.parent)
            if not same_directory_identity(reopened_parent, self._parent_fd):
                raise LaboratoryGateError("laboratory case journal parent identity changed")
            file_stat = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(file_stat.st_mode):
                raise LaboratoryGateError("laboratory case journal must be a regular file")
            if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
                raise LaboratoryGateError("laboratory case journal must be owned by the operator")
            if stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise LaboratoryGateError("laboratory case journal must be owner-only")
            return file_stat
        except LaboratoryGateError:
            raise
        except (OSError, SecureDirectoryError) as err:
            raise LaboratoryGateError("cannot protect laboratory case journal") from err
        finally:
            if reopened_parent >= 0:
                os.close(reopened_parent)

    def _connect(self) -> sqlite3.Connection:
        expected = self._check_path()
        descriptor = -1
        connection: sqlite3.Connection | None = None
        try:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path.name, flags, dir_fd=self._parent_fd)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
                raise LaboratoryGateError("laboratory case journal identity changed")
            database_uri = f"file:{quote(os.fspath(self.path), safe='/')}?mode=rw&nofollow=1"
            connection = sqlite3.connect(database_uri, uri=True)
            current = self._check_path()
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise LaboratoryGateError("laboratory case journal identity changed while opening")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except LaboratoryGateError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as err:
            if connection is not None:
                connection.close()
            raise LaboratoryGateError("cannot open laboratory case journal") from err
        except OSError as err:
            if connection is not None:
                connection.close()
            raise LaboratoryGateError("cannot protect laboratory case journal") from err
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _migrate_authorization_ids(connection: sqlite3.Connection) -> None:
        """Populate the indexed reservation column used by current journals."""
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(cases)")}
        if "authorization_id" not in columns:
            connection.execute("ALTER TABLE cases ADD COLUMN authorization_id TEXT")
        for row in connection.execute("SELECT attempt_id, payload_json FROM cases WHERE authorization_id IS NULL"):
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("invalid laboratory journal payload")
            authorization_id = payload.get("authorization_id")
            if not isinstance(authorization_id, str) or not authorization_id:
                raise ValueError("missing laboratory authorization identifier")
            connection.execute(
                "UPDATE cases SET authorization_id = ? WHERE attempt_id = ?",
                (authorization_id, row["attempt_id"]),
            )
        for row in connection.execute("SELECT authorization_id FROM cases"):
            authorization_id = row["authorization_id"]
            if not isinstance(authorization_id, str) or not authorization_id:
                raise ValueError("invalid laboratory authorization identifier")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS cases_authorization_id_unique "
            "ON cases(authorization_id) WHERE authorization_id IS NOT NULL"
        )

    def begin(self, attempt_id: str, environment_id: str, payload: dict[str, Any]) -> None:
        authorization_id = payload.get("authorization_id")
        if not isinstance(authorization_id, str) or not authorization_id:
            raise LaboratoryGateError("laboratory dispatch intent requires an authorization identifier")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM cases WHERE authorization_id = ?",
                    (authorization_id,),
                ).fetchone():
                    raise LaboratoryGateError("execution authorization has already been used for a dispatch attempt")
                connection.execute(
                    "INSERT INTO cases "
                    "(attempt_id, environment_id, state, payload_json, authorization_id) "
                    "VALUES (?, ?, 'dispatching', ?, ?)",
                    (attempt_id, environment_id, json.dumps(payload, sort_keys=True), authorization_id),
                )
                connection.commit()
        except LaboratoryGateError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record laboratory dispatch intent") from err

    def bind(self, attempt_id: str, result_id: str, failure_result: dict[str, Any]) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                row = connection.execute(
                    "SELECT payload_json FROM cases WHERE attempt_id = ? AND state = 'dispatching'",
                    (attempt_id,),
                ).fetchone()
                if row is None:
                    raise LaboratoryGateError("laboratory dispatch intent is missing")
                payload = json.loads(row["payload_json"])
                payload["failure_result"] = failure_result
                cursor = connection.execute(
                    "UPDATE cases SET state = 'pending', result_id = ?, payload_json = ? "
                    "WHERE attempt_id = ? AND state = 'dispatching'",
                    (result_id, json.dumps(payload, sort_keys=True), attempt_id),
                )
                if cursor.rowcount != 1:
                    raise LaboratoryGateError("laboratory dispatch intent is missing")
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record laboratory dispatch result") from err

    def mark_unknown(
        self,
        attempt_id: str,
        reason: str,
        *,
        evidence_records: list[dict[str, Any]] | None = None,
        cleanup_receipt_digest: str | None = None,
    ) -> None:
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
                if evidence_records is not None:
                    payload["durable_evidence"] = evidence_records
                if cleanup_receipt_digest is not None:
                    payload["cleanup_receipt_digest"] = cleanup_receipt_digest
                connection.execute(
                    "UPDATE cases SET state = 'unknown', payload_json = ? WHERE attempt_id = ?",
                    (json.dumps(payload, sort_keys=True), attempt_id),
                )
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot record uncertain laboratory dispatch") from err

    def authorization_attempted(self, authorization_id: str) -> bool:
        """Return whether an authorization has already crossed the dispatch boundary."""
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    "SELECT 1 FROM cases WHERE authorization_id = ?",
                    (authorization_id,),
                ).fetchone()
            return row is not None
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise LaboratoryGateError("cannot inspect laboratory authorization history") from err

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
