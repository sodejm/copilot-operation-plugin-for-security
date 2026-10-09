"""Durable ownership-aware side-effect tracking and cleanup receipts."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cops.contracts.lifecycle import ContractError
from cops.contracts.models import CleanupReceipt
from cops.evidence.canonical import digest, utc_now

from .filesystem import SecureDirectoryError, open_directory_no_symlinks

PLAN_DECLARED_PROVENANCE_KEY = "_cops_plan_declared_provenance"
PLAN_DECLARED_PROVENANCE_UNVERIFIED = "unverified"


class CleanupError(RuntimeError):
    """Base exception for cleanup and recovery failures."""


class CleanupOwnershipError(CleanupError):
    """Attempted to modify or clean a resource not owned by the worker."""


class CleanupPreconditionError(CleanupError):
    """Precondition check failed before executing rollback."""


class CleanupPersistenceError(CleanupError):
    """Cleanup journal state could not be safely persisted or recovered."""


@dataclass
class SideEffect:
    """Individual resource or state change tracked in the side-effect ledger."""

    effect_id: str
    step_id: str
    resource_type: str
    target: str
    action_plan_id: str
    engagement_id: str
    owner: str
    created_at: str
    cleanup_action: str = "delete"
    status: str = "pending"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "step_id": self.step_id,
            "resource_type": self.resource_type,
            "target": self.target,
            "action_plan_id": self.action_plan_id,
            "engagement_id": self.engagement_id,
            "owner": self.owner,
            "created_at": self.created_at,
            "cleanup_action": self.cleanup_action,
            "status": self.status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SideEffect:
        required = {
            "effect_id",
            "step_id",
            "resource_type",
            "target",
            "action_plan_id",
            "engagement_id",
            "owner",
            "created_at",
            "cleanup_action",
            "status",
            "metadata",
        }
        if set(data) != required:
            raise ValueError("side-effect payload fields are invalid")
        string_fields = required - {"metadata"}
        if any(not isinstance(data[key], str) or not data[key] for key in string_fields):
            raise ValueError("side-effect string fields must be non-empty")
        if data["status"] not in {"pending", "cleaning", "cleaned", "failed", "unknown"}:
            raise ValueError("side-effect status is invalid")
        if not isinstance(data["metadata"], dict):
            raise ValueError("side-effect metadata must be an object")
        return cls(
            effect_id=data["effect_id"],
            step_id=data["step_id"],
            resource_type=data["resource_type"],
            target=data["target"],
            action_plan_id=data["action_plan_id"],
            engagement_id=data["engagement_id"],
            owner=data["owner"],
            created_at=data["created_at"],
            cleanup_action=data["cleanup_action"],
            status=data["status"],
            metadata=dict(data["metadata"]),
        )


@dataclass(frozen=True)
class RecoveredCleanupRun:
    """Durable cleanup work reconstructed after worker restart."""

    run_id: str
    plan_id: str
    engagement_id: str
    worker_identity: str
    workspace_dir: Path | None
    effects: tuple[SideEffect, ...]


class CleanupJournal:
    """Append-only SQLite journal stored outside execution workspaces."""

    _SCHEMA_VERSION = 1

    def __init__(self, path: Path | str) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise CleanupPersistenceError("cleanup journal path must be absolute")
        self.path = Path(os.path.abspath(os.fspath(candidate)))
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        parent_fd = -1
        try:
            parent_fd = open_directory_no_symlinks(self.path.parent)
            parent_stat = os.fstat(parent_fd)
            if hasattr(os, "geteuid") and parent_stat.st_uid != os.geteuid():
                raise CleanupPersistenceError("cleanup journal parent must be owned by the worker account")
            if stat.S_IMODE(parent_stat.st_mode) & 0o077:
                raise CleanupPersistenceError("cleanup journal parent must be owner-only")
        except CleanupPersistenceError:
            raise
        except (OSError, SecureDirectoryError) as err:
            raise CleanupPersistenceError(f"cannot protect cleanup journal parent: {err}") from err
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

        if self.path.is_symlink():
            raise CleanupPersistenceError("cleanup journal must not be a symbolic link")
        if not self.path.exists():
            return
        try:
            file_stat = self.path.stat()
        except OSError as err:
            raise CleanupPersistenceError(f"cannot inspect cleanup journal: {err}") from err
        if not stat.S_ISREG(file_stat.st_mode):
            raise CleanupPersistenceError("cleanup journal must be a regular file")
        if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
            raise CleanupPersistenceError("cleanup journal must be owned by the worker account")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise CleanupPersistenceError("cleanup journal must be owner-only")

    def _connect(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            # Re-check the path on every open so replacing the journal or one of
            # its parent directories with a symlink fails closed after startup.
            self._prepare_path()
            if not self.path.exists():
                raise CleanupPersistenceError("cleanup journal disappeared after initialization")
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as err:
            if connection is not None:
                connection.close()
            raise CleanupPersistenceError(f"cannot open cleanup journal: {err}") from err

    def _initialize(self) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
            self._prepare_path()
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cleanup_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cleanup_runs (
                        run_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cleanup_events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        effect_id TEXT,
                        created_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
                version = connection.execute(
                    "SELECT value FROM cleanup_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if version is None:
                    connection.execute(
                        "INSERT INTO cleanup_metadata(key, value) VALUES ('schema_version', ?)",
                        (str(self._SCHEMA_VERSION),),
                    )
                elif version["value"] != str(self._SCHEMA_VERSION):
                    raise CleanupPersistenceError("unsupported cleanup journal schema version")
        except (OSError, sqlite3.Error) as err:
            raise CleanupPersistenceError(f"cannot initialize cleanup journal: {err}") from err
        try:
            self.path.chmod(0o600)
        except OSError as err:
            raise CleanupPersistenceError(f"cannot protect cleanup journal: {err}") from err
        self._prepare_path()

    def assert_external_to(self, workspace_dir: Path | str) -> None:
        workspace = Path(os.path.abspath(os.fspath(workspace_dir)))
        try:
            self.path.relative_to(workspace)
        except ValueError:
            return
        raise CleanupPersistenceError("cleanup journal must be outside the execution workspace")

    def append(
        self,
        run_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        effect_id: str | None = None,
    ) -> None:
        try:
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO cleanup_events(
                        event_id, run_id, event_type, effect_id, created_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (f"evt-{uuid.uuid4().hex}", run_id, event_type, effect_id, utc_now(), serialized),
                )
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise CleanupPersistenceError(f"cannot persist cleanup event '{event_type}': {err}") from err

    def start_run(
        self,
        *,
        run_id: str,
        plan_id: str,
        engagement_id: str,
        worker_identity: str,
        workspace_dir: Path | None,
    ) -> None:
        payload = {
            "plan_id": plan_id,
            "engagement_id": engagement_id,
            "worker_identity": worker_identity,
            "workspace_dir": str(workspace_dir) if workspace_dir is not None else None,
        }
        try:
            serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            with closing(self._connect()) as connection, connection:
                created_at = utc_now()
                connection.execute(
                    "INSERT INTO cleanup_runs(run_id, created_at) VALUES (?, ?)",
                    (run_id, created_at),
                )
                connection.execute(
                    """
                    INSERT INTO cleanup_events(
                        event_id, run_id, event_type, effect_id, created_at, payload_json
                    ) VALUES (?, ?, 'run_started', NULL, ?, ?)
                    """,
                    (f"evt-{uuid.uuid4().hex}", run_id, created_at, serialized),
                )
        except sqlite3.IntegrityError as err:
            raise CleanupPersistenceError(f"cleanup journal already contains execution run '{run_id}'") from err
        except (sqlite3.Error, TypeError, ValueError) as err:
            raise CleanupPersistenceError(f"cannot persist cleanup run start: {err}") from err

    def record_run_event(self, run_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.append(run_id, event_type, payload)

    def record_effect(self, run_id: str, effect: SideEffect) -> None:
        self.append(run_id, "effect_recorded", effect.to_dict(), effect_id=effect.effect_id)

    def transition(
        self,
        run_id: str,
        effect: SideEffect,
        status: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.append(
            run_id,
            "cleanup_transition",
            {"status": status, "details": details or {}},
            effect_id=effect.effect_id,
        )

    def record_receipt(self, run_id: str, receipt: CleanupReceipt) -> None:
        self.append(run_id, "cleanup_receipt", receipt.to_dict())

    def recoverable_runs(self, worker_identity: str) -> tuple[RecoveredCleanupRun, ...]:
        try:
            with closing(self._connect()) as connection:
                run_rows = connection.execute("SELECT run_id FROM cleanup_runs ORDER BY created_at, run_id").fetchall()
                rows = connection.execute(
                    """
                    SELECT sequence, run_id, event_type, effect_id, payload_json
                    FROM cleanup_events
                    ORDER BY sequence
                    """
                ).fetchall()
        except sqlite3.Error as err:
            raise CleanupPersistenceError(f"cannot recover cleanup journal: {err}") from err

        state: dict[str, dict[str, Any]] = {}
        try:
            for row in run_rows:
                run_id = row["run_id"]
                if not isinstance(run_id, str) or not run_id:
                    raise ValueError("cleanup run ID must be a non-empty string")
                state[run_id] = {"started": None, "effects": {}, "receipt": None}
            for row in rows:
                payload = json.loads(row["payload_json"])
                if not isinstance(payload, dict):
                    raise ValueError("event payload must be an object")
                run_id = row["run_id"]
                if run_id not in state:
                    raise ValueError(f"event refers to unknown cleanup run '{run_id}'")
                run = state[run_id]
                event_type = row["event_type"]
                if run["started"] is None and event_type != "run_started":
                    raise ValueError(f"execution run '{row['run_id']}' has an event before run_started")
                if event_type == "run_started":
                    if run["started"] is not None:
                        raise ValueError(f"execution run '{row['run_id']}' has duplicate run_started events")
                    required = {"plan_id", "engagement_id", "worker_identity", "workspace_dir"}
                    if set(payload) != required:
                        raise ValueError("run_started payload fields are invalid")
                    if any(
                        not isinstance(payload[key], str) or not payload[key]
                        for key in ("plan_id", "engagement_id", "worker_identity")
                    ):
                        raise ValueError("run_started identity fields must be non-empty strings")
                    workspace_value = payload["workspace_dir"]
                    if workspace_value is not None:
                        if not isinstance(workspace_value, str) or not workspace_value:
                            raise ValueError("run_started workspace_dir must be an absolute string or null")
                        workspace_path = Path(workspace_value)
                        if not workspace_path.is_absolute() or ".." in workspace_path.parts:
                            raise ValueError("run_started workspace_dir must be an absolute normalized path")
                        normalized = Path(os.path.abspath(os.fspath(workspace_path)))
                        if str(normalized) != workspace_value:
                            raise ValueError("run_started workspace_dir must be normalized")
                        self.assert_external_to(normalized)
                    run["started"] = payload
                elif event_type == "effect_recorded":
                    effect_id = row["effect_id"]
                    if not isinstance(effect_id, str) or not effect_id:
                        raise ValueError("effect_recorded requires an effect ID")
                    effect = SideEffect.from_dict(payload)
                    if effect.effect_id != effect_id:
                        raise ValueError("effect event ID does not match its payload")
                    started = run["started"]
                    if effect.action_plan_id != started["plan_id"] or effect.engagement_id != started["engagement_id"]:
                        raise ValueError("effect identity does not match its cleanup run")
                    if effect.status != "pending":
                        raise ValueError("newly recorded effect must have pending status")
                    if effect_id in run["effects"]:
                        raise ValueError(f"duplicate effect ID '{effect_id}'")
                    run["effects"][effect_id] = effect
                elif event_type == "cleanup_transition":
                    if set(payload) != {"status", "details"} or not isinstance(payload["details"], dict):
                        raise ValueError("cleanup transition payload fields are invalid")
                    effect = run["effects"].get(row["effect_id"])
                    if effect is None:
                        raise ValueError("cleanup transition refers to an unknown effect")
                    status = payload.get("status")
                    if status not in {"pending", "cleaning", "cleaned", "failed", "unknown"}:
                        raise ValueError("cleanup transition status is invalid")
                    effect.status = status
                elif event_type == "cleanup_receipt":
                    receipt = CleanupReceipt.from_dict(payload)
                    started = run["started"]
                    if (
                        receipt.plan_id != started["plan_id"]
                        or receipt.engagement_id != started["engagement_id"]
                        or receipt.worker_identity != started["worker_identity"]
                    ):
                        raise ValueError("cleanup receipt identity does not match its cleanup run")
                    if receipt.status in {"completed", "not_required"} and receipt.unresolved_effects:
                        raise ValueError("terminal cleanup receipt cannot contain unresolved effects")
                    if receipt.status in {"partial", "failed"} and not receipt.unresolved_effects:
                        raise ValueError("incomplete cleanup receipt must contain unresolved effects")
                    run["receipt"] = receipt
                elif event_type in {"approval_consumption_started", "approval_consumed"}:
                    if row["effect_id"] is not None:
                        raise ValueError("approval journal event must not refer to an effect")
                else:
                    raise ValueError(f"unknown cleanup journal event type '{event_type}'")
        except (ContractError, json.JSONDecodeError, KeyError, TypeError, ValueError) as err:
            raise CleanupPersistenceError(f"cleanup journal contains invalid event data: {err}") from err

        recovered: list[RecoveredCleanupRun] = []
        for run_id, run in state.items():
            started = run["started"]
            if started is None:
                raise CleanupPersistenceError(f"cleanup journal run '{run_id}' is missing run_started")
            if started.get("worker_identity") != worker_identity:
                continue
            receipt = run["receipt"]
            if receipt is not None:
                effect_statuses = {effect.status for effect in run["effects"].values()}
                if receipt.status in {"completed", "not_required"} and effect_statuses <= {"cleaned"}:
                    continue
            workspace_value = started.get("workspace_dir")
            recovered.append(
                RecoveredCleanupRun(
                    run_id=run_id,
                    plan_id=str(started["plan_id"]),
                    engagement_id=str(started["engagement_id"]),
                    worker_identity=str(started["worker_identity"]),
                    workspace_dir=Path(workspace_value) if workspace_value is not None else None,
                    effects=tuple(run["effects"].values()),
                )
            )
        return tuple(recovered)


class SideEffectLedger:
    """Side-effect ledger with optional durable journal persistence."""

    def __init__(
        self,
        plan_id: str,
        engagement_id: str,
        default_owner: str,
        *,
        journal: CleanupJournal | None = None,
        run_id: str | None = None,
        workspace_dir: Path | None = None,
        recovered_effects: tuple[SideEffect, ...] = (),
        start_run: bool = True,
    ) -> None:
        self.plan_id = plan_id
        self.engagement_id = engagement_id
        self.default_owner = default_owner
        self.journal = journal
        self.run_id = run_id or f"run-{uuid.uuid4().hex}"
        self.workspace_dir = Path(os.path.abspath(os.fspath(workspace_dir))) if workspace_dir else None
        self._effects = list(recovered_effects)
        if self.journal is not None:
            if self.workspace_dir is not None:
                self.journal.assert_external_to(self.workspace_dir)
            if start_run:
                self.journal.start_run(
                    run_id=self.run_id,
                    plan_id=self.plan_id,
                    engagement_id=self.engagement_id,
                    worker_identity=self.default_owner,
                    workspace_dir=self.workspace_dir,
                )

    def record_effect(
        self,
        *,
        step_id: str,
        resource_type: str,
        target: str,
        cleanup_action: str = "delete",
        owner: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> SideEffect:
        effect = SideEffect(
            effect_id=f"eff-{uuid.uuid4().hex[:16]}",
            step_id=step_id,
            resource_type=resource_type,
            target=str(target),
            action_plan_id=self.plan_id,
            engagement_id=self.engagement_id,
            owner=owner or self.default_owner,
            created_at=utc_now(),
            cleanup_action=cleanup_action,
            status="pending",
            metadata=dict(metadata) if metadata is not None else {},
        )
        if self.journal is not None:
            self.journal.record_effect(self.run_id, effect)
        self._effects.append(effect)
        return effect

    def get_effects(self, status: str | None = None) -> list[SideEffect]:
        if status is None:
            return list(self._effects)
        return [effect for effect in self._effects if effect.status == status]

    def transition_effect(
        self,
        effect: SideEffect,
        status: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Persist an effect transition before exposing it in memory."""
        if effect not in self._effects:
            raise CleanupPersistenceError("cannot transition an effect outside this ledger")
        if self.journal is not None:
            self.journal.transition(self.run_id, effect, status, details=details)
        effect.status = status


class CleanupManager:
    """Manage verified rollback and persist deterministic cleanup receipts."""

    def __init__(
        self,
        ledger: SideEffectLedger,
        worker_identity: str,
        workspace_dir: Path | None = None,
    ) -> None:
        self.ledger = ledger
        self.worker_identity = worker_identity
        self.workspace_dir = Path(os.path.abspath(os.fspath(workspace_dir))) if workspace_dir else None

    def _verify_resource_ownership(self, effect: SideEffect) -> int | None:
        if effect.owner != self.worker_identity:
            raise CleanupOwnershipError(
                f"Resource '{effect.target}' owned by '{effect.owner}', not worker '{self.worker_identity}'"
            )
        if effect.resource_type in ("file", "directory"):
            target_path = Path(os.path.abspath(effect.target))
            if self.workspace_dir is not None:
                try:
                    target_path.relative_to(self.workspace_dir)
                except ValueError as err:
                    scratch_root = Path(tempfile.gettempdir()).resolve(strict=True)
                    is_credential_scratch = (
                        effect.resource_type == "directory"
                        and effect.metadata.get("purpose") == "credential_operation_scratch"
                        and target_path.parent == scratch_root
                        and target_path.name.startswith("cops-credential-operation-")
                    )
                    if not is_credential_scratch:
                        raise CleanupOwnershipError(
                            f"Resource path '{target_path}' is outside worker workspace '{self.workspace_dir}'"
                        ) from err
            try:
                parent_fd = open_directory_no_symlinks(target_path.parent)
            except (OSError, SecureDirectoryError) as err:
                raise CleanupOwnershipError(
                    f"Resource parent for '{target_path}' cannot be verified without following symbolic links"
                ) from err
            return parent_fd
        return None

    @staticmethod
    def _unresolved(effect: SideEffect, reason: str) -> dict[str, Any]:
        return {
            "effect_id": effect.effect_id,
            "resource_type": effect.resource_type,
            "target": effect.target,
            "reason": reason,
        }

    def _transition(
        self,
        effect: SideEffect,
        status: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.ledger.transition_effect(effect, status, details=details)

    def _execute_cleanup(self, effect: SideEffect, *, parent_fd: int | None = None) -> str:
        if effect.resource_type == "file":
            path = Path(os.path.abspath(effect.target))
            if parent_fd is None:
                raise CleanupError(f"file parent for '{path}' was not verified")
            try:
                target_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return "deleted_file"
            if stat.S_ISLNK(target_stat.st_mode):
                raise CleanupError(f"file '{path}' changed to a symbolic link before unlink")
            if not stat.S_ISREG(target_stat.st_mode):
                raise CleanupError(f"file '{path}' changed type before unlink")
            os.unlink(path.name, dir_fd=parent_fd)
            try:
                os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CleanupError(f"file '{path}' still exists after unlink")
            return "deleted_file"
        if effect.resource_type == "directory":
            path = Path(os.path.abspath(effect.target))
            if parent_fd is None:
                raise CleanupError(f"directory parent for '{path}' was not verified")
            try:
                target_stat = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return "deleted_directory"
            if stat.S_ISLNK(target_stat.st_mode):
                raise CleanupError(f"directory '{path}' changed to a symbolic link before rmtree")
            if stat.S_ISDIR(target_stat.st_mode):
                shutil.rmtree(path.name, ignore_errors=False, dir_fd=parent_fd)
            else:
                raise CleanupError(f"directory '{path}' changed type before rmtree")
            try:
                os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CleanupError(f"directory '{path}' still exists after rmtree")
            return "deleted_directory"
        if effect.resource_type == "process":
            pid = int(effect.target)
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            except PermissionError as err:
                raise CleanupError(f"permission denied killing PID {pid}") from err
            return "terminated_process"
        return f"custom_reverted_{effect.cleanup_action}"

    def _build_receipt(
        self,
        *,
        created_at: str,
        cleaned_effects: list[dict[str, Any]],
        unresolved_effects: list[dict[str, Any]],
    ) -> CleanupReceipt:
        receipt_id = f"cln-{uuid.uuid4().hex[:16]}"
        if unresolved_effects:
            status = "partial" if cleaned_effects else "failed"
        elif cleaned_effects:
            status = "completed"
        else:
            status = "not_required"
        payload = {
            "receipt_id": receipt_id,
            "plan_id": self.ledger.plan_id,
            "engagement_id": self.ledger.engagement_id,
            "worker_identity": self.worker_identity,
            "cleaned_effects": cleaned_effects,
            "unresolved_effects": unresolved_effects,
        }
        return CleanupReceipt.from_dict(
            {
                "schema_version": "cops.cleanup-receipt/v1",
                **payload,
                "status": status,
                "created_at": created_at,
                "completed_at": utc_now(),
                "evidence_hash": digest(payload),
            }
        )

    def rollback(self, *, dry_run: bool = False, recovered: bool = False) -> CleanupReceipt:
        """Roll back pending effects, preserving unknown outcomes across restart."""
        created_at = utc_now()
        cleaned_effects: list[dict[str, Any]] = []
        unresolved_effects: list[dict[str, Any]] = []

        for effect in reversed(self.ledger.get_effects()):
            if effect.status == "cleaned":
                continue
            if effect.status in {"failed", "unknown"}:
                unresolved_effects.append(self._unresolved(effect, f"cleanup outcome remains {effect.status}"))
                continue
            if effect.status == "cleaning":
                try:
                    self._transition(
                        effect,
                        "unknown",
                        details={"reason": "worker restart interrupted cleanup"},
                    )
                except CleanupPersistenceError as err:
                    effect.status = "unknown"
                    unresolved_effects.append(self._unresolved(effect, f"cleanup state persistence failed: {err}"))
                    continue
                unresolved_effects.append(self._unresolved(effect, "cleanup may have completed before worker restart"))
                continue
            if effect.metadata.get(PLAN_DECLARED_PROVENANCE_KEY) == PLAN_DECLARED_PROVENANCE_UNVERIFIED:
                reason = "plan cleanup declaration does not establish worker ownership; cleanup target was preserved"
                try:
                    self._transition(effect, "unknown", details={"reason": reason})
                except CleanupPersistenceError as err:
                    effect.status = "unknown"
                    unresolved_effects.append(self._unresolved(effect, f"cleanup state persistence failed: {err}"))
                    continue
                unresolved_effects.append(self._unresolved(effect, reason))
                continue
            if recovered and effect.resource_type == "process":
                try:
                    self._transition(
                        effect,
                        "unknown",
                        details={"reason": "process identity cannot be verified after worker restart"},
                    )
                except CleanupPersistenceError as err:
                    effect.status = "unknown"
                    unresolved_effects.append(self._unresolved(effect, f"cleanup state persistence failed: {err}"))
                    continue
                unresolved_effects.append(
                    self._unresolved(effect, "process PID ownership cannot be verified after worker restart")
                )
                continue
            if dry_run:
                cleaned_effects.append(
                    {
                        "effect_id": effect.effect_id,
                        "resource_type": effect.resource_type,
                        "target": effect.target,
                        "action_taken": f"dry_run_{effect.cleanup_action}",
                    }
                )
                continue

            parent_fd: int | None = None
            action_started = False
            try:
                parent_fd = self._verify_resource_ownership(effect)
                self._transition(effect, "cleaning")
                action_started = True
                action_taken = self._execute_cleanup(effect, parent_fd=parent_fd)
                try:
                    self._transition(effect, "cleaned", details={"action_taken": action_taken})
                except CleanupPersistenceError as err:
                    effect.status = "unknown"
                    unresolved_effects.append(
                        self._unresolved(
                            effect,
                            f"resource action completed but cleanup state persistence failed: {err}",
                        )
                    )
                    continue
                cleaned_effects.append(
                    {
                        "effect_id": effect.effect_id,
                        "resource_type": effect.resource_type,
                        "target": effect.target,
                        "action_taken": action_taken,
                    }
                )
            except Exception as err:
                terminal_status = "unknown" if action_started else "failed"
                try:
                    self._transition(effect, terminal_status, details={"reason": str(err)})
                    reason = (
                        f"cleanup outcome unknown after resource action started: {err}"
                        if action_started
                        else f"cleanup failed: {err}"
                    )
                except CleanupPersistenceError as persistence_error:
                    effect.status = "unknown"
                    reason = f"cleanup failed and state persistence failed: {err}; {persistence_error}"
                unresolved_effects.append(self._unresolved(effect, reason))
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)

        receipt = self._build_receipt(
            created_at=created_at,
            cleaned_effects=cleaned_effects,
            unresolved_effects=unresolved_effects,
        )
        if self.ledger.journal is None or dry_run:
            return receipt
        try:
            self.ledger.journal.record_receipt(self.ledger.run_id, receipt)
            return receipt
        except CleanupPersistenceError as err:
            unresolved_effects.append(
                {
                    "effect_id": f"audit-{self.ledger.run_id}",
                    "resource_type": "cleanup_journal",
                    "target": str(self.ledger.journal.path),
                    "reason": f"cleanup receipt persistence failed: {err}",
                }
            )
            return self._build_receipt(
                created_at=created_at,
                cleaned_effects=cleaned_effects,
                unresolved_effects=unresolved_effects,
            )
