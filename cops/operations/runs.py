"""Private transactional local run ledger; locks never span handler execution."""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from cops._filesystem import open_directory_no_symlinks
from cops._schema_validation import validate
from cops.evidence.canonical import digest as evidence_digest

from .catalog import OFFLINE_OPERATION_IDS
from .contracts import MAX_BYTES, OperationError, decode, encode

_ALIAS_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
TERMINAL = {"succeeded", "cancelled", "failed", "partial"}
RUN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "run_id",
        "operation_id",
        "request",
        "request_digest",
        "binding_digest",
        "expected_binding",
        "state",
        "attempt",
        "cancellation_requested",
        "lease_token",
        "lease_until",
        "operation_result",
        "evidence_refs",
        "recovery_actions",
        "accepted_at",
        "updated_at",
    ],
    "properties": {
        "schema_version": {"const": "cops.operation-run/v1"},
        "run_id": {"type": "string", "pattern": "^run-[0-9a-f]{32}$"},
        "operation_id": {"type": "string", "maxLength": 96, "pattern": r"^cops\.(assess|soc|work)\."},
        "request": {"type": "object"},
        "request_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "binding_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "expected_binding": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "state": {"enum": ["cancelled", "failed", "partial", "queued", "running", "succeeded"]},
        "attempt": {"type": "integer", "minimum": 0},
        "cancellation_requested": {"type": "boolean"},
        "lease_token": {"type": ["string", "null"], "maxLength": 32},
        "lease_until": {"type": ["number", "null"]},
        "lease_expires_at": {"type": ["number", "null"]},
        "operation_result": {"type": ["object", "null"]},
        "error": {"type": ["object", "null"]},
        "evidence_refs": {"type": "array", "maxItems": 4096, "items": {"type": "string", "maxLength": 512}},
        "recovery_actions": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 96}},
        "accepted_at": {"type": "number"},
        "updated_at": {"type": "number"},
        "idempotency_key": {"type": "string", "maxLength": 96},
        "metadata": {"type": "object"},
    },
}


def alias(value):
    if not isinstance(value, str) or not _ALIAS_RE.fullmatch(value):
        raise OperationError("invalid_alias")
    return value


def digest(value, **limits):
    return evidence_digest(value, **limits)


def require_offline(operation_id):
    if operation_id not in OFFLINE_OPERATION_IDS:
        raise OperationError("offline_run_required")


def _require_offline_record(record):
    require_offline(record["operation_id"])
    if (
        record.get("controlled", False) is not False
        or record.get("kind", "pure") != "pure"
        or record.get("authorization_id") is not None
        or record.get("plan_ref") is not None
        or record.get("remote_observation") is not None
        or record.get("remote_error") is not None
        or record["state"] in {"uncertain", "approval_required"}
    ):
        raise OperationError("offline_run_required")

    # Pre-release offline records can still be read. Inert legacy fields
    # are removed from the in-memory record and from its next persisted update.
    return {
        key: value
        for key, value in record.items()
        if key
        not in {
            "controlled",
            "kind",
            "authorization_id",
            "plan_ref",
            "remote_observation",
            "remote_error",
        }
    }


class RunStore:
    """One connection per transaction supports competing threads and processes.

    A constructor argument is always a state directory. The database name is
    stable whether or not that directory already exists. State is not protected
    against its own administrator, who can replace files after these checks.
    """

    def __init__(self, path, *, clock=None, lease_seconds=120, max_records=64):
        self.path = Path(path).expanduser().absolute() / "private-run-state"
        self.clock = clock or time.time
        self.lease_seconds, self.max_records = lease_seconds, max_records
        with self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, "
                "document BLOB NOT NULL, checksum TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS delegations (id TEXT PRIMARY KEY, "
                "document BLOB NOT NULL, checksum TEXT NOT NULL)"
            )

    def _prepare_path(self):
        if os.name != "posix":
            raise OperationError("runtime_not_supported")
        descriptor = -1
        try:
            descriptor = open_directory_no_symlinks(self.path.parent, create=True)
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise OperationError("unsafe_state")
            try:
                fd = os.open(
                    self.path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=descriptor
                )
            except FileExistsError:
                pass
            else:
                os.close(fd)
            for suffix in ("", "-journal", "-wal", "-shm"):
                try:
                    info = os.stat(self.path.name + suffix, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if suffix:
                        continue
                    raise
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                ):
                    raise OperationError("unsafe_state")
        except OSError as exc:
            raise OperationError("unsafe_state") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @contextmanager
    def _transaction(self):
        self._prepare_path()
        connection = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA max_page_count=262144")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _decode(row):
        raw, checksum = row
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise OperationError("corrupt_state")
        return decode(raw)

    def _read(self, connection, run_id):
        row = connection.execute("SELECT document, checksum FROM runs WHERE run_id=?", (alias(run_id),)).fetchone()
        if row is None:
            raise OperationError("run_not_found")
        record = _require_offline_record(self._decode(row))
        validate(record, RUN_SCHEMA)
        return record

    def _write(self, connection, record):
        record["updated_at"] = self.clock()
        validate(record, RUN_SCHEMA)
        raw = encode(record)
        connection.execute(
            "INSERT INTO runs VALUES (?,?,?) ON CONFLICT(run_id) DO UPDATE SET "
            "document=excluded.document, checksum=excluded.checksum",
            (record["run_id"], raw, hashlib.sha256(raw).hexdigest()),
        )
        return record

    def get(self, run_id):
        with self._transaction() as connection:
            return self._read(connection, run_id)

    status = get

    def create(self, *, operation_id, request, expected_binding, idempotency_key=None):
        require_offline(operation_id)
        if len(encode(request)) > 2 * 1024 * 1024:
            raise OperationError("size_limit")
        comparable = dict(request)
        comparable.pop("request_id", None)
        identity = {
            "operation_id": operation_id,
            "request": comparable,
            "kind": "pure",
            "plan_ref": None,
            "binding": expected_binding,
        }
        request_digest = digest(identity)
        key = idempotency_key or request_digest
        with self._transaction() as connection:
            for row in connection.execute("SELECT document,checksum FROM runs").fetchall():
                record = self._decode(row)
                if record.get("idempotency_key") == key:
                    record = _require_offline_record(record)
                    validate(record, RUN_SCHEMA)
                    if record["request_digest"] != request_digest:
                        raise OperationError("idempotency_conflict")
                    return record
            self._capacity(connection)
            record = {
                "schema_version": "cops.operation-run/v1",
                "run_id": "run-" + uuid.uuid4().hex,
                "operation_id": operation_id,
                "request": request,
                "request_digest": request_digest,
                "idempotency_key": key,
                "binding_digest": expected_binding,
                "expected_binding": expected_binding,
                "state": "queued",
                "attempt": 0,
                "operation_result": None,
                "error": None,
                "evidence_refs": [],
                "cancellation_requested": False,
                "recovery_actions": [],
                "lease_token": None,
                "lease_expires_at": None,
                "lease_until": None,
                "accepted_at": self.clock(),
                "metadata": {},
            }
            return self._write(connection, record)

    def _capacity(self, connection):
        count = (
            connection.execute("SELECT count(*) FROM runs").fetchone()[0]
            + connection.execute("SELECT count(*) FROM delegations").fetchone()[0]
        )
        if count >= self.max_records:
            raise OperationError("state_capacity_exhausted")

    def _recover(self, connection, record):
        if record["lease_token"] is not None and record["state"] not in TERMINAL:
            if self.clock() < record["lease_expires_at"]:
                raise OperationError("run_busy")
            if record["state"] == "running":
                if record["cancellation_requested"]:
                    record.update(state="cancelled", operation_result=None, evidence_refs=[], recovery_actions=[])
                else:
                    record["state"] = "queued"
            record.update(lease_token=None, lease_expires_at=None, lease_until=None)
            self._write(connection, record)
        return record

    def recover(self, run_id):
        with self._transaction() as connection:
            return self._recover(connection, self._read(connection, run_id))

    def claim(self, run_id):
        with self._transaction() as connection:
            record = self._recover(connection, self._read(connection, run_id))
            if record["state"] not in TERMINAL:
                deadline = self.clock() + self.lease_seconds
                record.update(
                    state="running",
                    attempt=record["attempt"] + 1,
                    lease_token=uuid.uuid4().hex,
                    lease_expires_at=deadline,
                    lease_until=deadline,
                )
                return self._write(connection, record)
        # Commit any terminal recovery before rejecting the new claim.
        raise OperationError("run_terminal")

    def finish(self, run_id, lease_token, state, result=None, error=None):
        if result is not None and len(encode(result)) > MAX_BYTES // 2:
            raise OperationError("result_size_limit")
        with self._transaction() as connection:
            record = self._read(connection, run_id)
            if record["state"] in TERMINAL:
                return record
            if not lease_token or record["lease_token"] != lease_token:
                raise OperationError("stale_attempt")
            if record["cancellation_requested"]:
                state, result, error = "cancelled", None, None
            record.update(
                state=state,
                operation_result=result,
                error=error,
                evidence_refs=[],
                lease_token=None,
                lease_expires_at=None,
                lease_until=None,
                recovery_actions=[],
            )
            return self._write(connection, record)

    def cancel(self, run_id):
        with self._transaction() as connection:
            record = self._read(connection, run_id)
            record["cancellation_requested"] = True
            if record["state"] == "queued":
                record["state"] = "cancelled"
            return self._write(connection, record)

    def put_delegation(self, document):
        with self._transaction() as connection:
            self._capacity(connection)
            raw = encode(document)
            connection.execute(
                "INSERT INTO delegations VALUES (?,?,?)",
                (document["delegation_id"], raw, hashlib.sha256(raw).hexdigest()),
            )

    def get_delegation(self, identifier):
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT document,checksum FROM delegations WHERE id=?", (alias(identifier),)
            ).fetchone()
            if row is None:
                raise OperationError("delegation_not_found")
            return self._decode(row)

    def accept_delegation(self, identifier, expected, peer):
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT document,checksum FROM delegations WHERE id=?", (alias(identifier),)
            ).fetchone()
            if row is None:
                raise OperationError("delegation_not_found")
            document = self._decode(row)
            if document["state"] != "prepared":
                raise OperationError("delegation_replayed")
            if document["binding_digest"] != expected:
                raise OperationError("delegation_binding_changed")
            document.update(state="accepted", peer_response=peer)
            raw = encode(document)
            connection.execute(
                "UPDATE delegations SET document=?,checksum=? WHERE id=?",
                (raw, hashlib.sha256(raw).hexdigest(), identifier),
            )
            return document
