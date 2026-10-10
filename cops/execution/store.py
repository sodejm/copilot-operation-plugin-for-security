"""Isolated approval state store for COPS execution worker runtime.

Provides concurrency-safe, tamper-evident SQLite storage for operator-authenticated
execution authorizations, enforcing atomic consumption, lease tracking, and anti-replay.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from cops.contracts.models import ExecutionAuthorization
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import canonical, digest, timestamp, utc_now


@dataclass(frozen=True)
class LegacyApprovalRecord:
    """Read-only historical approval row that cannot authorize execution."""

    authorization_id: str
    action_plan_id: str
    plan_digest: str
    engagement_id: str
    operator: str
    historical_status: str
    issued_at: str
    authorized_until_utc: str
    bound_parameters: dict
    approval_mode: str
    signature_algorithm: str
    signing_key_id: str
    signature_digest: str
    consumed_at: str | None = None
    consumed_by_worker: str | None = None

    @property
    def status(self) -> str:
        return "legacy-untrusted"

    def to_dict(self) -> dict:
        return {
            "record_type": "legacy-untrusted",
            "authorization_id": self.authorization_id,
            "action_plan_id": self.action_plan_id,
            "plan_digest": self.plan_digest,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "status": self.status,
            "historical_status": self.historical_status,
            "issued_at": self.issued_at,
            "authorized_until_utc": self.authorized_until_utc,
            "bound_parameters": self.bound_parameters,
            "approval_mode": self.approval_mode,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "signature_digest": self.signature_digest,
            "consumed_at": self.consumed_at,
            "consumed_by_worker": self.consumed_by_worker,
        }


@dataclass(frozen=True)
class ApprovalConsumptionRecord:
    """Durable result of one idempotent approval-control request."""

    request_id: str
    request_digest: str
    authorization_id: str
    authorization_digest: str
    action_plan_id: str
    plan_digest: str
    engagement_id: str
    worker_identity: str
    target: str
    created_at: str


class ApprovalStoreError(ValueError):
    """Base error for approval store operations."""


class ApprovalStoreNotFoundError(ApprovalStoreError):
    """Requested approval envelope not found in the store."""


class ApprovalStoreAccessError(ApprovalStoreError):
    """Approval store permissions or directory security checks failed."""


class ApprovalStoreConflictError(ApprovalStoreError):
    """Approval envelope already consumed, expired, or locked by another worker."""


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS approvals (
    authorization_id TEXT PRIMARY KEY,
    action_plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    status TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    authorized_until_utc TEXT NOT NULL,
    bound_parameters_json TEXT NOT NULL,
    approval_mode TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature_digest TEXT NOT NULL,
    legacy_status TEXT,
    consumed_at TEXT,
    consumed_by_worker TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_plan ON approvals(action_plan_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS approval_consumptions (
    request_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    authorization_id TEXT NOT NULL UNIQUE,
    authorization_digest TEXT NOT NULL,
    action_plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    worker_identity TEXT NOT NULL,
    target TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (authorization_id) REFERENCES approvals(authorization_id)
);

CREATE INDEX IF NOT EXISTS idx_approval_consumptions_authorization
    ON approval_consumptions(authorization_id);
"""


class ApprovalStore:
    """Concurrency-safe, ACID-compliant approval state store backed by SQLite."""

    def __init__(self, db_path: Path | str, *, require_secure_perms: bool = True) -> None:
        source = Path(db_path).expanduser()
        self.db_path = source if source.is_absolute() else Path.cwd() / source
        self.require_secure_perms = require_secure_perms
        self._ensure_storage_security()
        self._prepare_database_file()
        self._init_db()

    def _ensure_storage_security(self) -> None:
        """Verify storage directory exists and has safe permissions (owner-only on POSIX)."""
        parent_dir = self.db_path.parent
        existed_before = parent_dir.exists()
        parent_dir.mkdir(parents=True, exist_ok=True)

        if os.name == "posix" and self.require_secure_perms:
            try:
                # If directory was just created by us, set 0700
                if not existed_before:
                    try:
                        parent_dir.chmod(0o700)
                    except OSError:
                        pass

                # Never follow an attacker-controlled store directory or database.
                p_stat = os.lstat(parent_dir)
                if not stat.S_ISDIR(p_stat.st_mode):
                    raise ApprovalStoreAccessError(f"approval store directory '{parent_dir}' is not a directory")
                if p_stat.st_uid != os.geteuid():
                    raise ApprovalStoreAccessError(
                        f"approval store directory '{parent_dir}' is not owned by the current account"
                    )
                if stat.S_IMODE(p_stat.st_mode) != 0o700:
                    # Reject insecure pre-existing directory rather than chmoding arbitrary caller directory
                    raise ApprovalStoreAccessError(
                        f"approval store directory '{parent_dir}' has insecure permissions {oct(stat.S_IMODE(p_stat.st_mode))}: "
                        "must be owner-only (0700); use a private directory"
                    )

                if os.path.lexists(self.db_path):
                    db_stat = os.lstat(self.db_path)
                    if not stat.S_ISREG(db_stat.st_mode):
                        raise ApprovalStoreAccessError(
                            f"approval store database file '{self.db_path}' is not a regular file"
                        )
                    if db_stat.st_uid != os.geteuid():
                        raise ApprovalStoreAccessError(
                            f"approval store database file '{self.db_path}' is not owned by the current account"
                        )
                    if stat.S_IMODE(db_stat.st_mode) != 0o600:
                        raise ApprovalStoreAccessError(
                            f"approval store database file '{self.db_path}' has insecure permissions: "
                            f"{oct(stat.S_IMODE(db_stat.st_mode))}; expected 0o600"
                        )
            except OSError as err:
                raise ApprovalStoreAccessError(f"failed to secure approval store permissions: {err}") from err

    def _prepare_database_file(self) -> None:
        """Create a new database at 0600 without repairing an existing file."""
        if os.name != "posix" or not self.require_secure_perms or os.path.lexists(self.db_path):
            return
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.db_path, flags, 0o600)
        except FileExistsError:
            # A concurrent replacement must pass the same strict checks.
            self._ensure_storage_security()
            return
        except OSError as err:
            raise ApprovalStoreAccessError(f"failed to create protected approval store: {err}") from err
        else:
            os.close(fd)

    def assert_protected_owner(self, expected_uid: int) -> None:
        """Fail closed unless the database and all SQLite files are authority-owned."""
        if os.name != "posix" or not self.require_secure_perms:
            raise ApprovalStoreAccessError("protected approval storage requires POSIX permission checks")
        expected = (
            (self.db_path.parent, stat.S_IFDIR, 0o700, "directory"),
            (self.db_path, stat.S_IFREG, 0o600, "database"),
            (Path(f"{self.db_path}-wal"), stat.S_IFREG, 0o600, "WAL sidecar"),
            (Path(f"{self.db_path}-shm"), stat.S_IFREG, 0o600, "shared-memory sidecar"),
        )
        for path, file_type, required_mode, label in expected:
            if label.endswith("sidecar") and not os.path.lexists(path):
                continue
            try:
                file_stat = os.lstat(path)
            except OSError as err:
                raise ApprovalStoreAccessError(f"approval store {label} is unavailable: {err}") from err
            if stat.S_IFMT(file_stat.st_mode) != file_type:
                raise ApprovalStoreAccessError(f"approval store {label} must not be a link or special file")
            if file_stat.st_uid != expected_uid:
                raise ApprovalStoreAccessError(f"approval store {label} is not owned by the authority UID")
            actual_mode = stat.S_IMODE(file_stat.st_mode)
            if actual_mode != required_mode:
                raise ApprovalStoreAccessError(
                    f"approval store {label} permissions are {oct(actual_mode)}; expected {oct(required_mode)}"
                )

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,  # autocommit mode, explicit transactions
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.execute("BEGIN IMMEDIATE")
            try:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(approvals)")}
                legacy_database = "signature_algorithm" not in columns or "signing_key_id" not in columns
                if "signature_algorithm" not in columns:
                    conn.execute(
                        "ALTER TABLE approvals ADD COLUMN signature_algorithm TEXT NOT NULL DEFAULT 'legacy-untrusted'"
                    )
                if "signing_key_id" not in columns:
                    conn.execute("ALTER TABLE approvals ADD COLUMN signing_key_id TEXT NOT NULL DEFAULT ''")
                if "legacy_status" not in columns:
                    conn.execute("ALTER TABLE approvals ADD COLUMN legacy_status TEXT")
                if legacy_database:
                    conn.execute("UPDATE approvals SET legacy_status = status, status = 'legacy-untrusted'")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        if os.name == "posix" and self.require_secure_perms:
            self.assert_protected_owner(os.geteuid())

    def store_authorization(self, auth: ExecutionAuthorization) -> None:
        """Store a newly signed execution authorization."""
        doc = auth.to_dict()
        validate_contract(doc, "execution_authorization")

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    INSERT INTO approvals (
                        authorization_id, action_plan_id, plan_digest, engagement_id,
                        operator, status, issued_at, authorized_until_utc,
                        bound_parameters_json, approval_mode, signature_algorithm,
                        signing_key_id, signature_digest,
                        consumed_at, consumed_by_worker, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        auth.authorization_id,
                        auth.action_plan_id,
                        auth.plan_digest,
                        auth.engagement_id,
                        auth.operator,
                        auth.status,
                        auth.issued_at,
                        auth.authorized_until_utc,
                        canonical(doc["bound_parameters"]),
                        auth.approval_mode,
                        auth.signature_algorithm,
                        auth.signing_key_id,
                        auth.signature_digest,
                        auth.consumed_at,
                        auth.consumed_by_worker,
                        utc_now(),
                    ),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError as err:
                conn.execute("ROLLBACK")
                raise ApprovalStoreConflictError(
                    f"authorization '{auth.authorization_id}' already exists in approval store"
                ) from err
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def get_authorization(self, authorization_id: str) -> ExecutionAuthorization | LegacyApprovalRecord:
        """Retrieve an authorization envelope by ID."""
        import json

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT authorization_id, action_plan_id, plan_digest, engagement_id,
                       operator, status, issued_at, authorized_until_utc,
                       bound_parameters_json, approval_mode, signature_algorithm,
                       signing_key_id, signature_digest, legacy_status,
                       consumed_at, consumed_by_worker
                FROM approvals WHERE authorization_id = ?
                """,
                (authorization_id,),
            )
            row = cur.fetchone()
            if row is None:
                raise ApprovalStoreNotFoundError(f"authorization '{authorization_id}' not found in store")

            doc = {
                "schema_version": "cops.execution-authorization/v1",
                "authorization_id": row["authorization_id"],
                "action_plan_id": row["action_plan_id"],
                "plan_digest": row["plan_digest"],
                "engagement_id": row["engagement_id"],
                "operator": row["operator"],
                "status": row["status"],
                "issued_at": row["issued_at"],
                "authorized_until_utc": row["authorized_until_utc"],
                "bound_parameters": json.loads(row["bound_parameters_json"]),
                "approval_mode": row["approval_mode"],
                "signature_algorithm": row["signature_algorithm"],
                "signing_key_id": row["signing_key_id"],
                "signature_digest": row["signature_digest"],
            }
            if row["consumed_at"]:
                doc["consumed_at"] = row["consumed_at"]
            if row["consumed_by_worker"]:
                doc["consumed_by_worker"] = row["consumed_by_worker"]

            if row["status"] == "legacy-untrusted":
                return LegacyApprovalRecord(
                    authorization_id=row["authorization_id"],
                    action_plan_id=row["action_plan_id"],
                    plan_digest=row["plan_digest"],
                    engagement_id=row["engagement_id"],
                    operator=row["operator"],
                    historical_status=row["legacy_status"] or "unknown",
                    issued_at=row["issued_at"],
                    authorized_until_utc=row["authorized_until_utc"],
                    bound_parameters=json.loads(row["bound_parameters_json"]),
                    approval_mode=row["approval_mode"],
                    signature_algorithm=row["signature_algorithm"],
                    signing_key_id=row["signing_key_id"],
                    signature_digest=row["signature_digest"],
                    consumed_at=row["consumed_at"],
                    consumed_by_worker=row["consumed_by_worker"],
                )
            return ExecutionAuthorization.from_dict(doc)

    @staticmethod
    def _consumption_record(row: sqlite3.Row) -> ApprovalConsumptionRecord:
        return ApprovalConsumptionRecord(
            request_id=row["request_id"],
            request_digest=row["request_digest"],
            authorization_id=row["authorization_id"],
            authorization_digest=row["authorization_digest"],
            action_plan_id=row["action_plan_id"],
            plan_digest=row["plan_digest"],
            engagement_id=row["engagement_id"],
            worker_identity=row["worker_identity"],
            target=row["target"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _assert_matching_consumption(
        record: ApprovalConsumptionRecord,
        *,
        request_digest: str,
        authorization_id: str,
        action_plan_id: str,
        plan_digest: str,
        engagement_id: str,
        worker_identity: str,
        target: str,
    ) -> None:
        expected = (
            request_digest,
            authorization_id,
            action_plan_id,
            plan_digest,
            engagement_id,
            worker_identity,
            target,
        )
        actual = (
            record.request_digest,
            record.authorization_id,
            record.action_plan_id,
            record.plan_digest,
            record.engagement_id,
            record.worker_identity,
            record.target,
        )
        if actual != expected:
            raise ApprovalStoreConflictError(
                f"approval request_id '{record.request_id}' was already used for a different request"
            )

    def get_matching_consumption(
        self,
        request_id: str,
        *,
        request_digest: str,
        authorization_id: str,
        action_plan_id: str,
        plan_digest: str,
        engagement_id: str,
        worker_identity: str,
        target: str,
    ) -> ApprovalConsumptionRecord | None:
        """Return the durable receipt for an exact retry, rejecting altered reuse."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM approval_consumptions WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        record = self._consumption_record(row)
        self._assert_matching_consumption(
            record,
            request_digest=request_digest,
            authorization_id=authorization_id,
            action_plan_id=action_plan_id,
            plan_digest=plan_digest,
            engagement_id=engagement_id,
            worker_identity=worker_identity,
            target=target,
        )
        return record

    def atomically_consume_request(
        self,
        request_id: str,
        *,
        request_digest: str,
        target: str,
        expected_authorization: ExecutionAuthorization,
        worker_identity: str,
        expected_authority_uid: int,
        current_time_iso: str | None = None,
    ) -> ApprovalConsumptionRecord:
        """Consume approval and persist its exact request and receipt in one transaction."""
        import json

        authorization_id = expected_authorization.authorization_id
        now_str = current_time_iso or utc_now()
        now_dt = timestamp(now_str)

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                prior_row = conn.execute(
                    "SELECT * FROM approval_consumptions WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if prior_row is not None:
                    prior = self._consumption_record(prior_row)
                    self._assert_matching_consumption(
                        prior,
                        request_digest=request_digest,
                        authorization_id=authorization_id,
                        action_plan_id=expected_authorization.action_plan_id,
                        plan_digest=expected_authorization.plan_digest,
                        engagement_id=expected_authorization.engagement_id,
                        worker_identity=worker_identity,
                        target=target,
                    )
                    conn.execute("COMMIT")
                    committed = True
                    return prior

                row = conn.execute(
                    """
                    SELECT authorization_id, action_plan_id, plan_digest, engagement_id,
                           operator, status, issued_at, authorized_until_utc,
                           bound_parameters_json, approval_mode, signature_algorithm,
                           signing_key_id, signature_digest, legacy_status,
                           consumed_at, consumed_by_worker
                    FROM approvals WHERE authorization_id = ?
                    """,
                    (authorization_id,),
                ).fetchone()
                if row is None:
                    raise ApprovalStoreNotFoundError(f"authorization '{authorization_id}' not found in store")
                if row["status"] != "approved":
                    raise ApprovalStoreConflictError(
                        f"cannot consume authorization '{authorization_id}': status is '{row['status']}' "
                        "(already consumed or revoked)"
                    )

                doc = {
                    "schema_version": "cops.execution-authorization/v1",
                    "authorization_id": row["authorization_id"],
                    "action_plan_id": row["action_plan_id"],
                    "plan_digest": row["plan_digest"],
                    "engagement_id": row["engagement_id"],
                    "operator": row["operator"],
                    "status": row["status"],
                    "issued_at": row["issued_at"],
                    "authorized_until_utc": row["authorized_until_utc"],
                    "bound_parameters": json.loads(row["bound_parameters_json"]),
                    "approval_mode": row["approval_mode"],
                    "signature_algorithm": row["signature_algorithm"],
                    "signing_key_id": row["signing_key_id"],
                    "signature_digest": row["signature_digest"],
                }
                if canonical(doc) != canonical(expected_authorization.to_dict()):
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' differs from the verified receipt"
                    )
                if doc["bound_parameters"].get("worker_identity") != worker_identity:
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' is bound to a different worker"
                    )
                if now_dt < timestamp(row["issued_at"]):
                    raise ApprovalStoreConflictError(f"authorization '{authorization_id}' is not yet valid")
                if now_dt >= timestamp(row["authorized_until_utc"]):
                    conn.execute(
                        "UPDATE approvals SET status = 'expired' WHERE authorization_id = ?",
                        (authorization_id,),
                    )
                    self.assert_protected_owner(expected_authority_uid)
                    conn.execute("COMMIT")
                    committed = True
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' expired at {row['authorized_until_utc']}"
                    )

                updated = conn.execute(
                    """
                    UPDATE approvals
                    SET status = 'consumed', consumed_at = ?, consumed_by_worker = ?
                    WHERE authorization_id = ? AND status = 'approved'
                    """,
                    (now_str, worker_identity, authorization_id),
                )
                if updated.rowcount != 1:
                    raise ApprovalStoreConflictError(f"authorization '{authorization_id}' could not be consumed")

                doc.update(
                    status="consumed",
                    consumed_at=now_str,
                    consumed_by_worker=worker_identity,
                )
                consumed = ExecutionAuthorization.from_dict(doc)
                record = ApprovalConsumptionRecord(
                    request_id=request_id,
                    request_digest=request_digest,
                    authorization_id=authorization_id,
                    authorization_digest=digest(consumed.to_dict()),
                    action_plan_id=consumed.action_plan_id,
                    plan_digest=consumed.plan_digest,
                    engagement_id=consumed.engagement_id,
                    worker_identity=worker_identity,
                    target=target,
                    created_at=now_str,
                )
                conn.execute(
                    """
                    INSERT INTO approval_consumptions (
                        request_id, request_digest, authorization_id,
                        authorization_digest, action_plan_id, plan_digest,
                        engagement_id, worker_identity, target, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.request_id,
                        record.request_digest,
                        record.authorization_id,
                        record.authorization_digest,
                        record.action_plan_id,
                        record.plan_digest,
                        record.engagement_id,
                        record.worker_identity,
                        record.target,
                        record.created_at,
                    ),
                )
                # Validate the protected-store postcondition while the write
                # transaction is still rollback-capable.
                self.assert_protected_owner(expected_authority_uid)
                conn.execute("COMMIT")
                committed = True
                return record
            except sqlite3.IntegrityError as err:
                if not committed:
                    conn.execute("ROLLBACK")
                raise ApprovalStoreConflictError(
                    "approval consumption request conflicts with an existing receipt"
                ) from err
            except Exception:
                if not committed:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise

    def atomically_consume(
        self,
        authorization_id: str,
        *,
        expected_authorization: ExecutionAuthorization,
        worker_identity: str,
        current_time_iso: str | None = None,
    ) -> ExecutionAuthorization:
        """Atomically claim and consume an approved authorization envelope within a write lock.

        The caller must independently verify ``expected_authorization`` before calling.
        The write lock binds consumption to that complete receipt and prevents replay.
        """
        import json

        now_str = current_time_iso or utc_now()
        now_dt = timestamp(now_str)

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                cur = conn.execute(
                    """
                    SELECT authorization_id, action_plan_id, plan_digest, engagement_id,
                           operator, status, issued_at, authorized_until_utc,
                           bound_parameters_json, approval_mode, signature_algorithm,
                           signing_key_id, signature_digest, legacy_status,
                           consumed_at, consumed_by_worker
                    FROM approvals WHERE authorization_id = ?
                    """,
                    (authorization_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise ApprovalStoreNotFoundError(f"authorization '{authorization_id}' not found in store")

                current_status = row["status"]
                if current_status != "approved":
                    raise ApprovalStoreConflictError(
                        f"cannot consume authorization '{authorization_id}': status is '{current_status}' "
                        f"(already consumed or revoked)"
                    )

                doc = {
                    "schema_version": "cops.execution-authorization/v1",
                    "authorization_id": row["authorization_id"],
                    "action_plan_id": row["action_plan_id"],
                    "plan_digest": row["plan_digest"],
                    "engagement_id": row["engagement_id"],
                    "operator": row["operator"],
                    "status": row["status"],
                    "issued_at": row["issued_at"],
                    "authorized_until_utc": row["authorized_until_utc"],
                    "bound_parameters": json.loads(row["bound_parameters_json"]),
                    "approval_mode": row["approval_mode"],
                    "signature_algorithm": row["signature_algorithm"],
                    "signing_key_id": row["signing_key_id"],
                    "signature_digest": row["signature_digest"],
                }
                if row["consumed_at"]:
                    doc["consumed_at"] = row["consumed_at"]
                if row["consumed_by_worker"]:
                    doc["consumed_by_worker"] = row["consumed_by_worker"]
                if canonical(doc) != canonical(expected_authorization.to_dict()):
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' differs from the verified receipt"
                    )
                if doc["bound_parameters"].get("worker_identity") != worker_identity:
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' is bound to a different worker"
                    )
                if now_dt < timestamp(row["issued_at"]):
                    raise ApprovalStoreConflictError(f"authorization '{authorization_id}' is not yet valid")

                # Check expiration
                expiry_dt = timestamp(row["authorized_until_utc"])
                if now_dt >= expiry_dt:
                    conn.execute(
                        "UPDATE approvals SET status = 'expired' WHERE authorization_id = ?",
                        (authorization_id,),
                    )
                    conn.execute("COMMIT")
                    committed = True
                    raise ApprovalStoreConflictError(
                        f"authorization '{authorization_id}' expired at {row['authorized_until_utc']}"
                    )

                # Atomically mark consumed
                conn.execute(
                    """
                    UPDATE approvals
                    SET status = 'consumed', consumed_at = ?, consumed_by_worker = ?
                    WHERE authorization_id = ? AND status = 'approved'
                    """,
                    (now_str, worker_identity, authorization_id),
                )

                conn.execute("COMMIT")
                committed = True

                doc.update(
                    status="consumed",
                    consumed_at=now_str,
                    consumed_by_worker=worker_identity,
                )
                return ExecutionAuthorization.from_dict(doc)
            except Exception:
                if not committed:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        # Preserve the original transaction failure if rollback also fails.
                        pass
                raise

    def list_approvals(self, status: str | None = None) -> list[ExecutionAuthorization | LegacyApprovalRecord]:
        """List authorizations optionally filtered by status."""
        import json

        with self._get_connection() as conn:
            if status:
                cur = conn.execute(
                    """
                    SELECT authorization_id, action_plan_id, plan_digest, engagement_id,
                           operator, status, issued_at, authorized_until_utc,
                           bound_parameters_json, approval_mode, signature_algorithm,
                           signing_key_id, signature_digest, legacy_status,
                           consumed_at, consumed_by_worker
                    FROM approvals WHERE status = ? ORDER BY issued_at DESC
                    """,
                    (status,),
                )
            else:
                cur = conn.execute(
                    """
                    SELECT authorization_id, action_plan_id, plan_digest, engagement_id,
                           operator, status, issued_at, authorized_until_utc,
                           bound_parameters_json, approval_mode, signature_algorithm,
                           signing_key_id, signature_digest, legacy_status,
                           consumed_at, consumed_by_worker
                    FROM approvals ORDER BY issued_at DESC
                    """
                )

            results: list[ExecutionAuthorization | LegacyApprovalRecord] = []
            for row in cur.fetchall():
                doc = {
                    "schema_version": "cops.execution-authorization/v1",
                    "authorization_id": row["authorization_id"],
                    "action_plan_id": row["action_plan_id"],
                    "plan_digest": row["plan_digest"],
                    "engagement_id": row["engagement_id"],
                    "operator": row["operator"],
                    "status": row["status"],
                    "issued_at": row["issued_at"],
                    "authorized_until_utc": row["authorized_until_utc"],
                    "bound_parameters": json.loads(row["bound_parameters_json"]),
                    "approval_mode": row["approval_mode"],
                    "signature_algorithm": row["signature_algorithm"],
                    "signing_key_id": row["signing_key_id"],
                    "signature_digest": row["signature_digest"],
                }
                if row["consumed_at"]:
                    doc["consumed_at"] = row["consumed_at"]
                if row["consumed_by_worker"]:
                    doc["consumed_by_worker"] = row["consumed_by_worker"]
                if row["status"] == "legacy-untrusted":
                    results.append(
                        LegacyApprovalRecord(
                            authorization_id=row["authorization_id"],
                            action_plan_id=row["action_plan_id"],
                            plan_digest=row["plan_digest"],
                            engagement_id=row["engagement_id"],
                            operator=row["operator"],
                            historical_status=row["legacy_status"] or "unknown",
                            issued_at=row["issued_at"],
                            authorized_until_utc=row["authorized_until_utc"],
                            bound_parameters=json.loads(row["bound_parameters_json"]),
                            approval_mode=row["approval_mode"],
                            signature_algorithm=row["signature_algorithm"],
                            signing_key_id=row["signing_key_id"],
                            signature_digest=row["signature_digest"],
                            consumed_at=row["consumed_at"],
                            consumed_by_worker=row["consumed_by_worker"],
                        )
                    )
                else:
                    results.append(ExecutionAuthorization.from_dict(doc))
            return results
