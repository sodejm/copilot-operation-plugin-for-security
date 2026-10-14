"""Bundled, fixture-only admission ledger for exported provider assessments.

The caller owns the policy, ledger path, and dispatch boundary. This module
does not wrap real provider clients or make network requests.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ACTIVE = frozenset({"reserved", "dispatched", "uncertain"})
_CHARGED = _ACTIVE | {"usage_unknown", "settled"}
_OUTCOMES = frozenset({"completed", "target_denied", "runner_stopped", "failed", "cancelled"})
_LIMIT_FIELDS = (
    "max_attempts",
    "max_estimated_tokens",
    "max_estimated_cost_microunits",
    "max_elapsed_ms",
    "max_concurrency",
    "max_retained_output_bytes",
    "max_depth",
    "max_children_per_parent",
)


class BudgetDenied(ValueError):
    """The requested operation would violate the trusted budget contract."""


class BudgetStoreError(RuntimeError):
    """The ledger cannot establish safe, durable admission state."""


def _identifier(value: str, field: str) -> None:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid {field}")


def _integer(value: int, field: str, *, positive: bool = False) -> None:
    if type(value) is not int or value < (1 if positive else 0) or value > 2**63 - 1:
        raise ValueError(f"invalid {field}")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class BudgetLimits:
    max_attempts: int
    max_estimated_tokens: int
    max_estimated_cost_microunits: int
    max_elapsed_ms: int
    max_concurrency: int
    max_retained_output_bytes: int
    max_depth: int
    max_children_per_parent: int

    def __post_init__(self) -> None:
        for field in _LIMIT_FIELDS:
            _integer(getattr(self, field), field, positive=field != "max_depth")

    def is_within(self, parent: BudgetLimits) -> bool:
        return all(getattr(self, field) <= getattr(parent, field) for field in _LIMIT_FIELDS)


@dataclass(frozen=True)
class BudgetPolicy:
    engagement_id: str
    limits: BudgetLimits
    currency: str
    price_source: str
    price_version: str
    price_effective_date: str
    schema_version: str = "cops.assessment-budget/v1"
    price_error_policy: str = "deny"

    def __post_init__(self) -> None:
        _identifier(self.engagement_id, "engagement_id")
        if not isinstance(self.limits, BudgetLimits):
            raise ValueError("invalid limits")
        if not isinstance(self.currency, str) or re.fullmatch(r"[A-Z]{3}", self.currency) is None:
            raise ValueError("invalid currency")
        for field in ("price_source", "price_version"):
            _identifier(getattr(self, field), field)
        if (
            not isinstance(self.price_effective_date, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.price_effective_date) is None
        ):
            raise ValueError("invalid price_effective_date")
        try:
            date.fromisoformat(self.price_effective_date)
        except ValueError as exc:
            raise ValueError("invalid price_effective_date") from exc
        if self.schema_version != "cops.assessment-budget/v1" or self.price_error_policy != "deny":
            raise ValueError("unsupported budget policy version or price error policy")


@dataclass(frozen=True)
class AttemptRequest:
    attempt_id: str
    parent_id: str | None
    estimated_tokens: int
    estimated_cost_microunits: int
    reserved_output_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "attempt_id")
        if self.parent_id is not None:
            _identifier(self.parent_id, "parent_id")
            if self.parent_id == self.attempt_id:
                raise ValueError("attempt cannot be its own parent")
        for field in ("estimated_tokens", "estimated_cost_microunits", "reserved_output_bytes"):
            _integer(getattr(self, field), field)


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    attempt_id: str
    outcome: str
    tokens: int | None
    cost_microunits: int | None
    retained_output_bytes: int | None

    def __post_init__(self) -> None:
        _identifier(self.receipt_id, "receipt_id")
        _identifier(self.attempt_id, "attempt_id")
        if not isinstance(self.outcome, str) or self.outcome not in _OUTCOMES:
            raise ValueError("invalid receipt outcome")
        for field in ("tokens", "cost_microunits", "retained_output_bytes"):
            value = getattr(self, field)
            if value is not None:
                _integer(value, field)


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    parent_id: str | None
    state: str
    depth: int


@dataclass(frozen=True)
class BudgetSnapshot:
    charged_attempts: int
    charged_tokens: int
    charged_cost_microunits: int
    charged_output_bytes: int
    active_concurrency: int
    over_budget: bool


@dataclass(frozen=True)
class CancellationReport:
    attempt_id: str
    requested: bool
    stop_confirmed: bool
    pending: bool
    final_consumption_known: bool
    outcome: str | None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    policy_json TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    cancelled INTEGER NOT NULL DEFAULT 0 CHECK (cancelled IN (0, 1))
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES attempts(attempt_id),
    request_json TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    depth INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','dispatched','uncertain','usage_unknown','settled','released')),
    estimated_tokens INTEGER NOT NULL,
    estimated_cost_microunits INTEGER NOT NULL,
    reserved_output_bytes INTEGER NOT NULL,
    actual_tokens INTEGER,
    actual_cost_microunits INTEGER,
    actual_output_bytes INTEGER,
    outcome TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1))
);
CREATE INDEX IF NOT EXISTS attempts_parent ON attempts(parent_id);
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    payload_json TEXT NOT NULL
);
"""


class AssessmentBudgetLedger:
    """SQLite ledger with one immediate transaction per state transition."""

    def __init__(self, db_path: Path | str, policy: BudgetPolicy, *, clock: Callable[[], int] | None = None) -> None:
        if not isinstance(policy, BudgetPolicy):
            raise ValueError("policy must be a BudgetPolicy")
        source = Path(db_path).expanduser()
        self.db_path = source if source.is_absolute() else Path.cwd() / source
        self.policy = policy
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._prepare_store()
        try:
            with self._connect() as db:
                db.executescript(_SCHEMA)
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM engagement WHERE singleton = 1").fetchone()
                now = self._now()
                if row is None:
                    db.execute(
                        "INSERT INTO engagement(singleton,policy_json,started_at_ms,last_seen_ms) VALUES(1,?,?,?)",
                        (_canonical(asdict(policy)), now, now),
                    )
                elif row["policy_json"] != _canonical(asdict(policy)):
                    raise BudgetStoreError("ledger policy mismatch")
                elif now < row["last_seen_ms"]:
                    raise BudgetStoreError("clock moved backward")
                else:
                    db.execute("UPDATE engagement SET last_seen_ms = ? WHERE singleton = 1", (now,))
                    # A process can die after durable dispatch intent but before a receipt.
                    db.execute("UPDATE attempts SET state = 'uncertain' WHERE state = 'dispatched'")
                db.commit()
        except sqlite3.Error as exc:
            raise BudgetStoreError("budget storage unavailable") from exc

    def _now(self) -> int:
        try:
            value = self._clock()
        except Exception as exc:
            raise BudgetStoreError("clock unavailable") from exc
        if type(value) is not int or value < 0 or value > 2**63 - 1:
            raise BudgetStoreError("clock returned an invalid millisecond timestamp")
        return value

    def _prepare_store(self) -> None:
        parent = self.db_path.parent
        try:
            if not parent.exists():
                parent.mkdir(parents=True, mode=0o700)
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
                raise BudgetStoreError("budget directory must be owner-only")
            if os.name == "posix" and info.st_uid != os.geteuid():
                raise BudgetStoreError("budget directory must be owned by the current account")
            if not self.db_path.exists():
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.db_path, flags, 0o600)
                os.close(fd)
            self._check_file()
        except OSError as exc:
            raise BudgetStoreError("budget storage unavailable") from exc

    def _check_file(self) -> None:
        try:
            info = self.db_path.lstat()
        except OSError as exc:
            raise BudgetStoreError("budget storage unavailable") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise BudgetStoreError("budget file must be owner-only and regular")
        if os.name == "posix" and info.st_uid != os.geteuid():
            raise BudgetStoreError("budget file must be owned by the current account")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self._check_file()
        try:
            db = sqlite3.connect(self.db_path.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA journal_mode = DELETE")
            db.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error as exc:
            raise BudgetStoreError("budget storage unavailable") from exc
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self) -> Iterator[tuple[sqlite3.Connection, sqlite3.Row, int]]:
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                engagement = db.execute("SELECT * FROM engagement WHERE singleton = 1").fetchone()
                if engagement is None or engagement["policy_json"] != _canonical(asdict(self.policy)):
                    raise BudgetStoreError("budget policy or engagement missing")
                now = self._now()
                if now < engagement["last_seen_ms"]:
                    raise BudgetStoreError("clock moved backward")
                db.execute("UPDATE engagement SET last_seen_ms = ? WHERE singleton = 1", (now,))
                db.execute("SAVEPOINT action")
                try:
                    yield db, engagement, now
                except BaseException:
                    db.execute("ROLLBACK TO SAVEPOINT action")
                    db.execute("RELEASE SAVEPOINT action")
                    # A rejected action cannot erase an observed clock high-water mark.
                    db.commit()
                    raise
                else:
                    db.execute("RELEASE SAVEPOINT action")
                    db.commit()
        except sqlite3.Error as exc:
            raise BudgetStoreError("budget storage unavailable") from exc

    @staticmethod
    def _attempt(row: sqlite3.Row) -> Attempt:
        return Attempt(row["attempt_id"], row["parent_id"], row["state"], row["depth"])

    @staticmethod
    def _charged(rows: list[sqlite3.Row]) -> BudgetSnapshot:
        charged = [row for row in rows if row["state"] in _CHARGED]

        def usage(row: sqlite3.Row, actual: str, estimated: str) -> int:
            reported = row[actual]
            reserved = row[estimated]
            if row["state"] == "settled":
                return reported
            return max(reserved, reported) if reported is not None else reserved

        return BudgetSnapshot(
            charged_attempts=len(charged),
            charged_tokens=sum(usage(row, "actual_tokens", "estimated_tokens") for row in charged),
            charged_cost_microunits=sum(
                usage(row, "actual_cost_microunits", "estimated_cost_microunits") for row in charged
            ),
            charged_output_bytes=sum(usage(row, "actual_output_bytes", "reserved_output_bytes") for row in charged),
            active_concurrency=sum(row["state"] in _ACTIVE for row in rows),
            over_budget=False,
        )

    @staticmethod
    def _within(snapshot: BudgetSnapshot, limits: BudgetLimits) -> bool:
        return (
            snapshot.charged_attempts <= limits.max_attempts
            and snapshot.charged_tokens <= limits.max_estimated_tokens
            and snapshot.charged_cost_microunits <= limits.max_estimated_cost_microunits
            and snapshot.charged_output_bytes <= limits.max_retained_output_bytes
            and snapshot.active_concurrency <= limits.max_concurrency
        )

    def reserve(self, request: AttemptRequest, *, child_limits: BudgetLimits | None = None) -> Attempt:
        if not isinstance(request, AttemptRequest):
            raise ValueError("request must be an AttemptRequest")
        if child_limits is not None and not isinstance(child_limits, BudgetLimits):
            raise ValueError("child_limits must be BudgetLimits")
        with self._transaction() as (db, engagement, now):
            existing = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (request.attempt_id,)).fetchone()
            if existing is not None:
                if existing["parent_id"] is None:
                    inherited = self.policy.limits
                else:
                    parent_row = db.execute(
                        "SELECT limits_json FROM attempts WHERE attempt_id = ?", (existing["parent_id"],)
                    ).fetchone()
                    if parent_row is None:
                        raise BudgetStoreError("attempt parent missing")
                    inherited = BudgetLimits(**json.loads(parent_row["limits_json"]))
                if existing["request_json"] != _canonical(asdict(request)) or existing["limits_json"] != _canonical(
                    asdict(child_limits or inherited)
                ):
                    raise BudgetDenied("conflicting attempt id reuse")
                return self._attempt(existing)
            if engagement["cancelled"]:
                raise BudgetDenied("engagement cancelled")
            if now - engagement["started_at_ms"] > self.policy.limits.max_elapsed_ms:
                raise BudgetDenied("budget deadline expired")
            parent = None
            ancestors: list[sqlite3.Row] = []
            if request.parent_id is not None:
                parent = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (request.parent_id,)).fetchone()
                if parent is None or parent["state"] == "released":
                    raise BudgetDenied("parent attempt unavailable")
                current = parent
                while current is not None:
                    ancestors.append(current)
                    current = (
                        db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (current["parent_id"],)).fetchone()
                        if current["parent_id"] is not None
                        else None
                    )
                parent_limits = BudgetLimits(**json.loads(parent["limits_json"]))
            else:
                parent_limits = self.policy.limits
            effective = child_limits or parent_limits
            if not effective.is_within(parent_limits):
                raise BudgetDenied("child limits widen parent")
            if request.parent_id is not None:
                sibling_count = db.execute(
                    "SELECT COUNT(*) FROM attempts WHERE parent_id = ?", (request.parent_id,)
                ).fetchone()[0]
                if sibling_count >= parent_limits.max_children_per_parent:
                    raise BudgetDenied("child fanout limit reached")
            depth = parent["depth"] + 1 if parent is not None else 0
            if depth > self.policy.limits.max_depth or any(
                depth - ancestor["depth"] > BudgetLimits(**json.loads(ancestor["limits_json"])).max_depth
                for ancestor in ancestors
            ):
                raise BudgetDenied("child depth limit reached")
            for ancestor in ancestors:
                limits = BudgetLimits(**json.loads(ancestor["limits_json"]))
                if now - engagement["started_at_ms"] > limits.max_elapsed_ms:
                    raise BudgetDenied("subtree deadline expired")
            db.execute(
                """INSERT INTO attempts(attempt_id,parent_id,request_json,limits_json,depth,state,
                   estimated_tokens,estimated_cost_microunits,reserved_output_bytes)
                   VALUES(?,?,?,?,?,'reserved',?,?,?)""",
                (
                    request.attempt_id,
                    request.parent_id,
                    _canonical(asdict(request)),
                    _canonical(asdict(effective)),
                    depth,
                    request.estimated_tokens,
                    request.estimated_cost_microunits,
                    request.reserved_output_bytes,
                ),
            )
            rows = list(db.execute("SELECT * FROM attempts"))
            if not self._within(self._charged(rows), self.policy.limits):
                raise BudgetDenied("aggregate budget exceeded")
            by_id = {row["attempt_id"]: row for row in rows}
            for ancestor in ancestors:
                subtree = [row for row in rows if self._descends_from(row, ancestor["attempt_id"], by_id)]
                if not self._within(self._charged(subtree), BudgetLimits(**json.loads(ancestor["limits_json"]))):
                    raise BudgetDenied("subtree budget exceeded")
            own = self._charged([by_id[request.attempt_id]])
            if not self._within(own, effective):
                raise BudgetDenied("attempt exceeds child budget")
            return Attempt(request.attempt_id, request.parent_id, "reserved", depth)

    @staticmethod
    def _descends_from(row: sqlite3.Row, ancestor_id: str, by_id: dict[str, sqlite3.Row]) -> bool:
        current = row
        while current is not None:
            if current["attempt_id"] == ancestor_id:
                return True
            current = by_id.get(current["parent_id"])
        return False

    def get_attempt(self, attempt_id: str) -> Attempt:
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as (db, _, _now):
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise BudgetDenied("attempt not found")
            return self._attempt(row)

    def mark_dispatched(self, attempt_id: str) -> Attempt:
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as (db, engagement, now):
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise BudgetDenied("attempt not found")
            if engagement["cancelled"]:
                raise BudgetDenied("engagement cancelled")
            if now - engagement["started_at_ms"] > self.policy.limits.max_elapsed_ms:
                raise BudgetDenied("budget deadline expired")
            if row["state"] != "reserved":
                raise BudgetDenied("attempt is not reserved")
            current = row
            while current is not None:
                limits = BudgetLimits(**json.loads(current["limits_json"]))
                if now - engagement["started_at_ms"] > limits.max_elapsed_ms:
                    raise BudgetDenied("subtree deadline expired")
                current = (
                    db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (current["parent_id"],)).fetchone()
                    if current["parent_id"] is not None
                    else None
                )
            db.execute("UPDATE attempts SET state = 'dispatched' WHERE attempt_id = ?", (attempt_id,))
            return Attempt(attempt_id, row["parent_id"], "dispatched", row["depth"])

    def mark_uncertain(self, attempt_id: str) -> Attempt:
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as (db, _, _now):
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None or row["state"] not in {"dispatched", "uncertain"}:
                raise BudgetDenied("no dispatch intent to mark uncertain")
            db.execute("UPDATE attempts SET state = 'uncertain' WHERE attempt_id = ?", (attempt_id,))
            return Attempt(attempt_id, row["parent_id"], "uncertain", row["depth"])

    def release_undispatched(self, attempt_id: str) -> Attempt:
        """Release an attempt only when no dispatch intent was ever recorded."""
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as (db, _, _now):
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None or row["state"] not in {"reserved", "released"}:
                raise BudgetDenied("attempt may be in flight")
            db.execute("UPDATE attempts SET state = 'released' WHERE attempt_id = ?", (attempt_id,))
            return Attempt(attempt_id, row["parent_id"], "released", row["depth"])

    def reconcile(self, receipt: Receipt) -> Attempt:
        if not isinstance(receipt, Receipt):
            raise ValueError("receipt must be a Receipt")
        with self._transaction() as (db, _, _now):
            payload = _canonical(asdict(receipt))
            duplicate = db.execute("SELECT * FROM receipts WHERE receipt_id = ?", (receipt.receipt_id,)).fetchone()
            if duplicate is not None and duplicate["payload_json"] != payload:
                raise BudgetDenied("conflicting receipt id reuse")
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (receipt.attempt_id,)).fetchone()
            if row is None:
                raise BudgetDenied("attempt not found")
            if duplicate is not None:
                return self._attempt(row)
            if row["state"] not in {"dispatched", "uncertain", "usage_unknown"}:
                raise BudgetDenied("conflicting terminal receipt")
            if row["state"] == "usage_unknown" and (
                receipt.outcome != row["outcome"]
                or any(
                    row[column] is not None and row[column] != getattr(receipt, field)
                    for column, field in (
                        ("actual_tokens", "tokens"),
                        ("actual_cost_microunits", "cost_microunits"),
                        ("actual_output_bytes", "retained_output_bytes"),
                    )
                )
            ):
                raise BudgetDenied("conflicting receipt revision")
            if (
                receipt.retained_output_bytes is not None
                and receipt.retained_output_bytes > row["reserved_output_bytes"]
            ):
                raise BudgetDenied("retained output exceeds reservation")
            known = all(
                value is not None for value in (receipt.tokens, receipt.cost_microunits, receipt.retained_output_bytes)
            )
            state = "settled" if known else "usage_unknown"
            db.execute(
                """UPDATE attempts SET state = ?, actual_tokens = ?, actual_cost_microunits = ?,
                   actual_output_bytes = ?, outcome = ? WHERE attempt_id = ?""",
                (
                    state,
                    receipt.tokens,
                    receipt.cost_microunits,
                    receipt.retained_output_bytes,
                    receipt.outcome,
                    receipt.attempt_id,
                ),
            )
            db.execute(
                "INSERT INTO receipts(receipt_id,attempt_id,payload_json) VALUES(?,?,?)",
                (receipt.receipt_id, receipt.attempt_id, payload),
            )
            return Attempt(receipt.attempt_id, row["parent_id"], state, row["depth"])

    def cancel(self) -> None:
        with self._transaction() as (db, _, _now):
            db.execute("UPDATE engagement SET cancelled = 1 WHERE singleton = 1")
            # Every active descendant shares this ledger and receives the request.
            db.execute(
                "UPDATE attempts SET cancel_requested = 1 WHERE state IN ('reserved', 'dispatched', 'uncertain')"
            )
            db.execute("UPDATE attempts SET state = 'released' WHERE state = 'reserved'")

    def cancellation_report(self, attempt_id: str) -> CancellationReport:
        """Report request, observed stop, and final usage separately."""
        _identifier(attempt_id, "attempt_id")
        with self._transaction() as (db, _, _now):
            row = db.execute("SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None:
                raise BudgetDenied("attempt not found")
            requested = bool(row["cancel_requested"])
            final = row["state"] in {"released", "settled"}
            confirmed = requested and (row["state"] == "released" or row["outcome"] in {"runner_stopped", "cancelled"})
            return CancellationReport(
                attempt_id=attempt_id,
                requested=requested,
                stop_confirmed=confirmed,
                pending=requested and not final,
                final_consumption_known=final,
                outcome=row["outcome"],
            )

    def snapshot(self) -> BudgetSnapshot:
        with self._transaction() as (db, _, _now):
            snapshot = self._charged(list(db.execute("SELECT * FROM attempts")))
            return BudgetSnapshot(**{**asdict(snapshot), "over_budget": not self._within(snapshot, self.policy.limits)})


@dataclass(frozen=True)
class CancellationSignal:
    """Durable, cross-process cancellation signal for a synthetic callback."""

    ledger: AssessmentBudgetLedger
    attempt_id: str

    def requested(self) -> bool:
        return self.ledger.cancellation_report(self.attempt_id).requested


def dispatch_fixture(
    ledger: AssessmentBudgetLedger,
    request: AttemptRequest,
    callback: Callable[[AttemptRequest, CancellationSignal], Receipt],
) -> Attempt:
    """Run one synthetic callback after durable reservation and dispatch intent."""
    ledger.reserve(request)
    ledger.mark_dispatched(request.attempt_id)
    try:
        receipt = callback(request, CancellationSignal(ledger, request.attempt_id))
        if not isinstance(receipt, Receipt) or receipt.attempt_id != request.attempt_id:
            raise BudgetDenied("receipt attempt mismatch")
        return ledger.reconcile(receipt)
    except BaseException:
        ledger.mark_uncertain(request.attempt_id)
        raise
