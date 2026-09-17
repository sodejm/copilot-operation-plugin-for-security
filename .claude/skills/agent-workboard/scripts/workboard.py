#!/usr/bin/env python3
"""Durable per-project workboard for parent and subagent coordination."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA_VERSION = 1
LEASE_MINUTES = 30
TASK_STATES = (
    "pending",
    "ready",
    "launched",
    "running",
    "blocked",
    "completed",
    "cancelled",
    "stale",
)
TERMINAL_STATES = ("blocked", "completed", "cancelled")


class WorkboardError(RuntimeError):
    """Expected command error with a concise user-facing message."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def json_text(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def new_id(prefix: str) -> str:
    return "{}_{}".format(prefix, uuid.uuid4().hex)


def canonical_path(path: str) -> Path:
    return Path(path).expanduser().resolve()


def run_git(cwd: Path, args: Sequence[str]) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd)] + list(args),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def resolve_storage(cwd: str) -> Dict[str, str]:
    project = canonical_path(cwd)
    common = run_git(
        project, ["rev-parse", "--path-format=absolute", "--git-common-dir"]
    )
    root = run_git(project, ["rev-parse", "--show-toplevel"])
    if common:
        common_path = canonical_path(common)
        project_root = canonical_path(root) if root else project
        database = common_path / "codex" / "workboard.sqlite3"
        kind = "git"
    else:
        digest = hashlib.sha256(str(project).encode("utf-8")).hexdigest()
        database = (
            Path.home()
            / ".codex"
            / "orchestration"
            / "projects"
            / digest
            / "workboard.sqlite3"
        )
        project_root = project
        kind = "directory"
    return {
        "database": str(database),
        "project_root": str(project_root),
        "storage_kind": kind,
    }


def resolve_database(cwd: str, explicit: Optional[str]) -> Tuple[Path, Dict[str, str]]:
    storage = resolve_storage(cwd)
    database = canonical_path(explicit) if explicit else Path(storage["database"])
    storage["database"] = str(database)
    return database, storage


def secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def connect(database: Path, initialize: bool = True) -> sqlite3.Connection:
    secure_directory(database.parent)
    existed = database.exists()
    connection = sqlite3.connect(str(database), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    if initialize:
        migrate(connection)
    if not existed or database.exists():
        try:
            database.chmod(0o600)
        except OSError:
            pass
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        raise WorkboardError(
            "database schema {} is newer than supported schema {}".format(
                version, SCHEMA_VERSION
            )
        )
    if version < 1:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                cwd TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'closed')),
                source TEXT,
                model TEXT,
                permission_mode TEXT,
                started_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                ended_at TEXT
            );

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                session_id TEXT,
                title TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'closed')),
                cwd TEXT NOT NULL,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                ended_at TEXT
            );

            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                parent_task_id TEXT REFERENCES tasks(task_id) ON DELETE SET NULL,
                title TEXT NOT NULL,
                goal TEXT NOT NULL,
                scope TEXT NOT NULL,
                inputs_json TEXT NOT NULL DEFAULT '[]',
                expected_output TEXT NOT NULL,
                acceptance_json TEXT NOT NULL DEFAULT '[]',
                model TEXT NOT NULL,
                effort TEXT NOT NULL,
                worktree TEXT,
                branch TEXT,
                assigned_agent_id TEXT,
                agent_type TEXT,
                status TEXT NOT NULL CHECK (
                    status IN (
                        'pending', 'ready', 'launched', 'running', 'blocked',
                        'completed', 'cancelled', 'stale'
                    )
                ),
                lease_expires_at TEXT,
                blocker TEXT,
                next_action TEXT,
                summary TEXT,
                validation_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS dependencies (
                task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
                depends_on_task_id TEXT NOT NULL
                    REFERENCES tasks(task_id) ON DELETE RESTRICT,
                PRIMARY KEY (task_id, depends_on_task_id),
                CHECK (task_id <> depends_on_task_id)
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT REFERENCES runs(run_id) ON DELETE CASCADE,
                task_id TEXT REFERENCES tasks(task_id) ON DELETE CASCADE,
                session_id TEXT,
                agent_id TEXT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tasks_run_status
                ON tasks(run_id, status);
            CREATE INDEX IF NOT EXISTS idx_tasks_agent_status
                ON tasks(assigned_agent_id, status);
            CREATE INDEX IF NOT EXISTS idx_tasks_lease
                ON tasks(status, lease_expires_at);
            CREATE INDEX IF NOT EXISTS idx_events_task
                ON events(task_id, event_id);
            CREATE INDEX IF NOT EXISTS idx_runs_session
                ON runs(session_id, status);
            PRAGMA user_version=1;
            """
        )
        connection.commit()


def record_event(
    connection: sqlite3.Connection,
    event_type: str,
    *,
    run_id: Optional[str] = None,
    task_id: Optional[str] = None,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    connection.execute(
        """
        INSERT INTO events(
            run_id, task_id, session_id, agent_id, event_type, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            task_id,
            session_id,
            agent_id,
            event_type,
            json_text(payload or {}),
            utc_now(),
        ),
    )


def fetch_task(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None:
        raise WorkboardError("unknown task: {}".format(task_id))
    return row


def incomplete_dependencies(
    connection: sqlite3.Connection, task_id: str
) -> List[sqlite3.Row]:
    return list(
        connection.execute(
            """
            SELECT prerequisite.task_id, prerequisite.status
            FROM dependencies dependency
            JOIN tasks prerequisite
              ON prerequisite.task_id = dependency.depends_on_task_id
            WHERE dependency.task_id = ?
              AND prerequisite.status <> 'completed'
            ORDER BY prerequisite.created_at
            """,
            (task_id,),
        )
    )


def refresh_ready_tasks(connection: sqlite3.Connection) -> List[str]:
    rows = list(
        connection.execute(
            """
            SELECT task.task_id
            FROM tasks task
            WHERE task.status = 'pending'
              AND NOT EXISTS (
                  SELECT 1
                  FROM dependencies dependency
                  JOIN tasks prerequisite
                    ON prerequisite.task_id = dependency.depends_on_task_id
                  WHERE dependency.task_id = task.task_id
                    AND prerequisite.status <> 'completed'
              )
            """
        )
    )
    now = utc_now()
    changed = []
    for row in rows:
        task_id = row["task_id"]
        connection.execute(
            "UPDATE tasks SET status = 'ready', updated_at = ? WHERE task_id = ?",
            (now, task_id),
        )
        task = fetch_task(connection, task_id)
        record_event(
            connection,
            "task_ready",
            run_id=task["run_id"],
            task_id=task_id,
        )
        changed.append(task_id)
    return changed


def write_handoff(
    connection: sqlite3.Connection,
    database: Path,
    task_id: str,
) -> Path:
    task = fetch_task(connection, task_id)
    handoff_dir = database.parent / "handoffs"
    secure_directory(handoff_dir)
    path = handoff_dir / "{}.md".format(task_id)
    inputs = json.loads(task["inputs_json"])
    acceptance = json.loads(task["acceptance_json"])
    validation = json.loads(task["validation_json"])
    dependencies = [
        row["depends_on_task_id"]
        for row in connection.execute(
            "SELECT depends_on_task_id FROM dependencies WHERE task_id = ? "
            "ORDER BY depends_on_task_id",
            (task_id,),
        )
    ]
    artifact_references = [
        "{}: {}".format(row["kind"], row["path"])
        for row in connection.execute(
            """
            SELECT kind, path FROM artifacts
            WHERE task_id = ? AND kind <> 'handoff'
            ORDER BY created_at, artifact_id
            """,
            (task_id,),
        )
    ]

    def bullets(values: Iterable[Any], empty: str = "- None recorded") -> str:
        lines = ["- {}".format(value) for value in values]
        return "\n".join(lines) if lines else empty

    body = """# Task handoff: {title}

- Task: `{task_id}`
- Run: `{run_id}`
- Status: `{status}`
- Model: `{model}`
- Effort: `{effort}`
- Agent: `{agent}`
- Worktree: `{worktree}`
- Branch: `{branch}`
- Updated: `{updated}`

## Goal

{goal}

## Scope

{scope}

## Inputs

{inputs}

## Expected output

{expected_output}

## Acceptance checks

{acceptance}

## Dependencies

{dependencies}

## Result

{summary}

## Validation

{validation}

## Artifact references

{artifacts}

## Blocker

{blocker}

## Next action

{next_action}
""".format(
        title=task["title"],
        task_id=task["task_id"],
        run_id=task["run_id"],
        status=task["status"],
        model=task["model"],
        effort=task["effort"],
        agent=task["assigned_agent_id"] or "Unassigned",
        worktree=task["worktree"] or "Not set",
        branch=task["branch"] or "Not set",
        updated=task["updated_at"],
        goal=task["goal"],
        scope=task["scope"],
        inputs=bullets(inputs),
        expected_output=task["expected_output"],
        acceptance=bullets(acceptance),
        dependencies=bullets(dependencies),
        summary=task["summary"] or "No result summary recorded.",
        validation=bullets(validation),
        artifacts=bullets(artifact_references),
        blocker=task["blocker"] or "None.",
        next_action=task["next_action"] or "None.",
    )
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)
    digest = file_sha256(path)
    connection.execute(
        "DELETE FROM artifacts WHERE task_id = ? AND kind = 'handoff'", (task_id,)
    )
    connection.execute(
        """
        INSERT INTO artifacts(artifact_id, task_id, kind, path, sha256, created_at)
        VALUES (?, ?, 'handoff', ?, ?, ?)
        """,
        (new_id("artifact"), task_id, str(path), digest, utc_now()),
    )
    return path


def record_artifact_references(
    connection: sqlite3.Connection,
    task_id: str,
    changed_files: Sequence[str],
    validation_files: Sequence[str],
) -> None:
    references = [
        ("changed_file", value) for value in changed_files
    ] + [("validation", value) for value in validation_files]
    for kind, value in references:
        path = Path(value).expanduser()
        digest = None
        if path.is_file():
            digest = file_sha256(path)
        connection.execute(
            """
            INSERT INTO artifacts(
                artifact_id, task_id, kind, path, sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (new_id("artifact"), task_id, kind, value, digest, utc_now()),
        )


def command_init(
    connection: sqlite3.Connection,
    database: Path,
    storage: Dict[str, str],
    _args: argparse.Namespace,
) -> Dict[str, Any]:
    return {
        "database": str(database),
        "project_root": storage["project_root"],
        "storage_kind": storage["storage_kind"],
        "schema_version": int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        ),
    }


def command_run_start(
    connection: sqlite3.Connection,
    database: Path,
    storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    run_id = args.run_id or new_id("run")
    now = utc_now()
    try:
        connection.execute(
            """
            INSERT INTO runs(
                run_id, session_id, title, status, cwd, started_at, updated_at
            ) VALUES (?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                run_id,
                args.session_id,
                args.title,
                storage["project_root"],
                now,
                now,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise WorkboardError("cannot start run {}: {}".format(run_id, exc))
    record_event(
        connection,
        "run_started",
        run_id=run_id,
        session_id=args.session_id,
        payload={"title": args.title},
    )
    connection.commit()
    return {"database": str(database), "run_id": run_id, "status": "active"}


def load_contract(args: argparse.Namespace) -> Dict[str, Any]:
    contract: Dict[str, Any] = {}
    if args.contract_file:
        contract = json.loads(
            Path(args.contract_file).expanduser().read_text(encoding="utf-8")
        )
        if not isinstance(contract, dict):
            raise WorkboardError("contract file must contain a JSON object")
    fields = (
        "title",
        "goal",
        "scope",
        "expected_output",
        "model",
        "effort",
        "worktree",
        "branch",
        "parent_task_id",
    )
    for field in fields:
        value = getattr(args, field, None)
        if value is not None:
            contract[field] = value
    if args.inputs_json is not None:
        contract["inputs"] = json.loads(args.inputs_json)
    if args.acceptance_json is not None:
        contract["acceptance"] = json.loads(args.acceptance_json)
    if args.depends_on:
        contract["dependencies"] = args.depends_on
    required = (
        "title",
        "goal",
        "scope",
        "expected_output",
        "model",
        "effort",
    )
    missing = [field for field in required if not contract.get(field)]
    if missing:
        raise WorkboardError(
            "task contract is missing: {}".format(", ".join(missing))
        )
    inputs = contract.get("inputs", [])
    acceptance = contract.get("acceptance", [])
    dependencies = contract.get("dependencies", [])
    if not isinstance(inputs, list) or not isinstance(acceptance, list):
        raise WorkboardError("inputs and acceptance must be JSON arrays")
    if not isinstance(dependencies, list):
        raise WorkboardError("dependencies must be an array")
    contract["inputs"] = inputs
    contract["acceptance"] = acceptance
    contract["dependencies"] = dependencies
    return contract


def command_task_add(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    contract = load_contract(args)
    run = connection.execute(
        "SELECT run_id FROM runs WHERE run_id = ?", (args.run_id,)
    ).fetchone()
    if run is None:
        raise WorkboardError("unknown run: {}".format(args.run_id))
    task_id = args.task_id or new_id("task")
    dependencies = list(dict.fromkeys(contract["dependencies"]))
    now = utc_now()
    try:
        connection.execute("BEGIN IMMEDIATE")
        prerequisite_states = []
        for prerequisite in dependencies:
            if prerequisite == task_id:
                raise WorkboardError("task cannot depend on itself")
            prerequisite_states.append(fetch_task(connection, prerequisite)["status"])
        status = (
            "pending"
            if any(state != "completed" for state in prerequisite_states)
            else "ready"
        )
        connection.execute(
            """
            INSERT INTO tasks(
                task_id, run_id, parent_task_id, title, goal, scope,
                inputs_json, expected_output, acceptance_json, model, effort,
                worktree, branch, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                args.run_id,
                contract.get("parent_task_id"),
                contract["title"],
                contract["goal"],
                contract["scope"],
                json_text(contract["inputs"]),
                contract["expected_output"],
                json_text(contract["acceptance"]),
                contract["model"],
                contract["effort"],
                contract.get("worktree"),
                contract.get("branch"),
                status,
                now,
                now,
            ),
        )
        for prerequisite in dependencies:
            connection.execute(
                """
                INSERT INTO dependencies(task_id, depends_on_task_id)
                VALUES (?, ?)
                """,
                (task_id, prerequisite),
            )
        record_event(
            connection,
            "task_added",
            run_id=args.run_id,
            task_id=task_id,
            payload={"status": status, "dependencies": dependencies},
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "database": str(database),
        "run_id": args.run_id,
        "task_id": task_id,
        "status": status,
    }


def command_task_bind(
    connection: sqlite3.Connection,
    _database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        if task["assigned_agent_id"] and task["assigned_agent_id"] != args.agent_id:
            raise WorkboardError(
                "task is already bound to {}".format(task["assigned_agent_id"])
            )
        if task["status"] not in ("ready", "launched", "running"):
            raise WorkboardError(
                "cannot bind task in {} state".format(task["status"])
            )
        status = "running" if task["status"] == "running" else "launched"
        connection.execute(
            """
            UPDATE tasks
            SET assigned_agent_id = ?, agent_type = COALESCE(?, agent_type),
                status = ?, updated_at = ?
            WHERE task_id = ?
            """,
            (args.agent_id, args.agent_type, status, utc_now(), args.task_id),
        )
        record_event(
            connection,
            "task_bound",
            run_id=task["run_id"],
            task_id=args.task_id,
            agent_id=args.agent_id,
            payload={"agent_type": args.agent_type},
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {"task_id": args.task_id, "agent_id": args.agent_id, "status": status}


def lease_deadline(minutes: int = LEASE_MINUTES) -> str:
    return (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
    ).isoformat(timespec="seconds")


def command_task_claim(
    connection: sqlite3.Connection,
    _database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    if args.lease_minutes <= 0:
        raise WorkboardError("--lease-minutes must be positive")
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        if task["assigned_agent_id"] and task["assigned_agent_id"] != args.agent_id:
            raise WorkboardError(
                "task is assigned to {}".format(task["assigned_agent_id"])
            )
        if task["status"] == "running":
            if task["assigned_agent_id"] != args.agent_id:
                raise WorkboardError("task is already running")
        elif task["status"] not in ("ready", "launched"):
            raise WorkboardError(
                "cannot claim task in {} state".format(task["status"])
            )
        missing = incomplete_dependencies(connection, args.task_id)
        if missing:
            raise WorkboardError(
                "prerequisites are incomplete: {}".format(
                    ", ".join(
                        "{} ({})".format(row["task_id"], row["status"])
                        for row in missing
                    )
                )
            )
        deadline = lease_deadline(args.lease_minutes)
        connection.execute(
            """
            UPDATE tasks
            SET assigned_agent_id = ?, agent_type = COALESCE(?, agent_type),
                status = 'running', lease_expires_at = ?, updated_at = ?
            WHERE task_id = ?
            """,
            (
                args.agent_id,
                args.agent_type,
                deadline,
                utc_now(),
                args.task_id,
            ),
        )
        record_event(
            connection,
            "task_claimed",
            run_id=task["run_id"],
            task_id=args.task_id,
            agent_id=args.agent_id,
            payload={"lease_expires_at": deadline},
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "task_id": args.task_id,
        "agent_id": args.agent_id,
        "status": "running",
        "lease_expires_at": deadline,
    }


def require_assignee(task: sqlite3.Row, agent_id: str) -> None:
    if task["assigned_agent_id"] != agent_id:
        raise WorkboardError(
            "task is assigned to {}, not {}".format(
                task["assigned_agent_id"] or "nobody", agent_id
            )
        )


def command_task_heartbeat(
    connection: sqlite3.Connection,
    _database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    if args.lease_minutes <= 0:
        raise WorkboardError("--lease-minutes must be positive")
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        require_assignee(task, args.agent_id)
        if task["status"] != "running":
            raise WorkboardError(
                "cannot heartbeat task in {} state".format(task["status"])
            )
        deadline = lease_deadline(args.lease_minutes)
        connection.execute(
            """
            UPDATE tasks SET lease_expires_at = ?, updated_at = ?
            WHERE task_id = ?
            """,
            (deadline, utc_now(), args.task_id),
        )
        record_event(
            connection,
            "task_heartbeat",
            run_id=task["run_id"],
            task_id=args.task_id,
            agent_id=args.agent_id,
            payload={"lease_expires_at": deadline, "progress": args.progress or ""},
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "task_id": args.task_id,
        "status": "running",
        "lease_expires_at": deadline,
    }


def command_task_block(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        if args.agent_id:
            require_assignee(task, args.agent_id)
        if task["status"] not in ("launched", "running", "ready"):
            raise WorkboardError(
                "cannot block task in {} state".format(task["status"])
            )
        now = utc_now()
        connection.execute(
            """
            UPDATE tasks
            SET status = 'blocked', lease_expires_at = NULL, blocker = ?,
                next_action = ?, summary = COALESCE(?, summary), updated_at = ?,
                completed_at = ?
            WHERE task_id = ?
            """,
            (
                args.reason,
                args.next_action,
                args.summary,
                now,
                now,
                args.task_id,
            ),
        )
        record_event(
            connection,
            "task_blocked",
            run_id=task["run_id"],
            task_id=args.task_id,
            agent_id=args.agent_id,
            payload={"reason": args.reason, "next_action": args.next_action},
        )
        record_artifact_references(
            connection, args.task_id, args.changed_file, args.validation_file
        )
        handoff = write_handoff(connection, database, args.task_id)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "task_id": args.task_id,
        "status": "blocked",
        "handoff": str(handoff),
    }


def list_argument(values: Sequence[str], encoded: Optional[str]) -> List[str]:
    if encoded is not None:
        parsed = json.loads(encoded)
        if not isinstance(parsed, list):
            raise WorkboardError("expected a JSON array")
        return [str(value) for value in parsed]
    return list(values)


def command_task_complete(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    validation = list_argument(args.validation, args.validation_json)
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        if args.agent_id:
            require_assignee(task, args.agent_id)
        if task["status"] not in ("launched", "running", "ready"):
            raise WorkboardError(
                "cannot complete task in {} state".format(task["status"])
            )
        now = utc_now()
        connection.execute(
            """
            UPDATE tasks
            SET status = 'completed', lease_expires_at = NULL, summary = ?,
                validation_json = ?, blocker = NULL, next_action = NULL,
                updated_at = ?, completed_at = ?
            WHERE task_id = ?
            """,
            (args.summary, json_text(validation), now, now, args.task_id),
        )
        record_event(
            connection,
            "task_completed",
            run_id=task["run_id"],
            task_id=args.task_id,
            agent_id=args.agent_id,
            payload={"validation": validation},
        )
        record_artifact_references(
            connection, args.task_id, args.changed_file, args.validation_file
        )
        made_ready = refresh_ready_tasks(connection)
        handoff = write_handoff(connection, database, args.task_id)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "task_id": args.task_id,
        "status": "completed",
        "handoff": str(handoff),
        "made_ready": made_ready,
    }


def command_task_cancel(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    try:
        connection.execute("BEGIN IMMEDIATE")
        task = fetch_task(connection, args.task_id)
        if task["status"] in ("completed", "cancelled"):
            if task["status"] == "cancelled":
                connection.rollback()
                return {"task_id": args.task_id, "status": "cancelled"}
            raise WorkboardError("completed tasks cannot be cancelled")
        now = utc_now()
        connection.execute(
            """
            UPDATE tasks
            SET status = 'cancelled', lease_expires_at = NULL, blocker = ?,
                summary = COALESCE(summary, ?), updated_at = ?, completed_at = ?
            WHERE task_id = ?
            """,
            (args.reason, args.reason, now, now, args.task_id),
        )
        record_event(
            connection,
            "task_cancelled",
            run_id=task["run_id"],
            task_id=args.task_id,
            payload={"reason": args.reason},
        )
        handoff = write_handoff(connection, database, args.task_id)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {
        "task_id": args.task_id,
        "status": "cancelled",
        "handoff": str(handoff),
    }


def task_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    result = dict(row)
    for field in ("inputs_json", "acceptance_json", "validation_json"):
        result[field[:-5]] = json.loads(result.pop(field))
    return result


def command_status(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    clauses = []
    values: List[Any] = []
    if args.run_id:
        clauses.append("task.run_id = ?")
        values.append(args.run_id)
    if args.task_id:
        clauses.append("task.task_id = ?")
        values.append(args.task_id)
    if args.active:
        clauses.append(
            "task.status IN ('pending','ready','launched','running','blocked','stale')"
        )
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = list(
        connection.execute(
            """
            SELECT task.*
            FROM tasks task
            {}
            ORDER BY task.created_at, task.task_id
            """.format(
                where
            ),
            values,
        )
    )
    tasks = []
    for row in rows:
        item = task_to_dict(row)
        item["dependencies"] = [
            dependency["depends_on_task_id"]
            for dependency in connection.execute(
                """
                SELECT depends_on_task_id FROM dependencies
                WHERE task_id = ? ORDER BY depends_on_task_id
                """,
                (row["task_id"],),
            )
        ]
        tasks.append(item)
    return {"database": str(database), "count": len(tasks), "tasks": tasks}


def command_reconcile(
    connection: sqlite3.Connection,
    _database: Path,
    _storage: Dict[str, str],
    _args: argparse.Namespace,
) -> Dict[str, Any]:
    try:
        connection.execute("BEGIN IMMEDIATE")
        now = utc_now()
        expired = list(
            connection.execute(
                """
                SELECT * FROM tasks
                WHERE status = 'running'
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < ?
                """,
                (now,),
            )
        )
        stale = []
        for task in expired:
            connection.execute(
                """
                UPDATE tasks
                SET status = 'stale', lease_expires_at = NULL, updated_at = ?
                WHERE task_id = ?
                """,
                (now, task["task_id"]),
            )
            record_event(
                connection,
                "task_stale",
                run_id=task["run_id"],
                task_id=task["task_id"],
                agent_id=task["assigned_agent_id"],
                payload={"reason": "lease_expired"},
            )
            stale.append(task["task_id"])
        ready = refresh_ready_tasks(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return {"stale": stale, "made_ready": ready}


def command_export(
    connection: sqlite3.Connection,
    _database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    artifact = connection.execute(
        """
        SELECT path FROM artifacts
        WHERE task_id = ? AND kind = 'handoff'
        ORDER BY created_at DESC LIMIT 1
        """,
        (args.task_id,),
    ).fetchone()
    if artifact is None:
        raise WorkboardError("task has no generated handoff")
    source = Path(artifact["path"])
    if not source.is_file():
        raise WorkboardError("handoff is missing: {}".format(source))
    target = Path(args.to).expanduser()
    if target.exists() and target.is_dir():
        target = target / source.name
    if target.exists() and not args.force:
        raise WorkboardError(
            "export target exists; pass --force to replace it: {}".format(target)
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(target))
    return {"task_id": args.task_id, "exported": str(target.resolve())}


def command_gc(
    connection: sqlite3.Connection,
    database: Path,
    _storage: Dict[str, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    if args.older_than < 0:
        raise WorkboardError("--older-than must be non-negative")
    cutoff = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.older_than)
    ).isoformat(timespec="seconds")
    try:
        connection.execute("BEGIN IMMEDIATE")
        tasks = list(
            connection.execute(
                """
                SELECT task_id FROM tasks
                WHERE status IN ('completed', 'cancelled', 'stale')
                  AND updated_at < ?
                  AND NOT EXISTS (
                      SELECT 1 FROM dependencies
                      WHERE dependencies.depends_on_task_id = tasks.task_id
                  )
                """,
                (cutoff,),
            )
        )
        task_ids = [row["task_id"] for row in tasks]
        handoffs = list(
            connection.execute(
                """
                SELECT path FROM artifacts
                WHERE task_id IN (
                    SELECT task_id FROM tasks
                    WHERE status IN ('completed', 'cancelled', 'stale')
                      AND updated_at < ?
                      AND NOT EXISTS (
                          SELECT 1 FROM dependencies
                          WHERE dependencies.depends_on_task_id = tasks.task_id
                      )
                )
                """,
                (cutoff,),
            )
        )
        for task_id in task_ids:
            connection.execute("DELETE FROM tasks WHERE task_id = ?", (task_id,))
        removed_runs = connection.execute(
            """
            DELETE FROM runs
            WHERE status = 'closed' AND updated_at < ?
              AND NOT EXISTS (
                  SELECT 1 FROM tasks WHERE tasks.run_id = runs.run_id
              )
            """,
            (cutoff,),
        ).rowcount
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    removed_files = []
    for row in handoffs:
        path = Path(row["path"])
        try:
            path.relative_to(database.parent / "handoffs")
            if path.is_file():
                path.unlink()
                removed_files.append(str(path))
        except (OSError, ValueError):
            continue
    return {
        "deleted_tasks": task_ids,
        "deleted_runs": removed_runs,
        "deleted_handoffs": removed_files,
    }


def compact_summary(connection: sqlite3.Connection, database: Path) -> str:
    rows = list(
        connection.execute(
            """
            SELECT task_id, title, status, assigned_agent_id
            FROM tasks
            WHERE status IN ('pending','ready','launched','running','blocked','stale')
            ORDER BY
                CASE status
                    WHEN 'running' THEN 0
                    WHEN 'blocked' THEN 1
                    WHEN 'launched' THEN 2
                    WHEN 'ready' THEN 3
                    WHEN 'pending' THEN 4
                    ELSE 5
                END,
                updated_at DESC
            LIMIT 8
            """
        )
    )
    lines = ["Agent workboard: {}".format(database)]
    if not rows:
        lines.append("No active tasks.")
    else:
        for row in rows:
            agent = " @{}".format(row["assigned_agent_id"]) if row[
                "assigned_agent_id"
            ] else ""
            lines.append(
                "- {} [{}] {}{}".format(
                    row["task_id"], row["status"], row["title"], agent
                )
            )
        lines.append("Run `workboard.py status --active --json` for details.")
    summary = "\n".join(lines)
    if len(summary) > 1200:
        summary = summary[:1197] + "..."
    return summary


def hook_output(event: str, context: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": context,
                }
            }
        )
    )


def session_upsert(
    connection: sqlite3.Connection, payload: Dict[str, Any], status: str
) -> None:
    session_id = payload.get("session_id")
    if not session_id:
        return
    now = utc_now()
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, cwd, status, source, model, permission_mode,
            started_at, last_seen_at, ended_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            cwd = excluded.cwd,
            status = excluded.status,
            source = COALESCE(excluded.source, sessions.source),
            model = COALESCE(excluded.model, sessions.model),
            permission_mode = COALESCE(
                excluded.permission_mode, sessions.permission_mode
            ),
            last_seen_at = excluded.last_seen_at,
            ended_at = excluded.ended_at
        """,
        (
            session_id,
            payload.get("cwd") or os.getcwd(),
            status,
            payload.get("source"),
            payload.get("model"),
            payload.get("permission_mode"),
            now,
            now,
            now if status == "closed" else None,
        ),
    )


def task_for_agent(
    connection: sqlite3.Connection, agent_id: str
) -> Optional[sqlite3.Row]:
    return connection.execute(
        """
        SELECT * FROM tasks
        WHERE assigned_agent_id = ?
        ORDER BY
            CASE status
                WHEN 'running' THEN 0
                WHEN 'launched' THEN 1
                WHEN 'ready' THEN 2
                ELSE 3
            END,
            updated_at DESC
        LIMIT 1
        """,
        (agent_id,),
    ).fetchone()


def hook_main(args: argparse.Namespace) -> int:
    try:
        payload = json.load(sys.stdin)
        event = payload.get("hook_event_name")
        cwd = payload.get("cwd") or args.cwd or os.getcwd()
        database, _storage = resolve_database(cwd, args.database)
        connection = connect(database)
        try:
            if event == "SessionStart":
                session_upsert(connection, payload, "active")
                record_event(
                    connection,
                    "session_started",
                    session_id=payload.get("session_id"),
                    payload={"source": payload.get("source")},
                )
                connection.commit()
                hook_output(event, compact_summary(connection, database))
            elif event == "SubagentStart":
                session_upsert(connection, payload, "active")
                agent_id = payload.get("agent_id")
                record_event(
                    connection,
                    "subagent_started",
                    session_id=payload.get("session_id"),
                    agent_id=agent_id,
                    payload={"agent_type": payload.get("agent_type")},
                )
                connection.commit()
                script = str(Path(__file__).resolve())
                context = (
                    "Agent workboard database: {database}\n"
                    "Parent session: {session}\n"
                    "Subagent ID: {agent}\n"
                    "Find WORKBOARD_TASK_ID in your launch prompt. Before work, claim "
                    "it atomically with:\n"
                    "`{python} {script} --db {database} task claim "
                    "--task-id <TASK_ID> --agent-id {agent}`\n"
                    "Record concise progress with `task heartbeat`; finish with "
                    "`task complete` or `task block`. Never store secrets, transcripts, "
                    "or unrestricted tool output."
                ).format(
                    database=database,
                    session=payload.get("session_id") or "unknown",
                    agent=agent_id or "unknown",
                    python=sys.executable,
                    script=script,
                )
                hook_output(event, context[:1200])
            elif event == "SubagentStop":
                agent_id = payload.get("agent_id")
                task = task_for_agent(connection, agent_id) if agent_id else None
                if task is None or task["status"] in TERMINAL_STATES:
                    print("{}")
                elif payload.get("stop_hook_active"):
                    now = utc_now()
                    connection.execute(
                        """
                        UPDATE tasks
                        SET status = 'stale', lease_expires_at = NULL, updated_at = ?
                        WHERE task_id = ?
                        """,
                        (now, task["task_id"]),
                    )
                    record_event(
                        connection,
                        "task_stale",
                        run_id=task["run_id"],
                        task_id=task["task_id"],
                        session_id=payload.get("session_id"),
                        agent_id=agent_id,
                        payload={"reason": "subagent_stop_loop_guard"},
                    )
                    connection.commit()
                    print("{}")
                else:
                    print(
                        json.dumps(
                            {
                                "decision": "block",
                                "reason": (
                                    "Before exiting, update workboard task {} as "
                                    "completed, blocked, or cancelled. Use the database "
                                    "{} and keep the record concise."
                                ).format(task["task_id"], database),
                            }
                        )
                    )
            elif event == "SessionEnd":
                session_upsert(connection, payload, "closed")
                now = utc_now()
                connection.execute(
                    """
                    UPDATE runs
                    SET status = 'closed', updated_at = ?, ended_at = ?
                    WHERE session_id = ? AND status = 'active'
                    """,
                    (now, now, payload.get("session_id")),
                )
                record_event(
                    connection,
                    "session_closed",
                    session_id=payload.get("session_id"),
                    payload={"reason": payload.get("reason")},
                )
                connection.commit()
            else:
                raise WorkboardError("unsupported hook event: {}".format(event))
        finally:
            connection.close()
        return 0
    except Exception as exc:
        print("agent-workboard hook: {}".format(exc), file=sys.stderr)
        if "payload" in locals() and payload.get("hook_event_name") == "SubagentStop":
            print("{}")
        return 0


def add_database_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        dest="database",
        help="explicit workboard path; otherwise resolve it from --cwd/current cwd",
    )
    parser.add_argument("--cwd", help="project directory used for path resolution")
    parser.add_argument("--json", action="store_true", help="emit JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    add_database_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init")
    init_parser.set_defaults(handler=command_init)

    run_parser = commands.add_parser("run")
    run_commands = run_parser.add_subparsers(dest="run_command", required=True)
    run_start = run_commands.add_parser("start")
    run_start.add_argument("--title", required=True)
    run_start.add_argument("--session-id")
    run_start.add_argument("--run-id")
    run_start.set_defaults(handler=command_run_start)

    task_parser = commands.add_parser("task")
    task_commands = task_parser.add_subparsers(dest="task_command", required=True)
    task_add = task_commands.add_parser("add")
    task_add.add_argument("--run-id", required=True)
    task_add.add_argument("--task-id")
    task_add.add_argument("--contract-file")
    task_add.add_argument("--title")
    task_add.add_argument("--goal")
    task_add.add_argument("--scope")
    task_add.add_argument("--inputs-json")
    task_add.add_argument("--expected-output")
    task_add.add_argument("--acceptance-json")
    task_add.add_argument("--model")
    task_add.add_argument("--effort")
    task_add.add_argument("--depends-on", action="append", default=[])
    task_add.add_argument("--worktree")
    task_add.add_argument("--branch")
    task_add.add_argument("--parent-task-id")
    task_add.set_defaults(handler=command_task_add)

    task_bind = task_commands.add_parser("bind")
    task_bind.add_argument("--task-id", required=True)
    task_bind.add_argument("--agent-id", required=True)
    task_bind.add_argument("--agent-type")
    task_bind.set_defaults(handler=command_task_bind)

    task_claim = task_commands.add_parser("claim")
    task_claim.add_argument("--task-id", required=True)
    task_claim.add_argument("--agent-id", required=True)
    task_claim.add_argument("--agent-type")
    task_claim.add_argument("--lease-minutes", type=int, default=LEASE_MINUTES)
    task_claim.set_defaults(handler=command_task_claim)

    heartbeat = task_commands.add_parser("heartbeat")
    heartbeat.add_argument("--task-id", required=True)
    heartbeat.add_argument("--agent-id", required=True)
    heartbeat.add_argument("--lease-minutes", type=int, default=LEASE_MINUTES)
    heartbeat.add_argument("--progress")
    heartbeat.set_defaults(handler=command_task_heartbeat)

    block = task_commands.add_parser("block")
    block.add_argument("--task-id", required=True)
    block.add_argument("--agent-id")
    block.add_argument("--reason", required=True)
    block.add_argument("--next-action", required=True)
    block.add_argument("--summary")
    block.add_argument("--changed-file", action="append", default=[])
    block.add_argument("--validation-file", action="append", default=[])
    block.set_defaults(handler=command_task_block)

    complete = task_commands.add_parser("complete")
    complete.add_argument("--task-id", required=True)
    complete.add_argument("--agent-id")
    complete.add_argument("--summary", required=True)
    complete.add_argument("--validation", action="append", default=[])
    complete.add_argument("--validation-json")
    complete.add_argument("--changed-file", action="append", default=[])
    complete.add_argument("--validation-file", action="append", default=[])
    complete.set_defaults(handler=command_task_complete)

    cancel = task_commands.add_parser("cancel")
    cancel.add_argument("--task-id", required=True)
    cancel.add_argument("--reason", required=True)
    cancel.set_defaults(handler=command_task_cancel)

    status = commands.add_parser("status")
    status.add_argument("--run-id")
    status.add_argument("--task-id")
    status.add_argument("--active", action="store_true")
    status.set_defaults(handler=command_status)

    reconcile = commands.add_parser("reconcile")
    reconcile.set_defaults(handler=command_reconcile)

    export = commands.add_parser("export")
    export.add_argument("--task-id", required=True)
    export.add_argument("--to", required=True)
    export.add_argument("--force", action="store_true")
    export.set_defaults(handler=command_export)

    gc = commands.add_parser("gc")
    gc.add_argument("--older-than", type=int, required=True)
    gc.set_defaults(handler=command_gc)

    hook = commands.add_parser("hook")
    hook.set_defaults(hook_handler=hook_main)
    return parser


def print_result(result: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if "tasks" in result:
        if not result["tasks"]:
            print("No matching tasks.")
            return
        for task in result["tasks"]:
            print(
                "{task_id}\t{status}\t{model}/{effort}\t{title}".format(**task)
            )
        return
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            print("{}={}".format(key, json_text(value)))
        else:
            print("{}={}".format(key, value))


def main(argv: Optional[Sequence[str]] = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "hook_handler"):
        return args.hook_handler(args)
    cwd = args.cwd or os.getcwd()
    try:
        database, storage = resolve_database(cwd, args.database)
        connection = connect(database)
        try:
            result = args.handler(connection, database, storage, args)
        finally:
            connection.close()
        print_result(result, args.json)
        return 0
    except (WorkboardError, json.JSONDecodeError, OSError, sqlite3.Error) as exc:
        print("agent-workboard: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
