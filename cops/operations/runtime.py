"""Installation-owned runtime for durable offline operations."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cops._filesystem import open_directory_no_symlinks

from .contracts import OperationError, decode
from .runs import TERMINAL, RunStore, require_offline


def load_configuration(path):
    if path is None:
        raise OperationError("runtime_not_configured")
    descriptor = parent = -1
    try:
        path = Path(path)
        if not path.is_absolute():
            raise OperationError("unsafe_runtime_configuration")
        parent = open_directory_no_symlinks(path.parent)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise OperationError("unsafe_runtime_configuration")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise OperationError("invalid_runtime_configuration")
        document = decode(raw)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "cops.operation-runtime/v1"
            or set(document) - {"schema_version", "state_directory", "installed_root"}
            or not isinstance(document.get("state_directory"), str)
            or not isinstance(document.get("installed_root"), (str, type(None)))
        ):
            raise OperationError("invalid_runtime_configuration")
        state_dir = Path(document["state_directory"])
        installed_root = Path(document["installed_root"]) if document.get("installed_root") is not None else None
        if not state_dir.is_absolute() or (installed_root is not None and not installed_root.is_absolute()):
            raise OperationError("unsafe_runtime_configuration")
        return RunStore(state_dir), installed_root
    except OSError as exc:
        raise OperationError("unsafe_runtime_configuration") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def result_status(result):
    state = result.get("state")
    if state == "running":
        return "partial"
    if state in {"partial", "failed"}:
        return state
    return "succeeded"


def public(record):
    """Expose lifecycle status without accepted inputs or lease capabilities."""
    keys = (
        "schema_version",
        "run_id",
        "operation_id",
        "state",
        "attempt",
        "cancellation_requested",
        "operation_result",
        "evidence_refs",
        "recovery_actions",
    )
    return {key: record[key] for key in keys}


class LocalRuntime:
    def __init__(self, service, run_store, *, installed_root=None):
        self.service, self.store = service, run_store
        self.installed_root = installed_root or Path(__file__).resolve().parents[2]

    def process(self, identifier, arguments):
        if identifier.startswith("cops.delegate."):
            from .delegation import process

            return process(self, identifier.removeprefix("cops.delegate."), arguments)
        if identifier == "cops.run.create":
            request = arguments["request"]
            operation_id = self._offline_operation(request)
            return public(
                self.store.create(
                    operation_id=operation_id,
                    request=request,
                    idempotency_key=arguments.get("idempotency_key"),
                    expected_binding=self.service.operation_binding(operation_id),
                )
            )
        run_id = arguments["run_id"]
        if identifier == "cops.run.status":
            return public(self.store.get(run_id))
        if identifier == "cops.run.resume":
            return self._resume(run_id)
        if identifier == "cops.run.recover":
            return public(self.store.recover(run_id))
        if identifier == "cops.run.cancel":
            return public(self.store.cancel(run_id))
        raise OperationError("unknown_operation")

    def _offline_operation(self, request):
        operation_id, _, _, _ = self.service.validate_request(request, require_complete=True)
        require_offline(operation_id)
        return operation_id

    def _check_binding(self, record):
        operation_id = self._offline_operation(record["request"])
        if (
            operation_id != record["operation_id"]
            or self.service.operation_binding(operation_id) != record["expected_binding"]
        ):
            raise OperationError("run_binding_changed")

    def _resume(self, run_id):
        record = self.store.get(run_id)
        if record["state"] in TERMINAL:
            return public(record)
        self._check_binding(record)
        try:
            lease = self.store.claim(run_id)
        except OperationError as exc:
            if exc.code == "run_terminal":
                return public(self.store.get(run_id))
            raise
        try:
            self._check_binding(lease)
            result = self.service.invoke(lease["request"])
            state = result["status"] if result["status"] in {"succeeded", "partial"} else "failed"
            return public(self.store.finish(run_id, lease["lease_token"], state, result))
        except OperationError as exc:
            if exc.code == "stale_attempt":
                raise
            return public(self.store.finish(run_id, lease["lease_token"], "failed", error={"code": exc.code}))
