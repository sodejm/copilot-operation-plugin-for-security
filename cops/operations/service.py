"""Explicit offline dispatch, with no user-selected paths, imports or commands."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from threading import Event, Lock

from cops._schema_validation import SchemaValidationError, validate

from .catalog import ASSESSMENTS, RESULT_SCHEMA, SOC_ACTIONS, declarations
from .contracts import OperationError, encode, response

ROOT = Path(__file__).resolve().parents[2]
SOC_ROOT = ROOT / "plugins/detection-hunting/soc-investigation-workbench"
_IMPORT_LOCK = Lock()


def _soc_module(root: Path, name: str):
    # The root comes from installation configuration, never an invocation argument.
    # Private package names prevent collisions with an ambient investigationwb.
    root = root.resolve()
    prefix = "_cops_soc_" + hashlib.sha256(str(root).encode()).hexdigest()[:16]
    with _IMPORT_LOCK:
        for module_name in ("", "engine", "files", name):
            full_name = prefix + ("." + module_name if module_name else "")
            if full_name in sys.modules:
                continue
            path = root / "investigationwb" / (module_name + ".py" if module_name else "__init__.py")
            if not path.is_file():
                raise OperationError("missing_prerequisite")
            spec = importlib.util.spec_from_file_location(
                full_name,
                path,
                submodule_search_locations=[str(path.parent)] if not module_name else None,
            )
            if spec is None or spec.loader is None:
                raise OperationError("missing_prerequisite")
            module = importlib.util.module_from_spec(spec)
            sys.modules[full_name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(full_name, None)
                raise
    return sys.modules[prefix + "." + name]


class OperationService:
    def __init__(self, *, soc_root: Path = SOC_ROOT, run_store=None, installed_root: Path = ROOT, runtime_config=None):
        self.soc_root = soc_root
        self._catalog = {item["operation_id"]: item for item in declarations()}
        self._run_store = run_store
        self._installed_root, self._runtime_config = installed_root, runtime_config
        self._runtime_instance = None
        self._runtime_lock = Lock()

    def _runtime(self):
        from .runtime import LocalRuntime, load_configuration

        with self._runtime_lock:
            if self._runtime_instance is None:
                store, root = self._run_store, self._installed_root
                if store is None:
                    store, configured_root = load_configuration(self._runtime_config)
                    root = configured_root or root
                self._runtime_instance = LocalRuntime(self, store, installed_root=root)
            return self._runtime_instance

    def validate_request(self, request, *, require_complete=False):
        encode(request)
        if (
            not isinstance(request, dict)
            or set(request) - {"schema_version", "operation_id", "request_id", "arguments"}
            or request.get("schema_version") != "cops.operation-request/v1"
        ):
            raise OperationError("invalid_request")
        request_id = request.get("request_id")
        if request_id is not None:
            from .runs import alias

            alias(request_id)
        identifier = request.get("operation_id")
        if not isinstance(identifier, str) or identifier not in self._catalog:
            raise OperationError("unknown_operation")
        arguments = request.get("arguments")
        if not isinstance(arguments, dict):
            raise OperationError("invalid_arguments")
        schema = deepcopy(self._catalog[identifier]["input_schema"])
        required = schema["required"]
        schema["required"] = []
        validate(arguments, schema)
        missing = sorted(set(required) - arguments.keys())
        if missing and require_complete:
            raise OperationError("missing_input")
        return identifier, request_id, arguments, missing

    def operation_binding(self, identifier):
        from .runs import digest

        paths = [Path(__file__), Path(__file__).with_name("catalog.py"), Path(__file__).with_name("contracts.py")]
        if identifier.startswith("cops.work."):
            paths.append(Path(__file__).with_name("exploration.py"))
        elif identifier.startswith("cops.assess."):
            paths.extend(sorted((ROOT / "cops/assessments").glob("*.py")))
        elif identifier.startswith("cops.soc."):
            paths.extend(
                self.soc_root / name
                for name in (
                    "investigationwb/engine.py",
                    "investigationwb/files.py",
                    "investigationwb/vendor.py",
                    "vendor-lock.json",
                )
            )
        fingerprints = []
        for path in paths:
            try:
                with path.open("rb") as stream:
                    raw = stream.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise OperationError("implementation_size_limit")
            except OSError as exc:
                raise OperationError("missing_prerequisite") from exc
            fingerprints.append(hashlib.sha256(raw).hexdigest())
        return digest({"declaration": self._catalog[identifier], "implementation_files": fingerprints})

    def invoke(self, request, *, cancelled: Event | None = None):
        identifier = request_id = None
        try:
            identifier, request_id, arguments, missing = self.validate_request(request)
            if missing:
                return response(
                    identifier,
                    request_id,
                    status="needs_input",
                    code="missing_input",
                    next_action="Supply required fields: " + ", ".join(missing),
                )
            if cancelled is not None and cancelled.is_set():
                raise OperationError("cancelled")
            persistent = identifier.startswith(("cops.run.", "cops.delegate."))
            if persistent:
                from .runtime import result_status

                result = self._runtime().process(identifier, deepcopy(arguments))
                status = result_status(result)
            else:
                result = self._dispatch(identifier, deepcopy(arguments))
                status = "blocked" if identifier == "cops.work.escalate" else "succeeded"
            if cancelled is not None and cancelled.is_set():
                raise OperationError("cancelled")
            escalated = identifier == "cops.work.escalate"
            next_action = None
            if escalated:
                next_action = "Review the proposal with a human. The headless interface grants no execution authority."
            document = response(identifier, request_id, status=status, result=result, next_action=next_action)
            validate(document, RESULT_SCHEMA)
            encode(document)
            return document
        except OperationError as exc:
            blocked = {
                "missing_prerequisite",
                "cancelled",
                "runtime_not_configured",
                "run_busy",
                "unknown_operation",
                "offline_run_required",
            }
            return response(
                identifier,
                request_id,
                status="blocked" if exc.code in blocked else "failed",
                code=exc.code,
                result=exc.result,
                next_action="Inspect the operation inputs, run state, and installed prerequisites.",
            )
        except SchemaValidationError, ValueError, TypeError, KeyError, OSError, ImportError, RecursionError:
            return response(
                identifier,
                request_id,
                status="failed",
                code="invalid_input_or_runtime",
                next_action="Validate supplied data and installed prerequisites; no input values are echoed.",
            )

        except Exception:
            return response(
                identifier,
                request_id,
                status="failed",
                code="internal_error",
                next_action="Inspect the installed runtime; no input values are echoed.",
            )

    def _dispatch(self, identifier, arguments):
        if identifier.startswith("cops.features."):
            from .inventory import query

            return query(self._installed_root, **arguments)
        if identifier.startswith("cops.work."):
            from .exploration import process

            return process(identifier.removeprefix("cops.work."), arguments)
        if identifier.startswith("cops.assess."):
            capability = identifier.removeprefix("cops.assess.")
            if capability not in ASSESSMENTS:
                raise OperationError("unknown_operation")
            from cops.assessments import assess
            from cops.assessments.__main__ import _decode_artifacts

            return assess(capability, _decode_artifacts(arguments["artifacts"]), as_of=arguments["as_of"])
        action = identifier.removeprefix("cops.soc.")
        if action not in SOC_ACTIONS:
            raise OperationError("unknown_operation")
        engine = _soc_module(self.soc_root, "engine")
        case = arguments["case"]
        if action == "validate":
            engine.validate(case)
            return {"status": "valid", "snapshot_hash": engine.digest(case)}
        if action == "next":
            return engine.next_steps(case)
        if action == "report":
            return engine.report(case)
        if action == "import":
            revised = engine.import_result(case, arguments["observation"])
            return {"case": revised, "snapshot_hash": engine.digest(revised)}
        if action == "revise":
            revised = engine.revise(case, arguments["steps"])
            return {"case": revised, "snapshot_hash": engine.digest(revised)}
        vendor = _soc_module(self.soc_root, "vendor")
        if (
            not (self.soc_root / "vendor-lock.json").is_file()
            or not (self.soc_root / "vendor/sentinel-hunt-workbench").is_dir()
        ):
            raise OperationError("missing_prerequisite")
        return vendor.handoff(case, arguments["step_id"], package=self.soc_root)
