"""Strict, versioned workflow definition contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cops.evidence.canonical import canonical, digest

WORKFLOW_SCHEMA_VERSION = "cops.workflow-definition/v1"
JSON_TYPES = {"string", "integer", "number", "boolean", "object", "array", "null"}


class WorkflowContractError(ValueError):
    """A workflow is structurally or semantically unsafe to execute."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def value_matches_type(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "integer":
        return type(value) is int
    if type_name == "number":
        return type(value) in (int, float) and type(value) is not bool
    if type_name == "boolean":
        return type(value) is bool
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    return value is None


def _keys(value: Any, required: set[str], optional: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        raise WorkflowContractError(code)
    return value


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise WorkflowContractError(code)
    if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value):
        raise WorkflowContractError(code)
    return value


@dataclass(frozen=True)
class WorkflowDefinition:
    """Validated immutable view of a workflow document."""

    _document: dict[str, Any]

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> WorkflowDefinition:
        try:
            copied = deepcopy(document)
            canonical(copied, max_bytes=2 * 1024 * 1024)
        except Exception as exc:
            raise WorkflowContractError("invalid_json") from exc
        _validate_workflow(copied)
        return cls(copied)

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(self._document)

    @property
    def workflow_id(self) -> str:
        return self._document["workflow_id"]

    @property
    def engagement_id(self) -> str:
        return self._document["engagement_id"]

    @property
    def scenario_id(self) -> str:
        return self._document["scenario_id"]

    @property
    def stages(self) -> list[dict[str, Any]]:
        return deepcopy(self._document["stages"])

    @property
    def inputs(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self._document["inputs"])

    @property
    def outputs(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self._document["outputs"])

    @property
    def budget(self) -> dict[str, int]:
        return deepcopy(self._document["budget"])

    @property
    def definition_digest(self) -> str:
        return digest(self._document)

    def stage(self, stage_id: str) -> dict[str, Any]:
        for stage in self._document["stages"]:
            if stage["stage_id"] == stage_id:
                return deepcopy(stage)
        raise WorkflowContractError("unknown_stage")


def _validate_workflow(doc: dict[str, Any]) -> None:
    _keys(
        doc,
        {"schema_version", "workflow_id", "engagement_id", "scenario_id", "inputs", "outputs", "budget", "stages"},
        {"description"},
        "workflow_shape",
    )
    if doc["schema_version"] != WORKFLOW_SCHEMA_VERSION:
        raise WorkflowContractError("schema_version")
    for field in ("workflow_id", "engagement_id", "scenario_id"):
        _identifier(doc[field], field)
    if "description" in doc and (not isinstance(doc["description"], str) or len(doc["description"]) > 4096):
        raise WorkflowContractError("description")
    _validate_type_map(doc["inputs"], allow_source=False)
    budget = _keys(
        doc["budget"],
        {"max_stages", "max_total_attempts", "max_output_bytes", "max_evidence_refs"},
        set(),
        "budget_shape",
    )
    bounds = {
        "max_stages": 256,
        "max_total_attempts": 1024,
        "max_output_bytes": 104_857_600,
        "max_evidence_refs": 10000,
    }
    if any(type(budget[key]) is not int or not 1 <= budget[key] <= maximum for key, maximum in bounds.items()):
        raise WorkflowContractError("budget_value")
    stages = doc["stages"]
    if not isinstance(stages, list) or not stages or len(stages) > budget["max_stages"]:
        raise WorkflowContractError("stage_budget")
    stage_map: dict[str, dict[str, Any]] = {}
    for stage in stages:
        _validate_stage(stage)
        stage_id = stage["stage_id"]
        if stage_id in stage_map:
            raise WorkflowContractError("duplicate_stage")
        stage_map[stage_id] = stage
    if sum(stage.get("retry", {}).get("max_attempts", 1) for stage in stages) > budget["max_total_attempts"]:
        raise WorkflowContractError("attempt_budget")
    _validate_graph(stage_map, doc["inputs"])
    _validate_workflow_outputs(doc["outputs"], stage_map)


def _validate_type_map(value: Any, *, allow_source: bool) -> None:
    if not isinstance(value, dict) or len(value) > 256:
        raise WorkflowContractError("type_map")
    for name, spec in value.items():
        _identifier(name, "field_name")
        optional = {"required", "default"} if not allow_source else {"source"}
        required = {"type", "source"} if allow_source else {"type"}
        _keys(spec, required, optional, "type_spec")
        if spec["type"] not in JSON_TYPES:
            raise WorkflowContractError("unknown_type")
        if "required" in spec and type(spec["required"]) is not bool:
            raise WorkflowContractError("required_flag")
        if "default" in spec and not value_matches_type(spec["default"], spec["type"]):
            raise WorkflowContractError("default_type")
        if allow_source and not isinstance(spec["source"], str):
            raise WorkflowContractError("output_source")


def _validate_stage(stage: Any) -> None:
    _keys(
        stage,
        {"stage_id", "depends_on", "inputs", "outputs", "action"},
        {"condition", "retry"},
        "stage_shape",
    )
    _identifier(stage["stage_id"], "stage_id")
    if not isinstance(stage["depends_on"], list) or not all(isinstance(item, str) for item in stage["depends_on"]):
        raise WorkflowContractError("dependencies")
    if len(set(stage["depends_on"])) != len(stage["depends_on"]):
        raise WorkflowContractError("duplicate_dependency")
    _validate_bindings(stage["inputs"])
    _validate_type_map(stage["outputs"], allow_source=False)
    if any("default" in value or "required" in value for value in stage["outputs"].values()):
        raise WorkflowContractError("stage_output_spec")
    action = _keys(
        stage["action"],
        {"target", "specialist_id", "tool", "tool_version", "action", "timeout_seconds", "limits"},
        {
            "credential_references",
            "expected_evidence",
            "side_effects",
            "platform_prerequisites",
            "cleanup",
            "egress_policy",
            "idempotent",
        },
        "action_shape",
    )
    for field in ("target", "specialist_id", "tool", "tool_version", "action"):
        if not isinstance(action[field], str) or not action[field] or "${" in action[field]:
            raise WorkflowContractError("literal_action_binding")
    if type(action["timeout_seconds"]) is not int or not 1 <= action["timeout_seconds"] <= 86400:
        raise WorkflowContractError("timeout")
    if "idempotent" in action and type(action["idempotent"]) is not bool:
        raise WorkflowContractError("idempotent_flag")
    limits = _keys(
        action["limits"],
        {"max_duration_seconds", "max_output_bytes", "egress_allowed"},
        set(),
        "limits_shape",
    )
    if type(limits["max_duration_seconds"]) is not int or not 1 <= limits["max_duration_seconds"] <= 604800:
        raise WorkflowContractError("limits")
    if type(limits["max_output_bytes"]) is not int or not 1 <= limits["max_output_bytes"] <= 104857600:
        raise WorkflowContractError("limits")
    if type(limits["egress_allowed"]) is not bool:
        raise WorkflowContractError("limits")
    for field in ("credential_references", "expected_evidence", "side_effects", "platform_prerequisites"):
        if field in action and (
            not isinstance(action[field], list) or not all(isinstance(item, str) for item in action[field])
        ):
            raise WorkflowContractError("action_list")
    if "cleanup" in action and not isinstance(action["cleanup"], dict):
        raise WorkflowContractError("cleanup")
    if "egress_policy" in action and not isinstance(action["egress_policy"], dict):
        raise WorkflowContractError("egress_policy")
    retry = stage.get("retry", {"max_attempts": 1})
    _keys(retry, {"max_attempts"}, set(), "retry_shape")
    if type(retry["max_attempts"]) is not int or not 1 <= retry["max_attempts"] <= 10:
        raise WorkflowContractError("retry_value")
    if "condition" in stage:
        condition = _keys(stage["condition"], {"source", "operator"}, {"value"}, "condition_shape")
        if condition["operator"] not in {"exists", "eq", "not_eq"}:
            raise WorkflowContractError("condition_operator")
        if condition["operator"] != "exists" and "value" not in condition:
            raise WorkflowContractError("condition_value")


def _validate_bindings(bindings: Any) -> None:
    if not isinstance(bindings, dict) or len(bindings) > 256:
        raise WorkflowContractError("bindings")
    for name, binding in bindings.items():
        _identifier(name, "binding_name")
        if not isinstance(binding, dict) or set(binding) not in ({"type", "source"}, {"type", "value"}):
            raise WorkflowContractError("binding_shape")
        if binding["type"] not in JSON_TYPES:
            raise WorkflowContractError("unknown_type")
        if "source" in binding and not isinstance(binding["source"], str):
            raise WorkflowContractError("binding_source")
        if "value" in binding:
            if not value_matches_type(binding["value"], binding["type"]):
                raise WorkflowContractError("binding_value_type")
            try:
                canonical(binding["value"], max_bytes=1_048_576)
            except Exception as exc:
                raise WorkflowContractError("binding_value") from exc


def _parse_source(source: str) -> tuple[str, str, str | None]:
    parts = source.split(".")
    if len(parts) == 3 and parts[:2] == ["workflow", "input"]:
        return "workflow", parts[2], None
    if len(parts) == 4 and parts[0] == "stage" and parts[2] == "output":
        return "stage", parts[1], parts[3]
    raise WorkflowContractError("invalid_source")


def _source_type(source: str, stage_map: dict[str, dict[str, Any]], workflow_inputs: dict[str, Any]) -> str:
    kind, name, output = _parse_source(source)
    if kind == "workflow":
        if name not in workflow_inputs:
            raise WorkflowContractError("missing_input_ref")
        return workflow_inputs[name]["type"]
    if name not in stage_map or output not in stage_map[name]["outputs"]:
        raise WorkflowContractError("missing_output_ref")
    return stage_map[name]["outputs"][output]["type"]


def _validate_graph(stage_map: dict[str, dict[str, Any]], workflow_inputs: dict[str, Any]) -> None:
    for stage in stage_map.values():
        for dependency in stage["depends_on"]:
            if dependency not in stage_map:
                raise WorkflowContractError("missing_dependency")
        for binding in stage["inputs"].values():
            if "source" in binding and _source_type(binding["source"], stage_map, workflow_inputs) != binding["type"]:
                raise WorkflowContractError("binding_source_type")
            if "source" not in binding:
                continue
            source = binding["source"]
            kind, input_name, _ = _parse_source(source)
            if kind != "workflow":
                continue
            input_spec = workflow_inputs[input_name]
            condition = stage.get("condition", {})
            guarded = condition.get("operator") == "exists" and condition.get("source") == source
            if not input_spec.get("required", True) and "default" not in input_spec and not guarded:
                raise WorkflowContractError("unguarded_optional_input_binding")
        sources = [binding["source"] for binding in stage["inputs"].values() if "source" in binding]
        if "condition" in stage:
            sources.append(stage["condition"]["source"])
            condition = stage["condition"]
            source_type = _source_type(condition["source"], stage_map, workflow_inputs)
            if condition["operator"] != "exists" and not value_matches_type(condition["value"], source_type):
                raise WorkflowContractError("condition_value_type")
        for source in sources:
            kind, owner, _ = _parse_source(source)
            _source_type(source, stage_map, workflow_inputs)
            if kind == "stage" and owner not in stage["depends_on"]:
                raise WorkflowContractError("undeclared_output_dependency")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(stage_id: str) -> None:
        if stage_id in visiting:
            raise WorkflowContractError("dependency_cycle")
        if stage_id in visited:
            return
        visiting.add(stage_id)
        for dependency in stage_map[stage_id]["depends_on"]:
            visit(dependency)
        visiting.remove(stage_id)
        visited.add(stage_id)

    for stage_id in stage_map:
        visit(stage_id)


def _validate_workflow_outputs(outputs: Any, stage_map: dict[str, dict[str, Any]]) -> None:
    _validate_type_map(outputs, allow_source=True)
    for spec in outputs.values():
        kind, _, _ = _parse_source(spec["source"])
        if kind != "stage":
            raise WorkflowContractError("workflow_output_type")
        actual_type = _source_type(spec["source"], stage_map, {})
        if actual_type != spec["type"]:
            raise WorkflowContractError("workflow_output_type")
