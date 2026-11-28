"""Trusted operation declarations. Never import implementation modules here."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .contracts import MAX_BYTES, RESULT_SCHEMA, OperationError

ASSESSMENTS = {
    "application_security": "web-api-assessment-workbench",
    "foundry_security": "foundry-agent-harness",
    "compliance_evidence": "compliance-posture-workbench",
    "forensic_evidence": "incident-response-sandbox",
    "malware_static": "soc-investigation-workbench",
    "cloud_configuration": "cloud-posture-workbench",
    "supply_chain": "supply-chain-cicd-workbench",
    "credential_history": "secrets-remediation-workbench",
    "network_segmentation": "network-segmentation-workbench",
    "transport_identity": "tls-crypto-workbench",
}
SOC_ACTIONS = ("validate", "next", "handoff", "import", "revise", "report")
WORK_ACTIONS = ("request", "note", "escalate")
OFFLINE_OPERATION_IDS = (
    *("cops.assess." + capability for capability in ASSESSMENTS),
    *("cops.soc." + action for action in SOC_ACTIONS),
    *("cops.work." + action for action in WORK_ACTIONS),
)
SOC_PACKAGE = "soc-investigation-workbench"
TEXT = {"type": "string", "minLength": 1, "maxLength": 4096}
ALIAS_SCHEMA = {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,96}$"}
OBJECT = {"type": "object"}
WORK_REQUEST = {
    "type": "object",
    "additionalProperties": False,
    "required": ["task"],
    "properties": {
        "schema_version": {"const": "cops.work-request/v1"},
        "task": TEXT,
        "context": TEXT,
        "artifacts": {"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 256}},
        "notes": {"type": "array", "maxItems": 32, "items": TEXT},
    },
}


def object_schema(properties, required):
    return {"type": "object", "additionalProperties": False, "properties": properties, "required": required}


def _declaration(identifier, owner, description, schema, implementation, feature):
    return {
        "schema_version": "cops.operation/v1",
        "operation_id": identifier,
        "version": "1.0.0",
        "owner": owner,
        "description": description,
        "implementation": implementation,
        "input_schema": schema,
        "output_schema": deepcopy(RESULT_SCHEMA),
        "feature_id": feature,
        "specification": "specs/headless-agent-interface.spec.md",
        "effects": {"network": False, "durable_writes": False, "executes_samples": False},
        "authorization": "supplied_data_only; no execution authority",
        "limits": {"input_bytes": MAX_BYTES, "output_bytes": MAX_BYTES},
        "retry": "pure transformation; resubmit caller-owned input; no durable server session",
        "cancellation": "cooperative; running pure transformation may finish; no external rollback",
        "coverage": "pilot; not package-wide or live-provider acceptance",
    }


def declarations():
    result = []
    artifact = object_schema(
        {
            "artifact_id": {"type": "string", "minLength": 1, "maxLength": 96},
            "kind": {"type": "string", "minLength": 1, "maxLength": 96},
            "content": {},
            "content_b64": {"type": "string", "maxLength": 6_000_000},
            "source_ref": {"type": ["string", "null"], "maxLength": 256},
            "collected_at": {"type": ["string", "null"], "maxLength": 32},
            "sha256": {"type": ["string", "null"], "maxLength": 64},
            "collection_authorized": {"type": ["boolean", "null"]},
            "custody": {"type": "array", "maxItems": 128, "items": OBJECT},
            "framework": {"type": ["string", "null"], "maxLength": 256},
            "framework_version": {"type": ["string", "null"], "maxLength": 96},
        },
        ["artifact_id", "kind"],
    )
    for capability, owner in ASSESSMENTS.items():
        result.append(
            _declaration(
                "cops.assess." + capability,
                owner,
                "Assess supplied offline artifacts: " + capability,
                object_schema(
                    {
                        "artifacts": {"type": "array", "maxItems": 64, "items": artifact},
                        "as_of": {"type": "string", "maxLength": 32},
                    },
                    ["artifacts", "as_of"],
                ),
                "artifact_assessment",
                "offline-" + capability,
            )
        )
    for action in SOC_ACTIONS:
        properties: dict[str, Any] = {"case": OBJECT}
        required = ["case"]
        if action == "handoff":
            properties["step_id"] = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"}
            required.append("step_id")
        if action == "import":
            properties["observation"] = OBJECT
            required.append("observation")
        if action == "revise":
            properties["steps"] = {"type": "array", "maxItems": 1000, "items": OBJECT}
            required.append("steps")
        result.append(
            _declaration(
                "cops.soc." + action,
                SOC_PACKAGE,
                "SOC supplied-case " + action + "; executes no queries",
                object_schema(properties, required),
                "soc_" + action,
                "soc-" + action,
            )
        )
    for action in WORK_ACTIONS:
        schema = (
            deepcopy(WORK_REQUEST)
            if action == "request"
            else object_schema(
                {"request": WORK_REQUEST, "note" if action == "note" else "action": TEXT},
                ["request", "note" if action == "note" else "action"],
            )
        )
        result.append(
            _declaration(
                "cops.work." + action,
                "cops-core",
                "Exploratory " + action + "; no authority or mandatory specialist",
                schema,
                "work_" + action,
                "exploration-" + action,
            )
        )
    request_schema = object_schema(
        {
            "schema_version": {"const": "cops.operation-request/v1"},
            "operation_id": {"enum": list(OFFLINE_OPERATION_IDS)},
            "request_id": ALIAS_SCHEMA,
            "arguments": OBJECT,
        },
        ["schema_version", "operation_id", "arguments"],
    )
    for action in ("create", "status", "resume", "cancel", "recover"):
        if action == "create":
            properties, required = {"request": request_schema, "idempotency_key": ALIAS_SCHEMA}, ["request"]
        else:
            properties, required = {"run_id": ALIAS_SCHEMA}, ["run_id"]
        item = _declaration(
            "cops.run." + action,
            "cops-core",
            "Durable local run " + action,
            object_schema(properties, required),
            "run_" + action,
            "run-" + action,
        )
        item["effects"]["durable_writes"] = True
        item["authorization"] = "installation-owned private runtime; supplied offline data only"
        item["retry"] = "atomic local admission; completed results are reused and expired offline attempts may retry"
        item["cancellation"] = "durable request; a running offline transformation may finish"
        result.append(item)
    for action in ("prepare", "accept"):
        schema = object_schema(
            {
                "task": TEXT,
                "scope_ref": ALIAS_SCHEMA,
                "specialist_id": ALIAS_SCHEMA,
                "skill_id": ALIAS_SCHEMA,
                "operation_id": {"enum": list(OFFLINE_OPERATION_IDS)},
            },
            ["task"],
        )
        if action == "accept":
            schema = object_schema(
                {"delegation_id": ALIAS_SCHEMA, "peer_response": OBJECT}, ["delegation_id", "peer_response"]
            )
        item = _declaration(
            "cops.delegate." + action,
            "cops-core",
            "Optional bound peer delegation " + action,
            schema,
            "delegate_" + action,
            "delegation-" + action,
        )
        item["effects"]["durable_writes"] = True
        item["retry"] = "accept peer response once; informal work notes remain available without this contract"
        result.append(item)
    for action in ("list", "info"):
        schema = object_schema(
            {
                "plugin_id": ALIAS_SCHEMA,
                "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            [],
        )
        if action == "info":
            schema = object_schema(
                {"feature_id": {"type": "string", "minLength": 1, "maxLength": 1024}}, ["feature_id"]
            )
        result.append(
            _declaration(
                "cops.features." + action,
                "cops-core",
                "Inspect source-indexed headless feature coverage",
                schema,
                "features_" + action,
                "features-" + action,
            )
        )
    return deepcopy(result)


def validate_catalog(documents):
    """Require exact reviewed bindings, schemas, effects and unique identities."""
    expected = {item["operation_id"]: item for item in declarations()}
    seen = set()
    for document in documents:
        if not isinstance(document, dict):
            raise OperationError("invalid_catalog")
        identifier = document.get("operation_id")
        if not isinstance(identifier, str) or identifier in seen or expected.get(identifier) != document:
            raise OperationError("invalid_catalog")
        seen.add(identifier)
    if seen != expected.keys():
        raise OperationError("incomplete_catalog")


def tool_name(identifier):
    return identifier.replace(".", "_")
