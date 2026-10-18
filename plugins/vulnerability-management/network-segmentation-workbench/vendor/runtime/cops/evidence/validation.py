"""Validate the published, deliberately small JSON Schema vocabulary without deps."""
import json
import re
from pathlib import Path

from .canonical import EvidenceError, canonical, digest, timestamp

SCHEMAS = Path(__file__).resolve().parents[2] / "catalog" / "schemas"


def _check(value, schema):
    kinds = {"object": dict, "array": list, "string": str, "integer": int,
             "number": (int, float), "boolean": bool, "null": type(None)}
    types = schema.get("type", list(kinds))
    if isinstance(types, str):
        types = [types]
    if not any(type(value) in (kinds[t] if isinstance(kinds[t], tuple) else (kinds[t],)) for t in types):
        raise EvidenceError("invalid_contract")
    if "const" in schema and value != schema["const"]:
        raise EvidenceError("unsupported_version")
    if "enum" in schema and value not in schema["enum"]:
        raise EvidenceError("invalid_contract")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not set(schema.get("required", [])) <= value.keys():
            raise EvidenceError("missing_provenance")
        if schema.get("additionalProperties") is False and value.keys() - properties.keys():
            raise EvidenceError("invalid_contract")
        for key, item in value.items():
            if key in properties:
                _check(item, properties[key])
    elif isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10000):
            raise EvidenceError("payload_limit")
        if schema.get("uniqueItems") and len({canonical(v) for v in value}) != len(value):
            raise EvidenceError("invalid_contract")
        for item in value:
            _check(item, schema.get("items", {}))
    elif isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 1048576):
            raise EvidenceError("payload_limit")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise EvidenceError("invalid_contract")
        if schema.get("format") == "date-time":
            timestamp(value)
    elif type(value) in (int, float):
        if value < schema.get("minimum", 0) or value > schema.get("maximum", 2**53):
            raise EvidenceError("invalid_contract")


def validate_document(document, schema_name, *, max_bytes=1024 * 1024, max_depth=32):
    canonical(document, max_bytes=max_bytes, max_depth=max_depth)
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    _check(document, schema)


def validate_envelope(item, *, max_bytes=1024 * 1024, max_depth=32):
    validate_document(item, "evidence-envelope.schema.json", max_bytes=max_bytes, max_depth=max_depth)
    for key in ("observed", "emitted"):
        observation = item[key]
        if (observation["at"] is None) != (observation["unknown_reason"] is not None):
            raise EvidenceError("missing_provenance")
    region = item["source"]["region"]
    if (region["value"] is None) != (region["unknown_reason"] is not None):
        raise EvidenceError("missing_provenance")
    if timestamp(item["transformed_at"]) < timestamp(item["acquired_at"]):
        raise EvidenceError("invalid_timestamp")
    unhashed = {k: v for k, v in item.items() if k != "content_hash"}
    if digest(unhashed, max_bytes=max_bytes, max_depth=max_depth) != item["content_hash"]:
        raise EvidenceError("integrity_mismatch")
    source = item["source"]
    if source["scope"] != sorted(source["scope"]):
        raise EvidenceError("invalid_contract")
    identity = ["cops.record/v1", source["product"], source["tenant"], source["scope"],
                source["identity"], source["version"], digest(item["payload"], max_bytes=max_bytes, max_depth=max_depth)]
    if digest(identity, max_bytes=max_bytes) != item["record_id"]:
        raise EvidenceError("integrity_mismatch")
    return item


def validate_receipt(item):
    validate_document(item, "acquisition-receipt.schema.json", max_bytes=65536)
    if timestamp(item["finished_at"]) < timestamp(item["started_at"]):
        raise EvidenceError("invalid_timestamp")
    if item["status"] == "complete" and item["reasons"]:
        raise EvidenceError("invalid_contract")
    if item["status"] == "partial" and not item["reasons"]:
        raise EvidenceError("invalid_contract")
    bounds = {"pages": "pages", "attempts": "attempts", "records": "records",
              "bytes": "total_bytes", "storage_bytes": "storage_bytes", "active_seconds": "active_seconds"}
    if any(item["consumed"][counter] > item["limits"][limit] for counter, limit in bounds.items()):
        raise EvidenceError("invalid_contract")
    if item["scope"] != sorted(item["scope"]):
        raise EvidenceError("invalid_contract")
    return item
