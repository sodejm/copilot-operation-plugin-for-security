"""Small, fail-closed JSON Schema subset validator for bundled fixtures."""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a value does not satisfy a bundled schema."""


def validate(value: Any, schema: dict[str, Any]) -> None:
    """Validate against the JSON Schema features used by this package's schemas."""
    _validate(value, schema, schema)


def _validate(value: Any, schema: Any, root: dict[str, Any]) -> None:
    if isinstance(schema, bool):
        if not schema:
            raise SchemaValidationError("schema forbids this value")
        return
    if not isinstance(schema, dict):
        raise SchemaValidationError("schema must be an object or boolean")

    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise SchemaValidationError("$ref siblings are unsupported")
        _validate(value, _resolve_ref(schema["$ref"], root), root)
        return

    allowed = {
        "$defs",
        "$schema",
        "additionalProperties",
        "allOf",
        "const",
        "contains",
        "description",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "patternProperties",
        "properties",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    }
    unknown = set(schema) - allowed
    if unknown:
        raise SchemaValidationError(f"unsupported schema keyword: {sorted(unknown)[0]}")

    if "type" in schema and not _matches_type(value, schema["type"]):
        raise SchemaValidationError("value has the wrong type")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError("value does not equal const")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError("value is not in enum")
    if "allOf" in schema:
        for option in _schema_list(schema["allOf"]):
            _validate(value, option, root)
    if "oneOf" in schema:
        matches = 0
        for option in _schema_list(schema["oneOf"]):
            try:
                _validate(value, option, root)
            except SchemaValidationError:
                continue
            matches += 1
        if matches != 1:
            raise SchemaValidationError("value must match exactly one schema")
    if "not" in schema:
        try:
            _validate(value, schema["not"], root)
        except SchemaValidationError:
            pass
        else:
            raise SchemaValidationError("value matches forbidden schema")
    if "if" in schema:
        try:
            _validate(value, schema["if"], root)
        except SchemaValidationError:
            branch = schema.get("else")
        else:
            branch = schema.get("then")
        if branch is not None:
            _validate(value, branch, root)

    if isinstance(value, dict):
        _validate_object(value, schema, root)
    if isinstance(value, list):
        _validate_array(value, schema, root)
    if isinstance(value, str):
        _validate_string(value, schema)
    if _is_number(value):
        _validate_number(value, schema)


def _validate_object(value: dict[str, Any], schema: dict[str, Any], root: dict[str, Any]) -> None:
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
        raise SchemaValidationError("required must be a list of strings")
    if any(key not in value for key in required):
        raise SchemaValidationError("required property is missing")
    _range(value, schema, "minProperties", "maxProperties", len)

    properties = schema.get("properties", {})
    patterns = schema.get("patternProperties", {})
    if not isinstance(properties, dict) or not isinstance(patterns, dict):
        raise SchemaValidationError("properties must be objects")
    compiled_patterns = [(re.compile(pattern), child) for pattern, child in patterns.items()]
    for key, item in value.items():
        matched = False
        if key in properties:
            _validate(item, properties[key], root)
            matched = True
        for pattern, child in compiled_patterns:
            if pattern.search(key):
                _validate(item, child, root)
                matched = True
        if not matched and schema.get("additionalProperties", True) is False:
            raise SchemaValidationError("additional property is forbidden")
        if not matched and isinstance(schema.get("additionalProperties"), dict):
            _validate(item, schema["additionalProperties"], root)


def _validate_array(value: list[Any], schema: dict[str, Any], root: dict[str, Any]) -> None:
    _range(value, schema, "minItems", "maxItems", len)
    if schema.get("uniqueItems"):
        encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
        if len(encoded) != len(set(encoded)):
            raise SchemaValidationError("array items must be unique")
    if "items" in schema:
        for item in value:
            _validate(item, schema["items"], root)
    if "contains" in schema:
        try:
            next(item for item in value if _matches_schema(item, schema["contains"], root))
        except StopIteration as exc:
            raise SchemaValidationError("array does not contain a required item") from exc


def _validate_string(value: str, schema: dict[str, Any]) -> None:
    _range(value, schema, "minLength", "maxLength", len)
    if "pattern" in schema and not re.search(schema["pattern"], value):
        raise SchemaValidationError("string does not match pattern")
    if schema.get("format") == "date":
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise SchemaValidationError("string is not an ISO date") from exc
    elif "format" in schema:
        raise SchemaValidationError("unsupported string format")


def _validate_number(value: int | float, schema: dict[str, Any]) -> None:
    if "minimum" in schema and value < schema["minimum"]:
        raise SchemaValidationError("number is below minimum")
    if "maximum" in schema and value > schema["maximum"]:
        raise SchemaValidationError("number is above maximum")


def _matches_schema(value: Any, schema: Any, root: dict[str, Any]) -> bool:
    try:
        _validate(value, schema, root)
    except SchemaValidationError:
        return False
    return True


def _matches_type(value: Any, expected: Any) -> bool:
    types = expected if isinstance(expected, list) else [expected]
    if not all(isinstance(item, str) for item in types):
        raise SchemaValidationError("type must be a string or list of strings")
    return any(
        (name == "object" and isinstance(value, dict))
        or (name == "array" and isinstance(value, list))
        or (name == "string" and isinstance(value, str))
        or (name == "integer" and type(value) is int)
        or (name == "number" and _is_number(value))
        or (name == "boolean" and type(value) is bool)
        or (name == "null" and value is None)
        for name in types
    )


def _resolve_ref(reference: Any, root: dict[str, Any]) -> Any:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise SchemaValidationError("only local JSON Pointer references are supported")
    target: Any = root
    for segment in reference[2:].split("/"):
        key = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or key not in target:
            raise SchemaValidationError("reference does not resolve")
        target = target[key]
    return target


def _schema_list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise SchemaValidationError("schema composition must be a list")
    return value


def _range(value: Any, schema: dict[str, Any], minimum: str, maximum: str, measure: Any) -> None:
    size = measure(value)
    if minimum in schema and size < schema[minimum]:
        raise SchemaValidationError(f"value is below {minimum}")
    if maximum in schema and size > schema[maximum]:
        raise SchemaValidationError(f"value exceeds {maximum}")


def _is_number(value: Any) -> bool:
    return type(value) in {int, float}
