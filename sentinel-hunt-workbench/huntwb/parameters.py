"""Typed, bounded KQL parameter serialization."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from .errors import ContentError
from .paths import load_json


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$")
_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_DURATION = re.compile(r"^[1-9][0-9]{0,5}(?:s|m|h|d)$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,254}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

MAX_STRING = 2048
MAX_LIST = 256
MAX_THRESHOLD = 1_000_000_000


def _string(value: Any, label: str, maximum: int = MAX_STRING) -> str:
    if not isinstance(value, str):
        raise ContentError(f"parameter {label} must be a string")
    if not value or len(value) > maximum or _CONTROL.search(value):
        raise ContentError(f"parameter {label} has an invalid length or control character")
    return value


def _kql_string(value: str) -> str:
    # Kusto single-quoted literals escape a quote by doubling it. Typed
    # validation occurs before this function; it is not a raw-fragment escape.
    return "'" + value.replace("'", "''") + "'"


def _utc(value: Any, label: str) -> str:
    text = _string(value, label, 64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ContentError(f"parameter {label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ContentError(f"parameter {label} must include a UTC offset")
    canonical = parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return f"datetime({canonical})"


def _normalize_scalar(type_name: str, value: Any, definition: dict[str, Any]) -> Any:
    """Validate a scalar and return its canonical JSON-compatible value."""

    name = definition["name"]
    if type_name == "utc_timestamp":
        rendered = _utc(value, name)
        return rendered.removeprefix("datetime(").removesuffix(")")
    if type_name in {"tenant_identifier", "workspace_identifier"}:
        text = _string(value, name, 64)
        if not _UUID.fullmatch(text):
            raise ContentError(f"parameter {name} must be a UUID")
        return text.lower()
    if type_name in {"account_identifier", "device_identifier", "application_identifier"}:
        text = _string(value, name, 255)
        if not _SAFE_ID.fullmatch(text):
            raise ContentError(f"parameter {name} contains characters outside the identifier allowlist")
        return text
    if type_name == "ip_or_cidr":
        text = _string(value, name, 64)
        try:
            parsed = ipaddress.ip_network(text, strict=False) if "/" in text else ipaddress.ip_address(text)
        except ValueError as error:
            raise ContentError(f"parameter {name} must be an IP address or CIDR") from error
        return str(parsed)
    if type_name in {"domain", "hostname"}:
        text = _string(value, name, 253).rstrip(".")
        if not _HOST.fullmatch(text):
            raise ContentError(f"parameter {name} must be a valid DNS name")
        return text.lower()
    if type_name == "url":
        text = _string(value, name)
        if "\\" in text or any(character.isspace() for character in text):
            raise ContentError(f"parameter {name} must not contain whitespace or backslashes")
        parsed = urllib.parse.urlsplit(text)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ContentError(f"parameter {name} must be an HTTP(S) URL without user information")
        try:
            parsed.port
        except ValueError as error:
            raise ContentError(f"parameter {name} has an invalid port") from error
        hostname = parsed.hostname.rstrip(".")
        if not hostname.isascii():
            raise ContentError(f"parameter {name} must use an ASCII hostname")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if not _HOST.fullmatch(hostname):
                raise ContentError(f"parameter {name} must use a valid DNS name or IP address")
        return text
    if type_name == "file_hash":
        text = _string(value, name, 64)
        if not _HASH.fullmatch(text):
            raise ContentError(f"parameter {name} must be an MD5, SHA-1, or SHA-256 hex digest")
        return text.lower()
    if type_name == "bounded_enum":
        text = _string(value, name, 128)
        allowed = definition.get("allowed", [])
        if text not in allowed:
            raise ContentError(f"parameter {name} must be one of: {', '.join(allowed)}")
        return text
    if type_name == "non_negative_integer":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_THRESHOLD:
            raise ContentError(f"parameter {name} must be an integer from 0 through {MAX_THRESHOLD}")
        return value
    if type_name == "duration":
        text = _string(value, name, 16)
        if not _DURATION.fullmatch(text):
            raise ContentError(f"parameter {name} must be a bounded KQL duration such as 30m or 2h")
        return text
    raise ContentError(f"parameter {name} uses unknown type {type_name!r}")


def _serialize_scalar(type_name: str, value: Any, definition: dict[str, Any]) -> str:
    name = definition["name"]
    if type_name == "utc_timestamp":
        return _utc(value, name)
    normalized = _normalize_scalar(type_name, value, definition)
    if type_name == "non_negative_integer":
        return str(normalized)
    if type_name == "duration":
        return str(normalized)
    return _kql_string(str(normalized))


def serialize_parameter(definition: dict[str, Any], value: Any) -> str:
    type_name = definition.get("type")
    if type_name == "bounded_list":
        if not isinstance(value, list) or not value or len(value) > min(definition.get("max_items", MAX_LIST), MAX_LIST):
            raise ContentError(f"parameter {definition['name']} must be a non-empty bounded list")
        item_definition = {
            "name": definition["name"],
            "type": definition.get("item_type"),
            "allowed": definition.get("allowed", []),
        }
        # Validate every item with the same scalar allowlists, then use JSON for
        # the dynamic literal. Embedding already-quoted KQL strings here would
        # produce a Kusto-looking value that is not valid JSON.
        normalized = [
            _normalize_scalar(item_definition["type"], item, item_definition)
            for item in value
        ]
        return "dynamic(" + json.dumps(normalized, ensure_ascii=False, separators=(",", ":")) + ")"
    return _serialize_scalar(str(type_name), value, definition)


def bind_parameters(hunt: dict[str, Any], query: str, supplied: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Bind exactly declared values and return a redacted parameter manifest."""

    definitions = {definition["name"]: definition for definition in hunt["parameters"]}
    unknown = sorted(set(supplied) - set(definitions))
    if unknown:
        raise ContentError(f"unknown parameters (raw KQL fragments are not accepted): {', '.join(unknown)}")

    values: dict[str, Any] = {}
    for name, definition in definitions.items():
        if name in supplied:
            values[name] = supplied[name]
        elif "default" in definition:
            values[name] = definition["default"]
        elif definition.get("required", True):
            raise ContentError(f"missing required parameter: {name}")

    rendered = query
    manifest: dict[str, Any] = {}
    for name, definition in definitions.items():
        placeholder = "{{" + name + "}}"
        if placeholder not in rendered:
            if definition.get("required", True):
                raise ContentError(f"query omits required typed placeholder: {name}")
            continue
        if name not in values:
            raise ContentError(f"missing optional parameter used by query: {name}")
        serialized = serialize_parameter(definition, values[name])
        rendered = rendered.replace(placeholder, serialized)
        manifest[name] = {
            "type": definition["type"],
            "value": "[REDACTED]",
            "serialized_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        }

    leftovers = re.findall(r"\{\{([a-zA-Z0-9_]+)\}\}", rendered)
    if leftovers:
        raise ContentError(f"unbound query placeholders: {', '.join(sorted(set(leftovers)))}")
    return rendered, manifest


def load_parameter_file(path: str | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        value = load_json(Path(path))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ContentError(f"cannot read parameter JSON: {error}") from error
    if not isinstance(value, dict):
        raise ContentError("parameter JSON must be an object")
    return value
