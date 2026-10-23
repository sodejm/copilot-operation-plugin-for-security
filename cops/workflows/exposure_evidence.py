"""Correlate imported exposure observations without discovering destinations."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

SCHEMA = "cops.exposure-evidence/v1"
ENDPOINT_FIELDS = ("scheme", "host", "port", "route")


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None
        return parsed if parsed and parsed.utcoffset() is not None else None
    except ValueError:
        return None


def _host(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 253
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) is not None
        and all(
            label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
            for label in value.split(".")
        )
    )


def _endpoint(item: Any) -> tuple | None:
    if not isinstance(item, dict):
        return None
    route = item.get("route")
    if (
        item.get("scheme") not in ("http", "https")
        or not _host(item.get("host"))
        or type(item.get("port")) is not int
        or not 1 <= item["port"] <= 65535
        or not isinstance(route, str)
        or not 1 <= len(route) <= 2048
        or not route.startswith("/")
        or route.startswith("//")
        or any(ord(char) < 33 or ord(char) > 126 for char in route)
        or "#" in route
    ):
        return None
    return tuple(item[field] for field in ENDPOINT_FIELDS)


def _address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) and "%" not in value else None
    except ValueError:
        return None


def scoped_records(scope: Any, section: Any, *, dns: bool = False) -> list[dict[str, Any]]:
    """Display only scoped records; completeness is assessed on the original input."""
    if not isinstance(scope, dict) or not isinstance(section, dict):
        return []
    endpoints = scope.get("endpoints")
    records = section.get("records" if dns else "checks")
    if not isinstance(endpoints, list) or not isinstance(records, list):
        return []
    keys = {_endpoint(item) for item in endpoints} - {None}
    hosts = {key[1] for key in keys}
    return [
        item
        for item in records
        if isinstance(item, dict)
        and (item.get("host") in hosts if dns and isinstance(item.get("host"), str) else _endpoint(item) in keys)
    ]


def assess_exposure(inputs: Any) -> dict[str, Any]:
    """Require unique, complete, in-window observations for every scoped endpoint."""
    result: dict[str, Any] = {
        "schema_version": SCHEMA,
        "outcome": "insufficient_evidence",
        "coverage_complete": False,
        "checked": [],
        "exposures": [],
        "evidence_refs": [],
        "reasons": [],
        "limitations": [
            "imported completeness and observations are producer assertions; no production validation",
            "coverage is limited to explicitly scoped endpoints and the collection window",
        ],
    }

    def unresolved(reason: str) -> dict[str, Any]:
        result["reasons"].append(reason)
        return result

    scope = inputs.get("scope") if isinstance(inputs, dict) else None
    if not isinstance(scope, dict):
        return unresolved("missing scope")
    endpoints, window = scope.get("endpoints"), scope.get("window")
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 256 or not isinstance(window, dict):
        return unresolved("missing or over-budget endpoint inventory or collection window")
    keys = [_endpoint(item) for item in endpoints]
    start, end = _time(window.get("start")), _time(window.get("end"))
    if None in keys or len(set(keys)) != len(keys) or not start or not end or start >= end:
        return unresolved("invalid or duplicate scoped endpoint or collection window")
    sections = {}
    for name in ("dns_service_inventory", "port_route_evidence", "auth_evidence"):
        section = inputs.get(name)
        items = (
            section.get("records" if name == "dns_service_inventory" else "checks")
            if isinstance(section, dict)
            else None
        )
        if (
            not isinstance(section, dict)
            or section.get("complete") is not True
            or not isinstance(items, list)
            or not 1 <= len(items) <= 4096
            or any(not isinstance(item, dict) for item in items)
        ):
            return unresolved("missing, incomplete, malformed, or over-budget " + name)
        sections[name] = items
    refs = set()
    for key in keys:
        dns = [item for item in sections["dns_service_inventory"] if item.get("host") == key[1]]
        connections = [item for item in sections["port_route_evidence"] if _endpoint(item) == key]
        authentication = [item for item in sections["auth_evidence"] if _endpoint(item) == key]
        if any(len(items) != 1 for items in (dns, connections, authentication)):
            return unresolved("missing or conflicting endpoint observations")
        for item in (dns[0], connections[0], authentication[0]):
            observed, ref = _time(item.get("observed_at")), item.get("evidence_ref")
            if (
                not observed
                or not start <= observed <= end
                or not isinstance(ref, str)
                or not 1 <= len(ref) <= 256
                or ref.strip() != ref
            ):
                return unresolved("missing evidence reference or in-window timestamp")
            refs.add(ref)
        addresses = dns[0].get("addresses")
        if (
            not isinstance(addresses, list)
            or not 1 <= len(addresses) <= 64
            or any(not isinstance(address, str) or _address(address) != address for address in addresses)
        ):
            return unresolved("invalid DNS addresses")
        connection, auth = connections[0], authentication[0]
        if (
            connection.get("connected") is not True
            or connection.get("address") not in addresses
            or auth.get("address") != connection.get("address")
        ):
            return unresolved("connection or authentication address differs from the scoped DNS observation")
        if (
            type(auth.get("authorized_status")) is not int
            or auth["authorized_status"] != 200
            or type(auth.get("anonymous_status")) is not int
            or auth["anonymous_status"] not in (200, 401, 403)
        ):
            return unresolved("authentication observations are inconclusive; redirects do not establish coverage")
        checked = {
            **dict(zip(ENDPOINT_FIELDS, key, strict=True)),
            "address": auth["address"],
            "authorized_status": auth["authorized_status"],
            "anonymous_status": auth["anonymous_status"],
        }
        result["checked"].append(checked)
        result["evidence_refs"] = sorted(refs)
        if auth["anonymous_status"] == 200:
            result["exposures"].append(checked)
    result.update(
        coverage_complete=True,
        evidence_refs=sorted(refs),
        outcome="action_required" if result["exposures"] else "no_exposure_observed",
    )
    return result
