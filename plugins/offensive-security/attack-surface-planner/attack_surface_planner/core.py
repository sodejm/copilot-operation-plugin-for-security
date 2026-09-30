"""Bounded local export ingestion and deterministic scope decisions.

No module in this package performs network or tenant API operations.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from datetime import datetime, timezone
from urllib.parse import urlsplit


KINDS = ("azure_resource_graph", "entra", "dns_ct", "public_endpoint")
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_RECORDS = 1000
MAX_DEPTH = 24
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
HIGH_CONSENT = frozenset({
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
})


class GateError(ValueError):
    """Input failed an offline authorization or integrity gate."""


def _fail(message: str) -> None:
    raise GateError(message)


def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(f"{label} must be a nonempty bounded string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(f"{label} contains control characters")
    return value


def _utc(value: object, label: str) -> str:
    raw = _text(value, label, maximum=40)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{label} must be an ISO-8601 UTC timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _fail(f"{label} must be an ISO-8601 UTC timestamp")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _list(value: object, label: str, *, maximum: int = 100) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"{label} must be a bounded array")
    return value


def _strings(value: object, label: str) -> list[str]:
    return [_text(item, label, maximum=253) for item in _list(value, label)]


def _domain(value: object, label: str) -> str:
    domain = _text(value, label, maximum=253).lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        _fail(f"{label} must be a DNS domain")
    return domain


def _network(value: object, label: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(_text(value, label, maximum=64), strict=True)
    except ValueError:
        _fail(f"{label} must be a canonical IP range")


def _relative_path(value: object) -> tuple[str, ...]:
    path = _text(value, "source path", maximum=240)
    if "\\" in path or path.startswith("/") or ":" in path:
        _fail("source path must be relative")
    parts = tuple(path.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        _fail("source path must be relative and traversal-free")
    return parts


def _read_regular(path: Path, limit: int) -> bytes:
    """Require a regular bounded manifest file and do not follow its final link."""
    try:
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        _fail("input file could not be safely opened")
    try:
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                _fail("input must be a bounded regular file")
            data = b""
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) > limit:
                _fail("input exceeds byte budget")
            return data
        finally:
            os.close(fd)
    except (OSError, ValueError) as error:
        if isinstance(error, GateError):
            raise
        _fail("input file could not be safely opened")
    finally:
        os.close(directory)


def _read_source(base: Path, relative: str) -> bytes:
    parts = _relative_path(relative)
    try:
        directory = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("source could not be safely opened")
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                _fail("source must be a bounded regular file")
            data = b""
            while len(data) <= MAX_SOURCE_BYTES:
                chunk = os.read(fd, min(65536, MAX_SOURCE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) > MAX_SOURCE_BYTES:
                _fail("source exceeds byte budget")
            return data
        finally:
            os.close(fd)
    except OSError:
        _fail("source could not be safely opened")
    finally:
        os.close(directory)


def _json(data: bytes, label: str) -> object:
    try:
        def unique_keys(pairs: list[tuple[str, object]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    _fail(f"{label} contains duplicate JSON keys")
                result[key] = value
            return result

        obj = json.loads(data, object_pairs_hook=unique_keys,
                         parse_constant=lambda _value: _fail(f"{label} contains invalid JSON constants"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(f"{label} must be UTF-8 JSON")
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            _fail(f"{label} exceeds JSON depth budget")
        if isinstance(node, dict):
            if len(node) > MAX_RECORDS:
                _fail(f"{label} exceeds object budget")
            stack.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            if len(node) > MAX_RECORDS:
                _fail(f"{label} exceeds array budget")
            stack.extend((item, depth + 1) for item in node)
    return obj


def _scope(manifest: dict) -> dict:
    if manifest.get("schema_version") != "1.0" or manifest.get("mode") != "offline":
        _fail("only schema 1.0 offline mode is supported")
    approval = manifest.get("approval")
    if not isinstance(approval, dict):
        _fail("approval is required")
    approved = {
        "reference": _text(approval.get("reference"), "approval reference", maximum=120),
        "approved_by": _text(approval.get("approved_by"), "approver", maximum=120),
        "approved_at": _utc(approval.get("approved_at"), "approval time"),
    }
    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        _fail("scope is required")
    normalized = {}
    for key in ("tenant_ids", "subscription_ids", "environments", "owners"):
        normalized[key] = sorted(set(_strings(scope.get(key), key)))
        if not normalized[key]:
            _fail(f"{key} must contain an approved value")
    normalized["domains"] = sorted(set(_domain(x, "domain") for x in
                                       _list(scope.get("domains"), "domains")))
    normalized["ip_ranges"] = sorted(set(str(_network(x, "IP range")) for x in
                                         _list(scope.get("ip_ranges"), "ip_ranges")))
    if not normalized["domains"] and not normalized["ip_ranges"]:
        _fail("a domain or IP range is required")
    methods = sorted(set(_strings(scope.get("allowed_methods"), "allowed methods")))
    if methods != ["passive-review"]:
        _fail("this package allows passive-review only")
    normalized["allowed_methods"] = methods
    windows = _list(scope.get("time_windows"), "time windows")
    if not windows:
        _fail("at least one time window is required")
    normalized["time_windows"] = []
    for window in windows:
        if not isinstance(window, dict):
            _fail("time window must be an object")
        start, end = _utc(window.get("start"), "window start"), _utc(window.get("end"), "window end")
        if datetime.fromisoformat(start.replace("Z", "+00:00")) >= datetime.fromisoformat(
            end.replace("Z", "+00:00")
        ):
            _fail("time window end must follow start")
        normalized["time_windows"].append({"start": start, "end": end})
    normalized["time_windows"].sort(key=lambda x: (x["start"], x["end"]))
    exclusions = scope.get("exclusions")
    if not isinstance(exclusions, dict):
        _fail("explicit exclusions are required")
    normalized["exclusions"] = {
        "tenant_ids": sorted(set(_strings(exclusions.get("tenant_ids"), "excluded tenants"))),
        "subscription_ids": sorted(set(_strings(exclusions.get("subscription_ids"), "excluded subscriptions"))),
        "domains": sorted(set(_domain(x, "excluded domain") for x in
                              _list(exclusions.get("domains"), "excluded domains"))),
        "ip_ranges": sorted(set(str(_network(x, "excluded IP range")) for x in
                                _list(exclusions.get("ip_ranges"), "excluded IP ranges"))),
    }
    return {"approval": approved, "scope": normalized}


def _host_from_url(value: object) -> str:
    raw = _text(value, "endpoint URL", maximum=2048)
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username \
                or parsed.password or parsed.query or parsed.fragment:
            _fail("endpoint URL must be HTTP(S) without credentials, query, or fragment")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            _fail("endpoint URL has an invalid port")
        host = parsed.hostname.lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(host):
            ipaddress.ip_address(host)
        return host
    except ValueError:
        _fail("endpoint URL has an invalid host")


def _normalize(kind: str, record: object, evidence: dict) -> dict:
    if not isinstance(record, dict):
        return {"kind": kind, "identity": None, "attributes": {}, "evidence": evidence,
                "decision": "unresolved", "reason": "record is not an object"}
    attributes = {}
    try:
        if kind == "azure_resource_graph":
            identity = _text(record.get("id"), "resource ID")
            attributes["tenant_id"] = record.get("tenant_id")
            attributes["subscription_id"] = record.get("subscription_id")
            subscription = re.match(r"^/subscriptions/([^/]+)(?:/|$)", identity, re.IGNORECASE)
            if not subscription or subscription.group(1).lower() != str(attributes["subscription_id"]).lower():
                _fail("resource ID and subscription ID disagree")
            attributes["public_endpoint"] = record.get("public_endpoint") is True
        elif kind == "entra":
            identity = _text(record.get("id"), "Entra object ID")
            if record.get("record_type") not in ("application", "service_principal"):
                _fail("unsupported Entra record type")
            attributes["tenant_id"] = record.get("tenant_id")
            attributes["record_type"] = record["record_type"]
            permissions = _strings(record.get("permissions", []), "permissions")
            attributes["review_permissions"] = sorted(set(permissions) & HIGH_CONSENT)
        elif kind == "dns_ct":
            identity = _domain(record.get("hostname"), "hostname")
            attributes["domain"] = identity
            if record.get("ip") is not None:
                attributes["ip"] = str(ipaddress.ip_address(record["ip"]))
            if record.get("record_type") not in ("dns", "certificate"):
                _fail("unsupported DNS/CT record type")
            attributes["record_type"] = record["record_type"]
        else:
            identity = _host_from_url(record.get("url"))
            try:
                attributes["ip"] = str(ipaddress.ip_address(identity))
            except ValueError:
                attributes["domain"] = identity
            if record.get("ip") is not None:
                attributes["ip"] = str(ipaddress.ip_address(record["ip"]))
        for key in ("tenant_id", "subscription_id", "environment", "owner"):
            if key in record and record[key] is not None:
                attributes[key] = _text(record[key], key, maximum=253)
        asset_id = hashlib.sha256(f"{kind}\0{identity}".encode()).hexdigest()[:20]
        return {"asset_id": asset_id, "kind": kind, "identity": identity,
                "attributes": attributes, "evidence": evidence}
    except (GateError, ValueError, TypeError):
        return {"kind": kind, "identity": None, "attributes": {}, "evidence": evidence,
                "decision": "unresolved", "reason": "record identity or fields are malformed"}


def _matches_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _decision(item: dict, scope: dict) -> tuple[str, str]:
    if "decision" in item:
        return item["decision"], item["reason"]
    attrs = item["attributes"]
    denied = scope["exclusions"]
    for key, singular in (("tenant_ids", "tenant_id"), ("subscription_ids", "subscription_id")):
        if attrs.get(singular) in denied[key]:
            return "excluded", f"{singular} is explicitly excluded"
    host = attrs.get("domain")
    if host and any(_matches_domain(host, name) for name in denied["domains"]):
        return "excluded", "domain is explicitly excluded"
    ip = attrs.get("ip")
    if ip and any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in
                  denied["ip_ranges"]):
        return "excluded", "IP is explicitly excluded"
    for key, singular in (("tenant_ids", "tenant_id"), ("subscription_ids", "subscription_id")):
        value = attrs.get(singular)
        if value and value not in scope[key]:
            return "excluded", f"{singular} is outside approved scope"
    if host and not any(_matches_domain(host, name) for name in scope["domains"]):
        return "excluded", "domain is outside approved scope"
    if ip and not any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in
                      scope["ip_ranges"]):
        return "excluded", "IP is outside approved scope"
    required = {"azure_resource_graph": ("tenant_id", "subscription_id"),
                "entra": ("tenant_id",), "dns_ct": ("domain",),
                "public_endpoint": ()}[item["kind"]]
    if item["kind"] == "public_endpoint" and not (host or ip):
        return "unresolved", "endpoint has no attributable host or IP"
    if any(not attrs.get(field) for field in required):
        return "unresolved", "required ownership identifier is missing"
    if not attrs.get("environment") or not attrs.get("owner"):
        return "unresolved", "environment or owner is missing"
    if attrs["environment"] not in scope["environments"]:
        return "excluded", "environment is outside approved scope"
    if attrs["owner"] not in scope["owners"]:
        return "unresolved", "owner is not approved or attribution is ambiguous"
    return "in_scope", "approved identifiers, environment, and owner match"


def _proposal(item: dict, approval: dict, scope: dict) -> dict:
    attrs, kind = item["attributes"], item["kind"]
    if kind == "azure_resource_graph":
        hypothesis = ("Public management exposure needs review" if attrs["public_endpoint"]
                      else "Resource inventory needs reconciliation")
        order = 1 if attrs["public_endpoint"] else 4
    elif kind == "entra":
        hypothesis = ("High-privilege app consent needs review" if attrs["review_permissions"]
                      else "App identity inventory needs reconciliation")
        order = 2 if attrs["review_permissions"] else 4
    elif kind == "dns_ct":
        hypothesis, order = "DNS or certificate record needs ownership review", 3
    else:
        hypothesis, order = "Public endpoint needs inventory review", 3
    return {
        "asset_id": item["asset_id"], "hypothesis": hypothesis, "review_order": order,
        "authorization": {"reference": approval["reference"],
                          "allowed_method": "passive-review",
                          "time_windows": scope["time_windows"]},
        "method": "passive-review of the cited local export and approved inventory",
        "expected_observation": "Confirm or reject the recorded asset identity and owner; export alone is not proof of exposure.",
        "expected_telemetry": "Local operator review record; no tenant or network event is expected from this plan.",
        "stop_condition": "Stop if scope, approval, provenance, owner, or source freshness cannot be confirmed.",
        "cleanup": "No remote change; handle the local report under the approved retention policy.",
        "evidence": item["evidence"],
    }


def analyze(manifest_path: Path) -> dict:
    """Analyze pinned local exports; return canonicalizable JSON-compatible data."""
    manifest_path = Path(manifest_path)
    manifest_bytes = _read_regular(manifest_path, MAX_MANIFEST_BYTES)
    manifest = _json(manifest_bytes, "manifest")
    if not isinstance(manifest, dict):
        _fail("manifest must be an object")
    validated = _scope(manifest)
    approval, scope = validated["approval"], validated["scope"]
    sources = _list(manifest.get("sources"), "sources", maximum=16)
    if len(sources) != len(KINDS):
        _fail("exactly one source of each supported kind is required")
    discoveries, source_ledger, total_bytes, total_records = [], [], len(manifest_bytes), 0
    seen = set()
    for source in sources:
        if not isinstance(source, dict) or source.get("kind") not in KINDS:
            _fail("source kind is unsupported")
        kind = source["kind"]
        if kind in seen:
            _fail("duplicate source kind")
        seen.add(kind)
        relative = _text(source.get("path"), "source path", maximum=240)
        _relative_path(relative)
        digest = _text(source.get("sha256"), "source SHA-256", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            _fail("source SHA-256 must be lowercase hexadecimal")
        collected = _utc(source.get("collected_at"), "collection time")
        reference = _text(source.get("source_ref"), "source reference", maximum=240)
        if any(char in reference for char in ("?", "#", "@")):
            _fail("source reference cannot contain credentials or URL query")
        count = source.get("record_count")
        if type(count) is not int or count < 0 or count > MAX_RECORDS:
            _fail("source record count exceeds budget")
        data = _read_source(manifest_path.parent, relative)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            _fail("total input byte budget exceeded")
        if hashlib.sha256(data).hexdigest() != digest:
            _fail("source SHA-256 mismatch")
        export = _json(data, "source")
        if not isinstance(export, dict) or not isinstance(export.get("records"), list):
            _fail("source must have a records array")
        records = export["records"]
        total_records += len(records)
        if len(records) != count or total_records > MAX_RECORDS:
            _fail("source record count mismatch or budget exceeded")
        source_ledger.append({"kind": kind, "file": relative, "source_ref": reference,
                              "sha256": digest, "collected_at": collected,
                              "record_count": count})
        for index, record in enumerate(records):
            evidence = {"source_kind": kind, "source_file": relative, "source_ref": reference,
                        "source_sha256": digest, "collected_at": collected,
                        "pointer": f"/records/{index}", "confidence": "reported-export"}
            item = _normalize(kind, record, evidence)
            item["decision"], item["reason"] = _decision(item, scope)
            discoveries.append(item)
    if seen != set(KINDS):
        _fail("all four supported source kinds are required")
    discoveries.sort(key=lambda x: (x["kind"], x.get("asset_id", ""), x["evidence"]["pointer"]))
    included = [x for x in discoveries if x["decision"] == "in_scope"]
    proposals = [_proposal(item, approval, scope) for item in included]
    proposals.sort(key=lambda x: (x["review_order"], x["asset_id"], x["evidence"]["pointer"]))
    return {
        "schema_version": "1.0", "mode": "offline", "network_requests": 0,
        "authorization_status": "operator_asserted_approval",
        "approval": approval, "scope": scope,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "limits": {"manifest_bytes": MAX_MANIFEST_BYTES, "source_bytes": MAX_SOURCE_BYTES,
                   "total_bytes": MAX_TOTAL_BYTES, "records": MAX_RECORDS, "json_depth": MAX_DEPTH},
        "usage": {"bytes": total_bytes, "records": total_records},
        "sources": sorted(source_ledger, key=lambda x: x["kind"]),
        "surface_map": discoveries, "test_plan": proposals,
        "summary": {status: sum(x["decision"] == status for x in discoveries)
                    for status in ("in_scope", "excluded", "unresolved")},
        "limitations": [
            "Exports are operator supplied and may be incomplete or stale.",
            "Ownership and approval are asserted by the manifest, not independently verified.",
            "Hypotheses are review prompts, not confirmed exposure or exploitability.",
            "No network, tenant API, active test, or authorization verification is performed.",
        ],
    }


def canonical(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
