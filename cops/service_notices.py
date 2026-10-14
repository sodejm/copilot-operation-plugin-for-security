"""Bounded offline validation and assessment for service attack notices."""

from __future__ import annotations

import json
import math
import os
import re
import stat
from argparse import Namespace
from datetime import date, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = "cops.service-attack-notices/v1"
MAX_INPUT_BYTES = 256 * 1024
MAX_JSON_DEPTH = 32
NOTICE_ID = re.compile(r"^COPS-SAN-\d{4}-\d{3}$")
ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ALLOWED_SOURCE_HOSTS = {
    "www.microsoft.com",
    "www.dell.com",
    "cloud.google.com",
    "support.apple.com",
    "calif.io",
}
SOURCE_TYPES = {"vendor_advisory", "vendor_security_research", "incident_research", "original_research"}
LIFECYCLE_STATES = {"active", "withdrawn", "superseded"}
RESULT_STATUSES = {"candidate", "fixed", "not_applicable", "unknown"}


class ServiceNoticeError(ValueError):
    """Raised when a registry or asset input violates its offline contract."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceNoticeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ServiceNoticeError(f"non-finite JSON constant is not allowed: {value}")


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise ServiceNoticeError(f"JSON nesting limit exceeded ({MAX_JSON_DEPTH})")
    if isinstance(value, dict):
        for item in value.values():
            _json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _json_depth(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ServiceNoticeError("non-finite JSON numbers are not allowed")
    return depth


def load_json_file(path: Path, *, label: str) -> Any:
    """Read one bounded regular JSON file without resolving external content."""

    try:
        # Reject obvious special files and links before opening; nonblocking
        # and no-follow flags below also protect supported platforms from races.
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise ServiceNoticeError(f"{label} must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with os.fdopen(os.open(path, flags), "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ServiceNoticeError(f"{label} must be a regular file")
            if info.st_size > MAX_INPUT_BYTES:
                raise ServiceNoticeError(f"{label} size limit exceeded ({MAX_INPUT_BYTES} bytes)")
            payload = source.read(MAX_INPUT_BYTES + 1)
    except ServiceNoticeError:
        raise
    except OSError as error:
        raise ServiceNoticeError(f"cannot read {label}: {error.strerror or error}") from error
    if len(payload) > MAX_INPUT_BYTES:
        raise ServiceNoticeError(f"{label} size limit exceeded ({MAX_INPUT_BYTES} bytes)")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as error:
        raise ServiceNoticeError(f"{label} is not valid UTF-8") from error
    except json.JSONDecodeError as error:
        raise ServiceNoticeError(f"invalid JSON in {label}: line {error.lineno}, column {error.colno}") from error
    except ServiceNoticeError:
        raise
    except ValueError as error:
        raise ServiceNoticeError(f"invalid JSON number in {label}") from error
    except RecursionError as error:
        raise ServiceNoticeError(f"{label} exceeds the JSON nesting limit") from error
    _json_depth(value)
    return value


def _object(value: Any, path: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ServiceNoticeError(f"{path} must be an object")
    unknown = sorted(set(value) - keys)
    missing = sorted(keys - set(value))
    if unknown:
        raise ServiceNoticeError(f"{path} has unsupported field(s): {', '.join(unknown)}")
    if missing:
        raise ServiceNoticeError(f"{path} is missing field(s): {', '.join(missing)}")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ServiceNoticeError(f"{path} must be a non-empty trimmed string")
    return value


def _optional_text(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _text(value, path)


def _date(value: Any, path: str) -> date:
    text = _text(value, path)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as error:
        raise ServiceNoticeError(f"{path} must be an ISO date") from error
    if parsed.isoformat() != text:
        raise ServiceNoticeError(f"{path} must use YYYY-MM-DD")
    return parsed


def _strings(value: Any, path: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise ServiceNoticeError(f"{path} must be {qualifier} of strings")
    result = [_text(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if len({item.casefold() for item in result}) != len(result):
        raise ServiceNoticeError(f"{path} contains duplicate values")
    return result


def _validate_source(value: Any, path: str) -> date:
    source = _object(value, path, {"type", "url", "published_on"})
    source_type = _text(source["type"], f"{path}.type")
    if source_type not in SOURCE_TYPES:
        raise ServiceNoticeError(f"{path}.type is unsupported")
    published_on = _date(source["published_on"], f"{path}.published_on")
    url = _text(source["url"], f"{path}.url")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise ServiceNoticeError(f"unsupported source URL at {path}.url") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_SOURCE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ServiceNoticeError(f"unsupported source URL at {path}.url")
    return published_on


def _validate_notice(value: Any, index: int) -> str:
    path = f"notices[{index}]"
    notice = _object(
        value,
        path,
        {
            "id",
            "title",
            "status",
            "publication_date",
            "observation_date",
            "observation_context",
            "review_date",
            "review_due",
            "lifecycle",
            "sources",
            "scope",
            "services",
            "prerequisites",
            "attack_mappings",
            "defensive",
            "limitations",
        },
    )
    notice_id = _text(notice["id"], f"{path}.id")
    if not NOTICE_ID.fullmatch(notice_id):
        raise ServiceNoticeError(f"{path}.id has invalid format")
    _text(notice["title"], f"{path}.title")
    status = _text(notice["status"], f"{path}.status")
    if status not in LIFECYCLE_STATES:
        raise ServiceNoticeError(f"{path}.status is unsupported")
    published = _date(notice["publication_date"], f"{path}.publication_date")
    observed = (
        _date(notice["observation_date"], f"{path}.observation_date")
        if notice["observation_date"] is not None
        else None
    )
    _text(notice["observation_context"], f"{path}.observation_context")
    reviewed = _date(notice["review_date"], f"{path}.review_date")
    review_due = _date(notice["review_due"], f"{path}.review_due")
    if (
        reviewed < published
        or (observed is not None and reviewed < observed)
        or reviewed > date.today()
        or not reviewed < review_due <= reviewed + timedelta(days=31)
    ):
        raise ServiceNoticeError(f"{path} date ordering is invalid")

    lifecycle = _object(
        notice["lifecycle"],
        f"{path}.lifecycle",
        {"state", "superseded_by", "withdrawn_reason"},
    )
    state = _text(lifecycle["state"], f"{path}.lifecycle.state")
    if state != status:
        raise ServiceNoticeError(f"{path}.status must match lifecycle.state")
    superseded_by = _optional_text(lifecycle["superseded_by"], f"{path}.lifecycle.superseded_by")
    withdrawn_reason = _optional_text(lifecycle["withdrawn_reason"], f"{path}.lifecycle.withdrawn_reason")
    if state == "active" and (superseded_by or withdrawn_reason):
        raise ServiceNoticeError(f"{path} active lifecycle cannot have terminal metadata")
    if state == "withdrawn" and (not withdrawn_reason or superseded_by):
        raise ServiceNoticeError(f"{path} withdrawn lifecycle requires only withdrawn_reason")
    if state == "superseded" and (not superseded_by or withdrawn_reason or superseded_by == notice_id):
        raise ServiceNoticeError(f"{path} superseded lifecycle metadata is invalid")
    if superseded_by and not NOTICE_ID.fullmatch(superseded_by):
        raise ServiceNoticeError(f"{path}.lifecycle.superseded_by has invalid format")

    sources = notice["sources"]
    if not isinstance(sources, list) or not sources:
        raise ServiceNoticeError(f"{path}.sources must be a non-empty list")
    source_dates = [
        _validate_source(source, f"{path}.sources[{source_index}]")
        for source_index, source in enumerate(sources)
    ]
    if published != min(source_dates) or reviewed < max(source_dates):
        raise ServiceNoticeError(f"{path} source publication dates are inconsistent with notice dates")
    source_urls = [source["url"] for source in sources]
    if len(set(source_urls)) != len(source_urls):
        raise ServiceNoticeError(f"{path}.sources contains duplicate URLs")

    scope = _object(notice["scope"], f"{path}.scope", {"operating_systems", "products"})
    _strings(scope["operating_systems"], f"{path}.scope.operating_systems")
    products = scope["products"]
    if not isinstance(products, list) or not products:
        raise ServiceNoticeError(f"{path}.scope.products must be a non-empty list")
    product_names: list[str] = []
    for product_index, product_value in enumerate(products):
        product_path = f"{path}.scope.products[{product_index}]"
        product = _object(product_value, product_path, {"name", "affected_versions", "fixed_versions"})
        product_names.append(_text(product["name"], f"{product_path}.name"))
        affected = _strings(product["affected_versions"], f"{product_path}.affected_versions", allow_empty=True)
        fixed = _strings(product["fixed_versions"], f"{product_path}.fixed_versions", allow_empty=True)
        if {item.casefold() for item in affected} & {item.casefold() for item in fixed}:
            raise ServiceNoticeError(f"version overlap at {product_path}")
    if len({item.casefold() for item in product_names}) != len(product_names):
        raise ServiceNoticeError(f"{path}.scope.products contains duplicate product names")

    services = notice["services"]
    if not isinstance(services, list) or not services:
        raise ServiceNoticeError(f"{path}.services must be a non-empty list")
    for service_index, service_value in enumerate(services):
        service_path = f"{path}.services[{service_index}]"
        service = _object(service_value, service_path, {"name", "transports"})
        _text(service["name"], f"{service_path}.name")
        transports = _strings(service["transports"], f"{service_path}.transports")
        if any(item not in {"tcp", "udp"} for item in transports):
            raise ServiceNoticeError(f"{service_path}.transports contains an unsupported transport")

    prerequisites = notice["prerequisites"]
    if not isinstance(prerequisites, list) or not prerequisites:
        raise ServiceNoticeError(f"{path}.prerequisites must be a non-empty list")
    for prerequisite_index, prerequisite_value in enumerate(prerequisites):
        prerequisite_path = f"{path}.prerequisites[{prerequisite_index}]"
        prerequisite = _object(prerequisite_value, prerequisite_path, {"key", "description"})
        _text(prerequisite["key"], f"{prerequisite_path}.key")
        _text(prerequisite["description"], f"{prerequisite_path}.description")

    mappings = notice["attack_mappings"]
    if not isinstance(mappings, list):
        raise ServiceNoticeError(f"{path}.attack_mappings must be a list")
    for mapping_index, mapping_value in enumerate(mappings):
        mapping_path = f"{path}.attack_mappings[{mapping_index}]"
        mapping = _object(mapping_value, mapping_path, {"technique_id", "rationale", "required_evidence"})
        technique_id = _text(mapping["technique_id"], f"{mapping_path}.technique_id")
        if not ATTACK_ID.fullmatch(technique_id):
            raise ServiceNoticeError(f"{mapping_path}.technique_id has invalid format")
        _text(mapping["rationale"], f"{mapping_path}.rationale")
        _strings(mapping["required_evidence"], f"{mapping_path}.required_evidence")

    defensive = _object(
        notice["defensive"],
        f"{path}.defensive",
        {"detection", "remediation", "safe_applicability", "safe_next_action"},
    )
    _strings(defensive["detection"], f"{path}.defensive.detection")
    _strings(defensive["remediation"], f"{path}.defensive.remediation")
    _text(defensive["safe_applicability"], f"{path}.defensive.safe_applicability")
    _text(defensive["safe_next_action"], f"{path}.defensive.safe_next_action")
    _strings(notice["limitations"], f"{path}.limitations")
    return notice_id


def validate_registry(registry: Any) -> dict[str, Any]:
    """Validate and return a service attack notice registry."""

    document = _object(registry, "registry", {"schema_version", "catalog_version", "notices"})
    if _text(document["schema_version"], "registry.schema_version") != SCHEMA_VERSION:
        raise ServiceNoticeError("registry.schema_version is unsupported")
    _text(document["catalog_version"], "registry.catalog_version")
    notices = document["notices"]
    if not isinstance(notices, list) or not notices:
        raise ServiceNoticeError("registry.notices must be a non-empty list")
    notice_ids = [_validate_notice(notice, index) for index, notice in enumerate(notices)]
    if len(set(notice_ids)) != len(notice_ids):
        raise ServiceNoticeError("duplicate notice id")
    by_id = {notice["id"]: notice for notice in notices}
    for notice in notices:
        successor = notice["lifecycle"]["superseded_by"]
        if successor and successor not in by_id:
            raise ServiceNoticeError(f"{notice['id']} references an unknown successor notice")
        if not successor:
            continue
        next_notice = by_id[successor]
        if next_notice["lifecycle"]["state"] == "withdrawn":
            raise ServiceNoticeError(f"{notice['id']} references a withdrawn successor notice")
        prior_os = {item.casefold() for item in notice["scope"]["operating_systems"]}
        next_os = {item.casefold() for item in next_notice["scope"]["operating_systems"]}
        prior_products = {item["name"].casefold() for item in notice["scope"]["products"]}
        next_products = {item["name"].casefold() for item in next_notice["scope"]["products"]}
        if not (prior_os & next_os) or not (prior_products & next_products):
            raise ServiceNoticeError(f"{notice['id']} references an incompatible successor notice")
        seen = {notice["id"]}
        while successor:
            if successor in seen:
                raise ServiceNoticeError(f"{notice['id']} has a successor cycle")
            seen.add(successor)
            successor = by_id[successor]["lifecycle"]["superseded_by"]
    return document


def load_registry(path: Path) -> dict[str, Any]:
    """Load and validate the versioned local registry."""

    return validate_registry(load_json_file(path, label="service attack notice registry"))


def _validate_asset(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ServiceNoticeError("asset input must be an object")
    allowed = {"asset_id", "operating_system", "product", "version", "services", "evidence"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ServiceNoticeError(f"asset input has unsupported field(s): {', '.join(unknown)}")
    asset_id = value.get("asset_id")
    _text(asset_id, "asset.asset_id")
    for key in ("operating_system", "product", "version"):
        if key in value:
            _text(value[key], f"asset.{key}")
    evidence = value.get("evidence", [])
    _strings(evidence, "asset.evidence", allow_empty=True)
    services = value.get("services", [])
    if not isinstance(services, list):
        raise ServiceNoticeError("asset.services must be a list")
    seen_services: set[tuple[str, str]] = set()
    for index, service_value in enumerate(services):
        path = f"asset.services[{index}]"
        if not isinstance(service_value, dict):
            raise ServiceNoticeError(f"{path} must be an object")
        allowed_service = {"name", "transport", "reachable", "configured"}
        unknown_service = sorted(set(service_value) - allowed_service)
        if unknown_service:
            raise ServiceNoticeError(f"{path} has unsupported field(s): {', '.join(unknown_service)}")
        _text(service_value.get("name"), f"{path}.name")
        transport = _text(service_value.get("transport"), f"{path}.transport")
        if transport not in {"tcp", "udp"}:
            raise ServiceNoticeError(f"{path}.transport is unsupported")
        identity = (service_value["name"].casefold(), transport)
        if identity in seen_services:
            raise ServiceNoticeError(f"{path} duplicates an asset service")
        seen_services.add(identity)
        for field in ("reachable", "configured"):
            if field in service_value and not isinstance(service_value[field], bool):
                raise ServiceNoticeError(f"{path}.{field} must be boolean")
    return value


def _result(notice: dict[str, Any], status: str, reasons: list[str], missing: list[str], action: str) -> dict[str, Any]:
    if status not in RESULT_STATUSES:  # defensive invariant
        raise AssertionError(f"unsupported result status: {status}")
    return {
        "notice_id": notice["id"],
        "status": status,
        "input_verification": "unverified",
        "review_date": notice["review_date"],
        "review_due": notice["review_due"],
        "publication_date": notice["publication_date"],
        "observation_date": notice["observation_date"],
        "observation_context": notice["observation_context"],
        "sources": notice["sources"],
        "conditional_attack_mappings": notice["attack_mappings"],
        "mapping_application": "not_assessed",
        "defensive": notice["defensive"],
        "limitations": notice["limitations"],
        "reasons": reasons,
        "missing_evidence": sorted(set(missing)),
        "safe_next_action": action,
    }


def _assess_notice(notice: dict[str, Any], asset: dict[str, Any], *, as_of: date) -> dict[str, Any]:
    lifecycle = notice["lifecycle"]["state"]
    if lifecycle != "active":
        return _result(
            notice,
            "not_applicable",
            [f"Notice lifecycle is {lifecycle}; terminal notices cannot produce candidates."],
            [],
            "Use an active, reviewed successor notice before investigating applicability.",
        )
    if as_of > date.fromisoformat(notice["review_due"]):
        return _result(
            notice,
            "unknown",
            ["The notice is past its review_due date and cannot produce a candidate."],
            ["fresh_source_review"],
            "Recheck every cited primary source and update the registry review metadata.",
        )

    product_name = asset.get("product")
    if product_name is None:
        return _result(notice, "unknown", ["Product evidence is missing."], ["product"], "Collect exact product and version inventory.")
    products = {item["name"].casefold(): item for item in notice["scope"]["products"]}
    product = products.get(product_name.casefold())
    if product is None:
        return _result(
            notice,
            "not_applicable",
            ["The supplied asset product is outside the notice's explicit product allowlist."],
            [],
            "Do not generalize this product-specific notice to the asset.",
        )

    operating_system = asset.get("operating_system")
    if operating_system is None:
        return _result(notice, "unknown", ["Operating-system evidence is missing."], ["operating_system"], "Collect exact operating-system inventory.")
    allowed_systems = {item.casefold() for item in notice["scope"]["operating_systems"]}
    if operating_system.casefold() not in allowed_systems:
        return _result(
            notice,
            "not_applicable",
            ["The supplied asset operating system is outside the notice's explicit allowlist."],
            [],
            "Do not extend the notice to an unlisted operating system.",
        )

    version = asset.get("version")
    if version is None:
        return _result(notice, "unknown", ["Version evidence is missing."], ["version"], "Collect an exact product version.")
    normalized_version = version.casefold()
    fixed_versions = {item.casefold() for item in product["fixed_versions"]}
    affected_versions = {item.casefold() for item in product["affected_versions"]}
    if normalized_version in fixed_versions:
        return _result(
            notice,
            "fixed",
            ["The supplied exact product version is in the notice's fixed-version allowlist."],
            [],
            "Verify the installed build and retain update evidence.",
        )
    if normalized_version not in affected_versions:
        return _result(
            notice,
            "unknown",
            ["The exact version is not in the notice's affected or fixed allowlist."],
            ["source_scoped_version_evidence"],
            "Review current primary sources before changing the registry version scope.",
        )

    configured_services: list[dict[str, Any]] = []
    rules = {
        (service["name"].casefold(), transport)
        for service in notice["services"]
        for transport in service["transports"]
    }
    for service in asset.get("services", []):
        if (service["name"].casefold(), service["transport"]) in rules:
            configured_services.append(service)
    if not configured_services:
        return _result(
            notice,
            "unknown",
            ["No source-scoped service context is present."],
            ["service", "reachability", "configuration"],
            "Collect service identity, reachability, and enabled/configured state.",
        )
    if all(service.get("reachable") is False for service in configured_services):
        return _result(notice, "not_applicable", ["The supplied input reports the required service unreachable."], [], "Verify and retain reachability evidence, then monitor configuration changes.")
    if not any(service.get("reachable") is True for service in configured_services):
        return _result(notice, "unknown", ["Service reachability is not established."], ["reachability"], "Confirm service reachability without extending scan scope.")
    reachable = [service for service in configured_services if service.get("reachable") is True]
    if all(service.get("configured") is False for service in reachable):
        return _result(notice, "not_applicable", ["The supplied input reports the required service disabled or unconfigured."], [], "Verify and retain configuration evidence, then monitor changes.")
    if not any(service.get("configured") is True for service in reachable):
        return _result(notice, "unknown", ["Required service configuration is not established."], ["configuration"], "Confirm the enabled/configured state from trusted local evidence.")

    supplied_evidence = {item.casefold() for item in asset.get("evidence", [])}
    missing_keys = [item["key"] for item in notice["prerequisites"] if item["key"].casefold() not in supplied_evidence]
    if missing_keys:
        return _result(
            notice,
            "unknown",
            ["Required contextual prerequisites are not evidenced."],
            missing_keys,
            "Collect the named contextual evidence; a service observation alone is insufficient.",
        )
    return _result(
        notice,
        "candidate",
        ["The supplied product, version, service state, and contextual prerequisites match this notice."],
        [],
        notice["defensive"]["safe_next_action"],
    )


def assess_asset(registry: Any, asset: Any, *, as_of: date) -> dict[str, Any]:
    """Assess one asset context against every notice without I/O or side effects."""

    document = validate_registry(registry)
    context = _validate_asset(asset)
    results = [_assess_notice(notice, context, as_of=as_of) for notice in document["notices"]]
    missing = {item for result in results for item in result["missing_evidence"]}
    if context.get("services") and not any("configured" in service for service in context["services"]):
        missing.add("configuration")
    if "product" not in context:
        missing.add("product")
    if "version" not in context:
        missing.add("version")
    return {
        "status": "ok",
        "registry_version": document["catalog_version"],
        "asset_id": context["asset_id"],
        "assessed_on": as_of.isoformat(),
        "input_verification": "unverified",
        "reasons": ["Offline allowlist assessment of unverified input completed; candidate results propose investigation only."],
        "missing_evidence": sorted(missing),
        "safe_next_action": "Review each notice result and collect missing evidence without expanding authorization or scan scope.",
        "results": results,
    }


def list_notices(registry: dict[str, Any]) -> dict[str, Any]:
    """Project registry metadata without asserting asset applicability."""

    notices = [
        {
            "id": notice["id"],
            "title": notice["title"],
            "status": notice["status"],
            "publication_date": notice["publication_date"],
            "observation_date": notice["observation_date"],
            "observation_context": notice["observation_context"],
            "review_date": notice["review_date"],
            "review_due": notice["review_due"],
            "products": [product["name"] for product in notice["scope"]["products"]],
            "sources": notice["sources"],
            "conditional_attack_mappings": notice["attack_mappings"],
        }
        for notice in registry["notices"]
    ]
    return {
        "status": "ok",
        "registry_version": registry["catalog_version"],
        "reasons": ["Notices are local research inputs, not findings."],
        "missing_evidence": [],
        "safe_next_action": "Assess a bounded local asset context or review notices whose review_due date is approaching.",
        "notices": notices,
    }


def _error_document(error: Exception) -> dict[str, Any]:
    return {
        "status": "error",
        "reasons": [str(error)],
        "missing_evidence": [],
        "safe_next_action": "Correct the local JSON or registry validation error; no assessment was performed.",
    }


def command_service_notices(args: Namespace, *, root: Path) -> int:
    """Run the machine-readable service-notices CLI."""

    try:
        registry = load_registry(root / "catalog/service_attack_notices.json")
        if args.service_notices_command == "validate":
            output = {
                "status": "valid",
                "registry_version": registry["catalog_version"],
                "notice_count": len(registry["notices"]),
                "reasons": ["Registry structure, lifecycle, source, date, and version constraints passed."],
                "missing_evidence": [],
                "safe_next_action": "Review cited primary sources by each notice's review_due date.",
            }
        elif args.service_notices_command == "list":
            output = list_notices(registry)
        elif args.service_notices_command == "assess":
            asset = load_json_file(args.input, label="asset input")
            output = assess_asset(registry, asset, as_of=date.today())
        else:  # pragma: no cover - argparse constrains the command
            raise ServiceNoticeError("unsupported service-notices command")
    except ServiceNoticeError as error:
        print(json.dumps(_error_document(error), indent=2, ensure_ascii=False))
        return 2
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0
