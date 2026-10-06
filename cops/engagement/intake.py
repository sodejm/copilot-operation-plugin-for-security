"""Engagement intake parsing, validation, and mode enforcement."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from cops.contracts.models import Engagement
from cops.contracts.validation import validate_contract

from .errors import (
    EngagementIntakeError,
    IncompatibleWindowError,
    IncompleteBudgetError,
    IncompleteLiveRequestError,
    MissingOwnerError,
    ScopeAmbiguityError,
)

VALID_MODES = {"planning", "import", "laboratory", "live"}
HOSTNAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _is_valid_ip_or_cidr(val: str) -> bool:
    try:
        ipaddress.ip_network(val, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_hostname(val: str) -> bool:
    if not val or len(val) > 255:
        return False
    return bool(HOSTNAME_PATTERN.fullmatch(val))


def _parse_timestamp(val: str, label: str) -> datetime:
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError) as err:
        raise IncompatibleWindowError(f"{label} has invalid ISO-8601 timestamp '{val}'") from err


def validate_engagement_intake(data: dict[str, Any]) -> dict[str, Any]:
    """Validate raw engagement intake input against security and operational boundaries."""
    if not isinstance(data, dict):
        raise EngagementIntakeError("Engagement intake document must be an object")

    # 1. Ownership validation
    operator = data.get("operator")
    if not operator or not isinstance(operator, str) or not operator.strip():
        raise MissingOwnerError("Engagement must have an explicit, non-empty owner/operator")
    operator = operator.strip()

    # 2. Window validation
    window = data.get("window")
    if not isinstance(window, dict):
        raise IncompatibleWindowError("Engagement must specify an assessment window object")
    started_at_raw = window.get("started_at")
    until_raw = window.get("authorized_until_utc")
    if not started_at_raw or not until_raw:
        raise IncompatibleWindowError("Assessment window requires both 'started_at' and 'authorized_until_utc'")
    t_start = _parse_timestamp(str(started_at_raw), "window.started_at")
    t_end = _parse_timestamp(str(until_raw), "window.authorized_until_utc")
    if t_end <= t_start:
        raise IncompatibleWindowError(
            f"Assessment window end time ({until_raw}) must be strictly after start time ({started_at_raw})"
        )

    # 3. Scope / Target validation
    scope = data.get("scope")
    if not isinstance(scope, dict):
        raise ScopeAmbiguityError("Engagement must specify a scope object")
    included = scope.get("included_targets")
    excluded = scope.get("excluded_targets", [])
    if not isinstance(included, list) or not included:
        raise ScopeAmbiguityError("Scope must specify at least one included target")
    if not isinstance(excluded, list):
        raise ScopeAmbiguityError("Scope excluded_targets must be a list")

    excluded_set = {str(t).strip().lower() for t in excluded if isinstance(t, str)}
    parsed_excluded_networks = []
    for exc in excluded:
        if isinstance(exc, str) and _is_valid_ip_or_cidr(exc):
            try:
                parsed_excluded_networks.append(ipaddress.ip_network(exc, strict=False))
            except ValueError:
                pass

    for target in included:
        if not isinstance(target, str) or not target.strip():
            raise ScopeAmbiguityError("Target cannot be empty or whitespace")
        target_str = target.strip()
        target_lower = target_str.lower()

        # Reject wildcard patterns
        if "*" in target_str or target_str in ("0.0.0.0/0", "::/0"):
            raise ScopeAmbiguityError(f"Ambiguous wildcard or universal target not permitted: '{target_str}'")

        # Must be valid IP, CIDR, or hostname
        is_ip_net = _is_valid_ip_or_cidr(target_str)
        is_host = _is_valid_hostname(target_str)
        if not (is_ip_net or is_host):
            raise ScopeAmbiguityError(f"Target '{target_str}' is malformed (must be valid IP, CIDR, or FQDN)")

        # Direct collision with exclusions
        if target_lower in excluded_set:
            raise ScopeAmbiguityError(
                f"Target '{target_str}' is simultaneously in included_targets and excluded_targets"
            )

        # Overlapping CIDR collision check
        if is_ip_net:
            try:
                target_net = ipaddress.ip_network(target_str, strict=False)
            except ValueError:
                target_net = None
            if target_net is not None:
                for exc_net in parsed_excluded_networks:
                    if target_net.overlaps(exc_net) and target_net.subnet_of(exc_net):
                        raise ScopeAmbiguityError(
                            f"Target network '{target_str}' is fully contained within excluded network '{exc_net}'"
                        )

    # 4. Budget validation
    budget = data.get("budget")
    if budget is not None:
        if not isinstance(budget, dict):
            raise IncompleteBudgetError("Budget must be a dictionary with max_duration_seconds and max_output_bytes")
        dur = budget.get("max_duration_seconds")
        out = budget.get("max_output_bytes")
        if dur is None or out is None or not isinstance(dur, int) or not isinstance(out, int) or dur <= 0 or out <= 0:
            raise IncompleteBudgetError(
                "Incomplete budget: 'max_duration_seconds' and 'max_output_bytes' must be positive integers"
            )

    # 5. Mode validation & Live execution refusal
    mode = data.get("mode", "planning")
    if mode not in VALID_MODES:
        raise EngagementIntakeError(
            f"Unsupported execution mode '{mode}'. Supported modes are: {sorted(VALID_MODES)}"
        )

    roe = data.get("rules_of_engagement", {})
    if not isinstance(roe, dict):
        raise EngagementIntakeError("rules_of_engagement must be an object")

    if mode == "live":
        # Live execution requires strict completeness and safety bounds
        if operator.lower() in ("unknown", "anonymous", "placeholder", "tbd"):
            raise IncompleteLiveRequestError(
                f"Live execution refused: placeholder operator '{operator}' is not permitted"
            )

        emergency = roe.get("emergency_contact")
        if not emergency or not isinstance(emergency, str) or len(emergency.strip()) < 3:
            raise IncompleteLiveRequestError(
                "Live execution refused: non-empty emergency_contact is mandatory"
            )

        if budget is None:
            raise IncompleteLiveRequestError(
                "Live execution refused: explicit budget (max_duration_seconds, max_output_bytes) is mandatory. "
                "For unconstrained analysis without execution bounds, use 'planning' or 'laboratory' mode."
            )

        if not roe.get("safe_mode", False):
            raise IncompleteLiveRequestError(
                "Live execution refused: safe_mode must be enabled for automated live assessments"
            )

        # Check subnet width limits for live execution (e.g. no subnets wider than /24)
        for target in included:
            target_str = target.strip()
            if _is_valid_ip_or_cidr(target_str):
                try:
                    net = ipaddress.ip_network(target_str, strict=False)
                except ValueError:
                    net = None
                if net is not None and net.version == 4 and net.prefixlen < 24:
                    raise IncompleteLiveRequestError(
                        f"Live execution refused: target network '{target_str}' exceeds maximum allowed scope (/24). "
                        "Refine target scope or select 'planning' mode."
                    )

    # 6. Credential references check
    cred_refs = data.get("credential_references", [])
    if isinstance(cred_refs, list):
        for ref in cred_refs:
            if not isinstance(ref, str) or not re.fullmatch(r"^[A-Za-z0-9_.-]+$", ref):
                raise EngagementIntakeError(f"Malformed credential reference identifier: '{ref}'")
            if any(secret_marker in ref.lower() for secret_marker in ("bearer ", "ghp_", "eyj", "pass")):
                raise EngagementIntakeError(f"Plaintext secret marker detected in credential reference '{ref}'")

    # 7. Validate against base contract schema
    validate_contract(data, "engagement")
    return data


def create_engagement_contract(
    *,
    name: str,
    operator: str,
    included_targets: list[str],
    excluded_targets: list[str] | None = None,
    started_at: str,
    authorized_until_utc: str,
    allowed_actions: list[str] | None = None,
    max_intensity: str = "low",
    emergency_contact: str = "security-ops@internal.net",
    safe_mode: bool = True,
    mode: str = "planning",
    budget: dict[str, int] | None = None,
    credential_references: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    engagement_id: str | None = None,
) -> Engagement:
    """Create and validate a new Engagement contract instance."""
    if engagement_id is None:
        random_suffix = uuid.uuid4().hex[:8]
        engagement_id = f"eng-cops-{random_suffix}"

    data: dict[str, Any] = {
        "schema_version": "cops.engagement/v1",
        "engagement_id": engagement_id,
        "name": name,
        "status": "planned",
        "scope": {
            "included_targets": included_targets,
            "excluded_targets": excluded_targets or [],
        },
        "window": {
            "started_at": started_at,
            "authorized_until_utc": authorized_until_utc,
        },
        "operator": operator,
        "rules_of_engagement": {
            "max_intensity": max_intensity,
            "allowed_actions": allowed_actions or ["read_only_discovery", "configuration_audit"],
            "emergency_contact": emergency_contact,
            "safe_mode": safe_mode,
        },
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "mode": mode,
    }
    if budget is not None:
        data["budget"] = budget
    if credential_references is not None:
        data["credential_references"] = credential_references
    if metadata is not None:
        data["metadata"] = metadata

    validated = validate_engagement_intake(data)
    return Engagement.from_dict(validated)
