"""Parse an operation's exact HTTPS destination and resource authorization."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

from .egress import AuthenticatedServiceAllowlist, AuthenticatedServiceIdentity

_IDENTITY_FIELDS = frozenset(field.name for field in fields(AuthenticatedServiceIdentity))
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class OperationEgressPolicyError(ValueError):
    """An operation has no unambiguous, bounded egress policy."""


@dataclass(frozen=True)
class HTTPSOperationEgressPolicy:
    """One exact HTTPS origin, authenticated identity, and set of request targets."""

    host: str
    port: int
    identity: AuthenticatedServiceIdentity
    request_targets: frozenset[str]

    @property
    def identity_allowlist(self) -> AuthenticatedServiceAllowlist:
        return AuthenticatedServiceAllowlist({self.identity: self.request_targets})


def _canonical_host(value: Any) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise OperationEgressPolicyError("HTTPS egress host must be canonical")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # A numeric-looking name can be interpreted as an alternate IP notation
        # by resolver implementations. Require a DNS label with a letter.
        if (
            len(value) > 253
            or value != value.lower()
            or value.endswith(".")
            or not any(character.isalpha() for character in value)
            or not all(_DNS_LABEL.fullmatch(label) for label in value.split("."))
        ):
            raise OperationEgressPolicyError("HTTPS egress host must be canonical") from None
    else:
        if str(address) != value or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped):
            raise OperationEgressPolicyError("HTTPS egress IP literal must be canonical")
    return value


def parse_operation_egress_policy(operation: Mapping[str, Any]) -> HTTPSOperationEgressPolicy | None:
    """Require a closed policy; missing policy means the operation has no egress."""

    if "egress_policy" not in operation:
        return None
    policy = operation["egress_policy"]
    if not isinstance(policy, Mapping) or set(policy) != {"https_endpoint"}:
        raise OperationEgressPolicyError("operation egress policy must contain one HTTPS endpoint")
    endpoint = policy["https_endpoint"]
    if not isinstance(endpoint, Mapping) or set(endpoint) != {"host", "port", "identity", "request_targets"}:
        raise OperationEgressPolicyError("HTTPS endpoint policy fields are invalid")
    host = _canonical_host(endpoint["host"])
    port = endpoint["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise OperationEgressPolicyError("HTTPS endpoint port is invalid")
    identity_value = endpoint["identity"]
    if not isinstance(identity_value, Mapping) or set(identity_value) != _IDENTITY_FIELDS:
        raise OperationEgressPolicyError("authenticated service identity fields are invalid")
    try:
        identity = AuthenticatedServiceIdentity(**dict(identity_value))
    except (TypeError, ValueError) as err:
        raise OperationEgressPolicyError("authenticated service identity is invalid") from err
    targets = endpoint["request_targets"]
    if not isinstance(targets, (list, tuple)) or not targets or any(not isinstance(target, str) for target in targets):
        raise OperationEgressPolicyError("HTTPS request targets must be non-empty strings")
    if len(targets) != len(set(targets)):
        raise OperationEgressPolicyError("HTTPS request targets must be non-empty and unique")
    try:
        allowlist = AuthenticatedServiceAllowlist({identity: frozenset(targets)})
    except (TypeError, ValueError) as err:
        raise OperationEgressPolicyError("HTTPS request targets are invalid") from err
    return HTTPSOperationEgressPolicy(host, port, identity, allowlist.request_targets[identity])
