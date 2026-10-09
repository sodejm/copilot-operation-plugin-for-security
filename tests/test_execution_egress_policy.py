"""Operation policy parsing is an exact, closed authorization boundary."""

from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType

import pytest

from cops.execution.egress_policy import OperationEgressPolicyError, parse_operation_egress_policy


def _operation() -> dict[str, object]:
    return {
        "egress_policy": {
            "https_endpoint": {
                "host": "api.example.test",
                "port": 443,
                "identity": {
                    "provider": "example",
                    "service": "inventory",
                    "account": "account-a",
                    "tenant": "tenant-a",
                    "cluster": "cluster-a",
                    "namespace": "namespace-a",
                    "resource": "resource-a",
                },
                "request_targets": ["/v1/accounts/account-a/resources/resource-a"],
            }
        }
    }


def test_absent_policy_is_no_egress() -> None:
    assert parse_operation_egress_policy({"tool": "inert"}) is None


def test_exact_policy_binds_origin_identity_and_target() -> None:
    policy = parse_operation_egress_policy(_operation())
    assert policy is not None
    assert (policy.host, policy.port) == ("api.example.test", 443)
    policy.identity_allowlist.require(
        policy.identity, request_target="/v1/accounts/account-a/resources/resource-a"
    )
    with pytest.raises(Exception, match="outside the exact identity allowlist"):
        policy.identity_allowlist.require(policy.identity, request_target="/v1/accounts/account-b/resources/resource-a")


def test_frozen_action_plan_policy_is_accepted() -> None:
    operation = _operation()
    endpoint = operation["egress_policy"]["https_endpoint"]  # type: ignore[index]
    endpoint["request_targets"] = tuple(endpoint["request_targets"])  # type: ignore[index]
    endpoint["identity"] = MappingProxyType(endpoint["identity"])  # type: ignore[arg-type,index]
    operation["egress_policy"] = MappingProxyType({"https_endpoint": MappingProxyType(endpoint)})
    assert parse_operation_egress_policy(MappingProxyType(operation)) is not None


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("egress_policy",), None),
        (("egress_policy", "https_endpoint", "host"), "API.EXAMPLE.TEST"),
        (("egress_policy", "https_endpoint", "host"), "api.example.test."),
        (("egress_policy", "https_endpoint", "host"), "127.1"),
        (("egress_policy", "https_endpoint", "host"), "::ffff:127.0.0.1"),
        (("egress_policy", "https_endpoint", "port"), True),
        (("egress_policy", "https_endpoint", "port"), 0),
        (("egress_policy", "https_endpoint", "identity", "account"), "*"),
        (("egress_policy", "https_endpoint", "request_targets"), ["/a", "/a"]),
        (("egress_policy", "https_endpoint", "request_targets"), ["/a/../b"]),
        (("egress_policy", "https_endpoint", "request_targets"), ["https://api.example.test/a"]),
    ],
)
def test_ambiguous_or_broad_policy_is_rejected(path: tuple[str, ...], value: object) -> None:
    operation = deepcopy(_operation())
    parent = operation
    for key in path[:-1]:
        parent = parent[key]  # type: ignore[assignment,index]
    parent[path[-1]] = value
    with pytest.raises(OperationEgressPolicyError):
        parse_operation_egress_policy(operation)


def test_extra_policy_dimension_is_rejected() -> None:
    operation = _operation()
    endpoint = operation["egress_policy"]["https_endpoint"]  # type: ignore[index]
    endpoint["proxy"] = "http://proxy.example.test"  # type: ignore[index]
    with pytest.raises(OperationEgressPolicyError):
        parse_operation_egress_policy(operation)
