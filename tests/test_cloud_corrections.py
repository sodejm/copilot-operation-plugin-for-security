from __future__ import annotations

import copy
import json

import pytest

from cops.assessments import assess


def codes(kind: str, content: object) -> set[str]:
    original = copy.deepcopy(content)
    result = assess(
        "cloud_configuration",
        [{"artifact_id": "cloud", "kind": kind, "content": content}],
        as_of="2026-10-15T12:00:00Z",
    )
    assert content == original
    return set(result["finding_codes"].values())


def plan(resource_type: str, values: dict, **change: object) -> dict:
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "example.resource",
                "type": resource_type,
                "change": {"actions": ["update"], "after": values, "after_unknown": {}, **change},
            }
        ],
    }


def test_terraform_reads_after_not_deleted_or_before_values() -> None:
    risky = {"ingress": [{"cidr_blocks": ["0.0.0.0/0", "::/0"]}]}
    assert "internet_ingress" in codes("terraform_plan", plan("aws_security_group", risky))
    fixed = {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}], "egress": risky["ingress"]}
    assert "internet_ingress" not in codes("terraform_plan", plan("aws_security_group", fixed, before=risky))
    assert "internet_ingress" not in codes(
        "terraform_plan", plan("aws_security_group", {}, actions=["delete"], after=None, before=risky)
    )


def test_terraform_unknown_and_unsupported_resources_are_partial() -> None:
    assert "cloud_configuration_insufficient_evidence" in codes(
        "terraform_plan", plan("aws_security_group", {}, after_unknown={"ingress": True})
    )
    assert "cloud_configuration_insufficient_evidence" in codes(
        "terraform_plan", plan("unregistered_custom_resource", {})
    )


@pytest.mark.parametrize("effect,expected", [("Allow", True), ("Deny", False)])
def test_iam_effect_controls_wildcard_observation(effect: str, expected: bool) -> None:
    document = {"Statement": [{"Effect": effect, "Action": "s3:*", "Resource": "*"}]}
    assert ("iam_wildcard" in codes("aws_export", document)) is expected
    assert (
        "iam_wildcard" in codes("terraform_plan", plan("aws_iam_policy", {"policy": json.dumps(document)}))
    ) is expected


def test_iam_constrained_resource_is_not_a_global_wildcard() -> None:
    assert "iam_wildcard" not in codes(
        "aws_export",
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example/*",
                }
            ]
        },
    )


def test_public_acl_structures_do_not_raise_and_distinguish_groups() -> None:
    public = {
        "Grants": [
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }
        ]
    }
    private = {"Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "synthetic"}, "Permission": "FULL_CONTROL"}]}
    assert "public_storage" in codes("aws_export", public)
    assert "public_storage" not in codes("aws_export", private)
    assert "cloud_configuration_insufficient_evidence" in codes("aws_export", {"acl": {"unexpected": []}})


def test_kubernetes_workload_rbac_and_direction_are_typed() -> None:
    pod = {"apiVersion": "v1", "kind": "Pod", "spec": {"containers": [{"securityContext": {"privileged": True}}]}}
    assert "workload_privilege" in codes("kubernetes_rendered", pod)
    role = {"kind": "ClusterRole", "rules": [{"verbs": ["*"], "resources": ["*"]}]}
    assert "iam_wildcard" in codes("kubernetes_rendered", role)
    role["rules"][0]["verbs"] = ["get"]
    role["rules"][0]["resources"] = ["pods"]
    assert "iam_wildcard" not in codes("kubernetes_rendered", role)
    policy = {"kind": "NetworkPolicy", "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]}}
    assert "internet_ingress" not in codes("kubernetes_rendered", policy)
    policy["spec"] = {
        "podSelector": {},
        "policyTypes": ["Ingress"],
        "ingress": [{"from": [{"ipBlock": {"cidr": "::/0"}}]}],
    }
    assert "internet_ingress" in codes("kubernetes_rendered", policy)


@pytest.mark.parametrize(
    "kind,content",
    [
        (
            "aws_export",
            {
                "SecurityGroups": [
                    {"IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "IpPermissionsEgress": []}
                ]
            },
        ),
        (
            "azure_export",
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "properties": {
                    "securityRules": [
                        {"properties": {"access": "Allow", "direction": "Inbound", "sourceAddressPrefixes": ["::/0"]}}
                    ]
                },
            },
        ),
        (
            "gcp_export",
            {
                "kind": "compute#firewall",
                "direction": "INGRESS",
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp"}],
            },
        ),
    ],
)
def test_provider_ingress_correction(kind: str, content: dict) -> None:
    assert "internet_ingress" in codes(kind, content)
    corrected = json.loads(json.dumps(content).replace("0.0.0.0/0", "10.0.0.0/8").replace("::/0", "fd00::/8"))
    assert "internet_ingress" not in codes(kind, corrected)


@pytest.mark.parametrize(
    "kind,content",
    [
        ("terraform_plan", {}),
        ("terraform_plan", {"format_version": "9.0", "resource_changes": []}),
        ("kubernetes_rendered", []),
        ("kubernetes_rendered", {"kind": "UnknownCustomResource"}),
        ("aws_export", {}),
        ("azure_export", {"value": [None]}),
        ("gcp_export", {"bindings": "invalid"}),
    ],
)
def test_unrecognized_or_malformed_exports_are_unknown(kind: str, content: object) -> None:
    assert "cloud_configuration_insufficient_evidence" in codes(kind, content)


@pytest.mark.parametrize(
    "kind,content",
    [
        ("aws_export", {"Statement": [{"Effect": {}, "Action": "*", "Resource": "*"}]}),
        ("terraform_plan", {"format_version": "1.2", "resource_changes": [{"change": {"actions": [{}]}}]}),
        ("kubernetes_rendered", {"kind": {}}),
        ("gcp_export", {"bindings": [{"role": [], "members": []}]}),
        (
            "azure_export",
            {
                "type": "Microsoft.Network/networkSecurityGroups",
                "properties": {"securityRules": [{"properties": {"direction": [], "access": "Allow"}}]},
            },
        ),
    ],
)
def test_nested_wrong_types_are_partial_without_crashing(kind: str, content: dict) -> None:
    assert "cloud_configuration_insufficient_evidence" in codes(kind, content)


def bucket_statement(**extra: object) -> dict:
    return {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/*", **extra}


@pytest.mark.parametrize("wrapper", ["direct", "policy", "terraform-iam", "terraform-bucket"])
@pytest.mark.parametrize(
    "condition",
    [{"StringEquals": {"aws:PrincipalOrgID": "o-synthetic"}}, {}, None, [], "unsupported"],
)
def test_conditional_public_principal_is_unknown_in_every_registered_shape(wrapper: str, condition: object) -> None:
    policy = {"Statement": [bucket_statement(Condition=condition)]}
    if wrapper.startswith("terraform"):
        kind = "terraform_plan"
        resource = "aws_iam_policy" if wrapper == "terraform-iam" else "aws_s3_bucket_policy"
        content = plan(resource, {"policy": json.dumps(policy)})
    else:
        kind = "aws_export"
        content = policy if wrapper == "direct" else {"Policy": json.dumps(policy)}
    observed = codes(kind, content)
    assert "public_storage" not in observed
    assert "iam_wildcard" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


def test_conditional_policy_does_not_hide_an_unconditional_public_statement() -> None:
    conditional = bucket_statement(Condition={"StringEquals": {"aws:PrincipalOrgID": "o-synthetic"}})
    assert "public_storage" in codes("aws_export", {"Statement": [bucket_statement()]})
    mixed = codes("aws_export", {"Statement": [conditional, bucket_statement()]})
    assert {"public_storage", "cloud_configuration_insufficient_evidence"} <= mixed
    assert "public_storage" not in codes("aws_export", {"Statement": [bucket_statement(Effect="Deny")]})


def test_conditional_wildcard_cannot_establish_effective_permissions() -> None:
    observed = codes("aws_export", {"Statement": [bucket_statement(Action="s3:*", Resource="*", Condition={})]})
    assert observed == {"cloud_configuration_insufficient_evidence"}
