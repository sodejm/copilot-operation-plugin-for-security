from __future__ import annotations

import copy

import pytest

from cops.assessments import assess


def network_policy(*peers: object) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": list(peers)}],
        },
    }


def codes(policy: dict) -> set[str]:
    original = copy.deepcopy(policy)
    result = assess(
        "cloud_configuration",
        [{"artifact_id": "network-policy", "kind": "kubernetes_rendered", "content": policy}],
        as_of="2026-10-18T12:00:00Z",
    )
    assert policy == original
    return set(result["finding_codes"].values())


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
@pytest.mark.parametrize("except_value", [None, []])
def test_world_ipblock_without_effective_exclusions_flags_ingress(cidr: str, except_value: object) -> None:
    ip_block = {"cidr": cidr}
    if except_value is not None:
        ip_block["except"] = except_value

    assert "internet_ingress" in codes(network_policy({"ipBlock": ip_block}))


def test_covering_nonempty_exclusions_cannot_claim_world_ingress() -> None:
    observed = codes(
        network_policy(
            {
                "ipBlock": {
                    "cidr": "0.0.0.0/0",
                    "except": ["0.0.0.0/1", "128.0.0.0/1"],
                }
            }
        )
    )

    assert "internet_ingress" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


@pytest.mark.parametrize(
    "ip_block",
    [
        {"cidr": "0.0.0.0/0", "except": "10.0.0.0/8"},
        {"cidr": "0.0.0.0/0", "except": [123]},
        {"cidr": "0.0.0.0/0", "except": ["not-a-cidr"]},
        {"cidr": "not-a-cidr", "except": []},
        {"cidr": 0, "except": []},
        {"except": []},
        "0.0.0.0/0",
    ],
)
def test_malformed_ipblock_or_exclusions_remain_incomplete(ip_block: object) -> None:
    observed = codes(network_policy({"ipBlock": ip_block}))

    assert "internet_ingress" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


@pytest.mark.parametrize(
    "cidr",
    [
        "0.0.0.0",
        "0.0.0.0/0.0.0.0",
        "::%eth0/0",
    ],
)
def test_non_kubernetes_cidr_forms_remain_incomplete(cidr: str) -> None:
    observed = codes(network_policy({"ipBlock": {"cidr": cidr}}))

    assert "internet_ingress" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


@pytest.mark.parametrize(
    "exclusion",
    [
        "10.0.0.0",
        "10.0.0.0/255.0.0.0",
        "fe80::%eth0/64",
    ],
)
def test_non_kubernetes_exclusion_cidr_forms_remain_incomplete(exclusion: str) -> None:
    observed = codes(network_policy({"ipBlock": {"cidr": "0.0.0.0/0", "except": [exclusion]}}))

    assert "internet_ingress" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


@pytest.mark.parametrize(
    "peer",
    [
        {"ipBlock": {"cidr": "0.0.0.0/0"}, "namespaceSelector": {}},
        {"ipBlock": {"cidr": "::/0"}, "unknownSelector": {}},
        {"unknownSelector": {}},
    ],
)
def test_invalid_ipblock_peer_shapes_remain_incomplete(peer: dict) -> None:
    observed = codes(network_policy(peer))

    assert "internet_ingress" not in observed
    assert "cloud_configuration_insufficient_evidence" in observed


def test_independent_supported_peer_survives_unsupported_and_malformed_peers() -> None:
    observed = codes(
        network_policy(
            {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}},
            {"ipBlock": {"cidr": "0.0.0.0/0", "except": {"cidr": "10.0.0.0/8"}}},
            {"ipBlock": {"cidr": "0.0.0.0/0"}, "podSelector": {}},
            {"ipBlock": {"cidr": "::/0", "except": []}},
        )
    )

    assert {"internet_ingress", "cloud_configuration_insufficient_evidence"} <= observed
