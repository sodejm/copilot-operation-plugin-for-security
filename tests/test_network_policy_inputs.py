from __future__ import annotations

import copy
import json

import pytest

from cops.assessments import assess

AS_OF = "2026-10-15T12:00:00Z"


def report(kind, value):
    before = copy.deepcopy(value)
    result = assess("network_segmentation", [{"artifact_id": "network", "kind": kind, "content": value}], as_of=AS_OF)
    assert value == before
    return set(result["finding_codes"].values())


def firewall():
    return {
        "schema_version": "cops.firewall-policy/v1",
        "complete": True,
        "default_action": "deny",
        "rules": [
            {"from_cidr": "10.0.0.0/24", "to_cidr": "10.1.0.0/24", "protocol": "TCP", "ports": [443], "action": "allow"}
        ],
        "expected_reachability": [
            {"from_ip": "10.0.0.2", "to_ip": "10.1.0.2", "protocol": "TCP", "port": 443, "allowed": True},
            {"from_ip": "10.2.0.2", "to_ip": "10.1.0.2", "protocol": "TCP", "port": 443, "allowed": False},
        ],
    }


def kubernetes():
    return {
        "schema_version": "cops.kubernetes-network-policy/v1",
        "complete": True,
        "items": [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "demo"}},
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"namespace": "demo", "name": "client", "labels": {"role": "client"}},
                "spec": {"containers": []},
                "status": {"podIP": "10.0.0.2"},
            },
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"namespace": "demo", "name": "server", "labels": {"role": "server"}},
                "spec": {"containers": [{"ports": [{"name": "https", "containerPort": 443}]}]},
                "status": {"podIP": "10.0.0.3"},
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"namespace": "demo", "name": "server"},
                "spec": {
                    "podSelector": {"matchLabels": {"role": "server"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {"from": [{"podSelector": {"matchLabels": {"role": "client"}}}], "ports": [{"port": "https"}]}
                    ],
                },
            },
        ],
        "expected_reachability": [
            {"from": "demo/client", "to": "demo/server", "protocol": "TCP", "port": 443, "allowed": True},
            {"from": "demo/client", "to": "demo/server", "protocol": "TCP", "port": 80, "allowed": False},
        ],
    }


def test_firewall_corrected_vulnerable_first_match_and_ipv6():
    value = firewall()
    assert report("firewall_policy", value) == set()
    broad = {"from_cidr": "0.0.0.0/0", "to_cidr": "0.0.0.0/0", "protocol": "ANY", "ports": [], "action": "allow"}
    value["rules"].append(broad)
    assert report("firewall_policy", value) == {"segmentation_mismatch"}
    value["rules"].insert(1, {**broad, "action": "deny"})
    assert report("firewall_policy", value) == set()
    value = firewall()
    value["rules"][0].update(from_cidr="2001:db8:1::/64", to_cidr="2001:db8:2::/64")
    value["expected_reachability"] = [
        {"from_ip": "2001:db8:1::2", "to_ip": "2001:db8:2::3", "protocol": "TCP", "port": 443, "allowed": True}
    ]
    assert report("firewall_policy", value) == set()


def test_kubernetes_additive_default_and_both_directions():
    value = kubernetes()
    assert report("kubernetes_network_policy", value) == set()
    value["items"][-1]["spec"]["ingress"].append({})
    assert report("kubernetes_network_policy", value) == {"segmentation_mismatch"}
    value = kubernetes()
    value["items"].append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"namespace": "demo", "name": "client"},
            "spec": {"podSelector": {"matchLabels": {"role": "client"}}, "policyTypes": ["Egress"], "egress": []},
        }
    )
    assert report("kubernetes_network_policy", value) == {"segmentation_mismatch"}
    value["items"][-1]["spec"]["egress"] = [
        {
            "to": [{"ipBlock": {"cidr": "10.0.0.0/24", "except": ["10.0.0.4/32"]}}],
            "ports": [{"port": 440, "endPort": 450}],
        }
    ]
    assert report("kubernetes_network_policy", value) == set()


def test_namespace_and_pod_selector_are_intersection():
    value = kubernetes()
    policy = value["items"][-1]["spec"]
    peer = policy["ingress"][0]["from"][0]
    peer["namespaceSelector"] = {"matchLabels": {"kubernetes.io/metadata.name": "elsewhere"}}
    assert report("kubernetes_network_policy", value) == {"segmentation_mismatch"}
    peer["namespaceSelector"] = {
        "matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": ["demo"]}]
    }
    assert report("kubernetes_network_policy", value) == set()
    # An omitted policyTypes still isolates ingress and nonempty egress.
    policy.pop("policyTypes")
    assert report("kubernetes_network_policy", value) == set()


@pytest.mark.parametrize("selector_kind", ["podSelector", "namespaceSelector"])
@pytest.mark.parametrize("label_value", [None, "excluded", "other"])
@pytest.mark.parametrize("operator,require_exists", [("NotIn", False), ("NotIn", True), ("In", False)])
def test_set_selectors_match_kubernetes_missing_label_semantics(selector_kind, label_value, operator, require_exists):
    value = kubernetes()
    resource = value["items"][1 if selector_kind == "podSelector" else 0]
    if label_value is not None:
        resource["metadata"].setdefault("labels", {})["environment"] = label_value
    expressions = [{"key": "environment", "operator": operator, "values": ["excluded"]}]
    if require_exists:
        expressions.append({"key": "environment", "operator": "Exists"})
    peer = value["items"][-1]["spec"]["ingress"][0]["from"][0]
    peer[selector_kind] = {"matchExpressions": expressions}
    allowed = label_value != "excluded" if operator == "NotIn" else label_value == "excluded"
    if require_exists and label_value is None:
        allowed = False
    value["expected_reachability"][0]["allowed"] = allowed
    assert report("kubernetes_network_policy", value) == set()
    value["expected_reachability"][0]["allowed"] = not allowed
    assert report("kubernetes_network_policy", value) == {"segmentation_mismatch"}


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(complete=False),
        lambda v: v["items"].pop(0),
        lambda v: v["items"][1]["spec"].update(hostNetwork=True),
        lambda v: v["items"][-1]["spec"].update(unknownFeature=True),
        lambda v: v["items"][-1]["spec"]["ingress"][0]["ports"][0].update(endPort=450),
        lambda v: v["items"].append(copy.deepcopy(v["items"][1])),
        lambda v: v["expected_reachability"].extend([v["expected_reachability"][0]] * 256),
    ],
)
def test_kubernetes_incomplete_or_unsupported_never_passes(mutation):
    value = kubernetes()
    mutation(value)
    assert "network_policy_evidence_insufficient_evidence" in report("kubernetes_network_policy", value)


def test_flow_requires_fresh_observation_including_denials():
    value = {
        "schema_version": "cops.flow-evidence/v1",
        "complete": True,
        "expected_reachability": firewall()["expected_reachability"],
        "observations": [],
    }
    assert report("flow_evidence", value) == {"network_policy_evidence_insufficient_evidence"}
    value["observations"] = [
        {**item, "observed_at": "2026-10-15T11:59:00Z", "evidence_ref": "evidence:probe-1"}
        for item in value["expected_reachability"]
    ]
    assert report("flow_evidence", value) == set()
    value["observations"][1]["allowed"] = True
    assert report("flow_evidence", value) == {"segmentation_mismatch"}
    value["observations"][0]["observed_at"] = "2026-10-14T12:00:00Z"
    assert "network_policy_evidence_insufficient_evidence" in report("flow_evidence", value)


def test_dns_freshness_and_exact_address_set():
    value = {
        "schema_version": "cops.dns-evidence/v1",
        "complete": True,
        "records": [
            {"name": "service.example", "addresses": ["10.0.0.2"], "ttl": 300, "observed_at": "2026-10-15T11:59:00Z"}
        ],
        "expected_records": [{"name": "service.example", "addresses": ["10.0.0.2"]}],
    }
    assert report("dns_evidence", value) == set()
    value["records"][0]["addresses"] = ["10.0.0.3"]
    assert report("dns_evidence", value) == {"dns_mismatch"}
    value["records"][0]["ttl"] = 30
    assert report("dns_evidence", value) == {"network_policy_evidence_insufficient_evidence"}


def test_malformed_firewall_and_legacy_rules_are_unknown_and_content_free():
    value = firewall()
    value["rules"][0]["from_cidr"] = "secret-untrusted-marker"
    result = assess(
        "network_segmentation", [{"artifact_id": "n", "kind": "firewall_policy", "content": value}], as_of=AS_OF
    )
    assert set(result["finding_codes"].values()) == {"network_policy_evidence_insufficient_evidence"}
    assert "secret-untrusted-marker" not in json.dumps(result)
    assert report(
        "segmentation_model",
        {
            "rules": [{"from": "a", "to": "b", "action": "invalid"}],
            "expected_reachability": [{"from": "a", "to": "b", "allowed": False}],
        },
    ) == {"segmentation_model_insufficient_evidence"}


@pytest.mark.parametrize("action", [{}, [], None, True])
def test_legacy_malformed_action_remains_unknown(action):
    value = {
        "rules": [{"from": "a", "to": "b", "action": action}],
        "expected_reachability": [{"from": "a", "to": "b", "allowed": False}],
    }
    assert report("segmentation_model", value) == {"segmentation_model_insufficient_evidence"}


def test_conflicting_flow_observations_are_unknown():
    path = firewall()["expected_reachability"][0]
    observation = {**path, "observed_at": AS_OF, "evidence_ref": "evidence:probe-1"}
    value = {
        "schema_version": "cops.flow-evidence/v1",
        "complete": True,
        "expected_reachability": [path],
        "observations": [observation, {**observation, "allowed": False}],
    }
    assert report("flow_evidence", value) == {"network_policy_evidence_insufficient_evidence"}
