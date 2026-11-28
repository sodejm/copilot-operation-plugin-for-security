"""Bounded policy predictions and supplied observations; no network operations.

Kubernetes support is deliberately limited to Pod-to-Pod TCP/UDP paths in a
complete inventory. Unknown semantics invalidate the prediction, never grant it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any


@dataclass
class NetworkInput:
    codes: set[str] = field(default_factory=set)
    incomplete: bool = False


class _Gap(ValueError):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise _Gap()


def _object(value: Any, allowed: set[str] | None = None) -> dict:
    _require(isinstance(value, dict))
    if allowed is not None:
        _require(not set(value) - allowed)
    return value


def _list(value: Any, bound: int = 256, *, nonempty: bool = False) -> list:
    _require(isinstance(value, list) and len(value) <= bound and (not nonempty or bool(value)))
    return value


def _text(value: Any) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 253)
    return value


def _port(value: Any) -> int:
    _require(type(value) is int and 1 <= value <= 65535)
    return value


def _protocol(value: Any, *, any_protocol: bool = False) -> str:
    _require(isinstance(value, str) and value in ({"TCP", "UDP", "ANY"} if any_protocol else {"TCP", "UDP"}))
    return value


def _address(value: Any):
    text = _text(value)
    _require("%" not in text)
    return ip_address(text)


def _network(value: Any):
    text = _text(value)
    _require("%" not in text and "/" in text)
    return ip_network(text, strict=True)


def _time(value: Any) -> datetime:
    text = _text(value)
    _require(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text)))
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _path(value: Any, *, pods: bool = False) -> tuple:
    obj = _object(value)
    _require(type(obj.get("allowed")) is bool)
    left, right = (
        (_text(obj.get("from")), _text(obj.get("to")))
        if pods
        else (_address(obj.get("from_ip")), _address(obj.get("to_ip")))
    )
    if not pods:
        _require(left.version == right.version)
    return left, right, _protocol(obj.get("protocol")), _port(obj.get("port"))


def _firewall(value: dict, result: NetworkInput) -> None:
    default = value.get("default_action")
    _require(default in ("allow", "deny"))
    rules = []
    for item in _list(value.get("rules"), 1024):
        item = _object(item, {"from_cidr", "to_cidr", "protocol", "ports", "action"})
        src, dst = _network(item.get("from_cidr")), _network(item.get("to_cidr"))
        _require(src.version == dst.version and item.get("action") in ("allow", "deny"))
        rules.append(
            (
                src,
                dst,
                _protocol(item.get("protocol"), any_protocol=True),
                {_port(p) for p in _list(item.get("ports"), 128)},
                item["action"] == "allow",
            )
        )
    for item in _list(value.get("expected_reachability"), nonempty=True):
        src, dst, protocol, port = _path(item)
        actual = default == "allow"
        for source, target, proto, ports, allow in rules:
            if src in source and dst in target and proto in ("ANY", protocol) and (not ports or port in ports):
                actual = allow
                break
        if actual != item["allowed"]:
            result.codes.add("segmentation_mismatch")


def _labels(value: Any) -> dict:
    value = _object(value)
    _require(len(value) <= 128)
    for key, label in value.items():
        _label_key(key)
        _label_value(label)
    return value


def _dns_name(value: Any) -> str:
    value = _text(value).removesuffix(".").lower()
    _require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")))
    return value


def _label_value(value: Any) -> str:
    _require(
        isinstance(value, str)
        and (value == "" or bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?", value)))
    )
    return value


def _label_key(value: Any) -> str:
    _require(isinstance(value, str) and value.count("/") <= 1)
    if "/" in value:
        prefix, name = value.split("/")
        _require(_dns_name(prefix) == prefix)
    else:
        name = value
    _require(bool(name))
    _label_value(name)
    return value


def _selector(value: Any):
    value = _object(value, {"matchLabels", "matchExpressions"})
    labels = _labels(value.get("matchLabels", {}))
    expressions = []
    for item in _list(value.get("matchExpressions", []), 128):
        item = _object(item, {"key", "operator", "values"})
        key, operator = _label_key(item.get("key")), item.get("operator")
        _require(operator in ("In", "NotIn", "Exists", "DoesNotExist"))
        values = {_label_value(v) for v in _list(item.get("values", []), 128)}
        _require(bool(values) == (operator in ("In", "NotIn")))
        expressions.append((key, operator, values))

    def matches(candidate):
        if any(candidate.get(k) != v for k, v in labels.items()):
            return False
        for key, operator, values in expressions:
            if operator == "In" and candidate.get(key) not in values:
                return False
            if operator == "NotIn" and candidate.get(key) in values:
                return False
            if operator == "Exists" and key not in candidate:
                return False
            if operator == "DoesNotExist" and key in candidate:
                return False
        return True

    return matches


def _peer(value: Any):
    value = _object(value, {"podSelector", "namespaceSelector", "ipBlock"})
    if "ipBlock" in value:
        _require(len(value) == 1)
        block = _object(value["ipBlock"], {"cidr", "except"})
        network = _network(block.get("cidr"))
        exclusions = [_network(v) for v in _list(block.get("except", []), 128)]
        _require(all(v.version == network.version and v.subnet_of(network) for v in exclusions))

        def ip_matches(pod, _namespace, _policy_namespace):
            _require(pod["ip"] is not None)
            return pod["ip"] in network and not any(pod["ip"] in v for v in exclusions)

        return ip_matches
    pod_match = _selector(value.get("podSelector", {}))
    ns_match = _selector(value["namespaceSelector"]) if "namespaceSelector" in value else None
    return lambda pod, namespace, policy_ns: (
        pod_match(pod["labels"])
        and (ns_match(namespace) if ns_match is not None else (not value or pod["namespace"] == policy_ns))
    )


def _policy_rule(value: Any, direction: str):
    peer_key = "from" if direction == "Ingress" else "to"
    value = _object(value, {peer_key, "ports"})
    peers = [_peer(v) for v in _list(value.get(peer_key, []), 128)]
    ports = []
    for item in _list(value.get("ports", []), 128):
        item = _object(item, {"protocol", "port", "endPort"})
        proto, port = _protocol(item.get("protocol", "TCP")), item.get("port")
        if isinstance(port, str):
            _require(bool(re.fullmatch(r"[a-z][a-z0-9-]{0,14}", port)) and "endPort" not in item)
            ports.append((proto, port, port))
        elif port is None:
            _require("endPort" not in item)
            ports.append((proto, 1, 65535))
        else:
            start, end = _port(port), _port(item.get("endPort", port))
            _require(start <= end)
            ports.append((proto, start, end))
    return peers, ports


def _kubernetes(value: dict, result: NetworkInput) -> None:
    namespaces, pods, policies = {}, {}, []
    identities = set()
    for item in _list(value.get("items"), 384, nonempty=True):
        item = _object(item)
        metadata = _object(item.get("metadata"))
        kind, name = item.get("kind"), _text(metadata.get("name"))
        _require(kind in ("Namespace", "Pod", "NetworkPolicy"))
        _require(item.get("apiVersion") == ("networking.k8s.io/v1" if kind == "NetworkPolicy" else "v1"))
        namespace = "" if kind == "Namespace" else _text(metadata.get("namespace"))
        identity = (kind, namespace, name)
        _require(identity not in identities)
        identities.add(identity)
        if kind == "Namespace":
            labels = dict(_labels(metadata.get("labels", {})))
            _require(labels.get("kubernetes.io/metadata.name", name) == name)
            labels["kubernetes.io/metadata.name"] = name
            namespaces[name] = labels
        elif kind == "Pod":
            spec = _object(item.get("spec"))
            _require(spec.get("hostNetwork", False) is False)
            named = {}
            for container in _list(spec.get("containers"), 64):
                for port in _list(_object(container).get("ports", []), 128):
                    port = _object(port)
                    number, proto = _port(port.get("containerPort")), _protocol(port.get("protocol", "TCP"))
                    _require(not port.get("hostPort"))
                    if "name" in port:
                        key = (_text(port["name"]), proto)
                        _require(key not in named)
                        named[key] = number
            status = _object(item.get("status", {}))
            pods[f"{namespace}/{name}"] = {
                "namespace": namespace,
                "labels": _labels(metadata.get("labels", {})),
                "ip": _address(status["podIP"]) if "podIP" in status else None,
                "ports": named,
            }
        else:
            spec = _object(item.get("spec"), {"podSelector", "policyTypes", "ingress", "egress"})
            selector = _selector(spec.get("podSelector"))
            types = _list(
                spec.get("policyTypes", ["Ingress"] + (["Egress"] if spec.get("egress") else [])), 2, nonempty=True
            )
            _require(all(t in ("Ingress", "Egress") for t in types) and len(set(types)) == len(types))
            rules = {
                direction: [_policy_rule(v, direction) for v in _list(spec.get(direction.lower(), []), 128)]
                for direction in ("Ingress", "Egress")
            }
            _require(all(not rules[d] or d in types for d in rules))
            policies.append((namespace, selector, types, rules))
    _require(
        bool(pods)
        and all(p["namespace"] in namespaces for p in pods.values())
        and all(p[0] in namespaces for p in policies)
    )
    _require(len(pods) <= 128 and len(policies) <= 128 and len(namespaces) <= 128)

    def permits(direction, source, target, protocol, port):
        selected, allowed = False, False
        subject, peer = (target, source) if direction == "Ingress" else (source, target)
        for namespace, selector, types, rules in policies:
            if namespace != subject["namespace"] or direction not in types or not selector(subject["labels"]):
                continue
            selected = True
            for peers, ports in rules[direction]:
                peer_ok = not peers or any(p(peer, namespaces[peer["namespace"]], namespace) for p in peers)
                port_ok = not ports or any(
                    proto == protocol
                    and (
                        target["ports"].get((start, proto)) == port if isinstance(start, str) else start <= port <= end
                    )
                    for proto, start, end in ports
                )
                allowed |= peer_ok and port_ok
        return not selected or allowed

    paths = _list(value.get("expected_reachability"), nonempty=True)
    comparisons = sum(
        max(1, len(peers)) + max(1, len(ports))
        for _, _, _, rules in policies
        for entries in rules.values()
        for peers, ports in entries
    )
    _require(len(paths) * max(1, comparisons) <= 200_000)
    for item in paths:
        source, target, protocol, port = _path(item, pods=True)
        _require(source in pods and target in pods and source != target)
        actual = all(permits(d, pods[source], pods[target], protocol, port) for d in ("Ingress", "Egress"))
        if actual != item["allowed"]:
            result.codes.add("segmentation_mismatch")


def _flows(value: dict, result: NetworkInput, as_of: datetime) -> None:
    observations = {}
    for item in _list(value.get("observations"), 1024):
        key = _path(item)
        _require(bool(re.fullmatch(r"evidence:[A-Za-z0-9_.:-]{1,128}", _text(item.get("evidence_ref")))))
        age = (as_of - _time(item.get("observed_at"))).total_seconds()
        _require(0 <= age <= 900)
        observations.setdefault(key, set()).add(item["allowed"])
    for item in _list(value.get("expected_reachability"), nonempty=True):
        observed = observations.get(_path(item), set())
        if len(observed) != 1:
            result.incomplete = True
        elif observed != {item["allowed"]}:
            result.codes.add("segmentation_mismatch")


def _dns(value: dict, result: NetworkInput, as_of: datetime) -> None:
    def record(item):
        item = _object(item)
        name = _dns_name(item.get("name"))
        return name, {_address(v) for v in _list(item.get("addresses"), 128, nonempty=True)}

    records = {}
    for item in _list(value.get("records"), 1024):
        name, addresses = record(item)
        ttl = item.get("ttl")
        _require(name not in records and type(ttl) is int and 0 <= ttl <= 86400)
        age = (as_of - _time(item.get("observed_at"))).total_seconds()
        _require(0 <= age < ttl)
        records[name] = addresses
    for item in _list(value.get("expected_records"), nonempty=True):
        name, addresses = record(item)
        if name not in records:
            result.incomplete = True
        elif records[name] != addresses:
            result.codes.add("dns_mismatch")


KINDS = {
    "firewall_policy": "cops.firewall-policy/v1",
    "kubernetes_network_policy": "cops.kubernetes-network-policy/v1",
    "flow_evidence": "cops.flow-evidence/v1",
    "dns_evidence": "cops.dns-evidence/v1",
}


def inspect_network(kind: str, value: Any, as_of: datetime) -> NetworkInput:
    result = NetworkInput()
    try:
        value = _object(value)
        _require(value.get("schema_version") == KINDS[kind] and value.get("complete") is True)
        if kind == "firewall_policy":
            _firewall(value, result)
        elif kind == "kubernetes_network_policy":
            _kubernetes(value, result)
        elif kind == "flow_evidence":
            _flows(value, result, as_of)
        elif kind == "dns_evidence":
            _dns(value, result, as_of)
    except (ValueError, TypeError):
        # Never publish predictions computed from a partially interpreted policy.
        result.codes.clear()
        result.incomplete = True
    return result
