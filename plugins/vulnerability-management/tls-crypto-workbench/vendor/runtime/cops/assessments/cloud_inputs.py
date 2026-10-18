"""Typed observations from bounded cloud exports, never a policy solver.

Only registered shapes are considered analyzed. Unknown resources, plan values,
versions, and malformed subdocuments retain an explicit coverage gap.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any


@dataclass
class CloudInput:
    codes: set[str] = field(default_factory=set)
    incomplete: bool = False


def _strings(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _world(value: Any) -> bool:
    return isinstance(value, str) and value in {"0.0.0.0/0", "::/0", "*", "Internet"}


def _kubernetes_cidr(value: Any, result: CloudInput) -> IPv4Network | IPv6Network | None:
    if not isinstance(value, str) or value.count("/") != 1:
        result.incomplete = True
        return None
    address, prefix = value.rsplit("/", 1)
    if "%" in address or not prefix.isascii() or not prefix.isdecimal():
        result.incomplete = True
        return None
    try:
        return ip_network(value, strict=True)
    except ValueError:
        result.incomplete = True
        return None


def _network_policy_world_ip_block(value: Any, result: CloudInput) -> bool:
    if not isinstance(value, dict) or set(value) - {"cidr", "except"}:
        result.incomplete = True
        return False
    network = _kubernetes_cidr(value.get("cidr"), result)
    if network is None:
        return False

    exclusions = value.get("except", [])
    if not isinstance(exclusions, list):
        result.incomplete = True
        return False
    for exclusion in exclusions:
        excluded_network = _kubernetes_cidr(exclusion, result)
        if excluded_network is None:
            return False
        if excluded_network.version != network.version or not excluded_network.subnet_of(network):
            result.incomplete = True
            return False

    # Computing the address space left by exclusions requires effective-policy
    # evaluation. Retain that gap instead of treating the enclosing CIDR as open.
    if exclusions:
        result.incomplete = True
        return False
    return network.prefixlen == 0


def _network_policy_peer_world(peer: Any, result: CloudInput) -> bool:
    if not isinstance(peer, dict):
        result.incomplete = True
        return False
    keys = set(peer)
    selector_keys = {"namespaceSelector", "podSelector"}
    if keys - selector_keys - {"ipBlock"}:
        result.incomplete = True
        return False
    if not keys:
        return True
    if "ipBlock" in keys:
        if keys != {"ipBlock"}:
            result.incomplete = True
            return False
        return _network_policy_world_ip_block(peer["ipBlock"], result)
    if any(not isinstance(peer[key], dict) for key in keys):
        result.incomplete = True
    return False


def _iam(value: Any, result: CloudInput) -> None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            result.incomplete = True
            return
    if not isinstance(value, dict) or "Statement" not in value:
        result.incomplete = True
        return
    statements = value["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        result.incomplete = True
        return
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            result.incomplete = True
            continue
        if statement["Effect"] == "Deny":
            continue
        # Conditions need request context and policy evaluation, neither of
        # which this offline shape parser has. Even an empty/malformed condition
        # cannot establish effective public access or wildcard permissions.
        if "Condition" in statement:
            result.incomplete = True
            continue
        actions, resources = _strings(statement.get("Action")), _strings(statement.get("Resource"))
        if actions is None or resources is None or "NotAction" in statement or "NotResource" in statement:
            result.incomplete = True
            continue
        if "*" in resources or any(action == "*" or action.endswith(":*") for action in actions):
            result.codes.add("iam_wildcard")
        # Public resource policies also require an Allow statement.
        principal = statement.get("Principal")
        public = principal == "*" or isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"])
        if public and any(action.lower().startswith("s3:") for action in actions):
            result.codes.add("public_storage")


def _aws_acl(value: dict, result: CloudInput) -> None:
    grants = value.get("Grants")
    if not isinstance(grants, list):
        result.incomplete = True
        return
    for grant in grants:
        if not isinstance(grant, dict) or not isinstance(grant.get("Grantee"), dict):
            result.incomplete = True
            continue
        grantee = grant["Grantee"]
        if grantee.get("Type") == "Group":
            if grantee.get("URI") in {"http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}:
                result.codes.add("public_storage")
            else:
                result.incomplete = True
        elif grantee.get("Type") != "CanonicalUser" or not isinstance(grantee.get("ID"), str):
            result.incomplete = True


def _aws_permissions(permissions: Any, result: CloudInput) -> None:
    if not isinstance(permissions, list):
        result.incomplete = True
        return
    for rule in permissions:
        if not isinstance(rule, dict):
            result.incomplete = True
            continue
        for key, cidr_key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
            ranges = rule.get(key, [])
            if not isinstance(ranges, list):
                result.incomplete = True
                continue
            for entry in ranges:
                if not isinstance(entry, dict) or not isinstance(entry.get(cidr_key), str):
                    result.incomplete = True
                elif _world(entry[cidr_key]):
                    result.codes.add("internet_ingress")


def _aws(value: Any, result: CloudInput) -> None:
    if not isinstance(value, dict):
        result.incomplete = True
    elif "Statement" in value:
        _iam(value, result)
    elif "Grants" in value:
        _aws_acl(value, result)
    elif "SecurityGroups" in value:
        groups = value["SecurityGroups"]
        if not isinstance(groups, list):
            result.incomplete = True
        else:
            for group in groups:
                if isinstance(group, dict):
                    _aws_permissions(group.get("IpPermissions"), result)
                else:
                    result.incomplete = True
    elif "Policy" in value:
        _iam(value["Policy"], result)
    else:
        result.incomplete = True


def _kubernetes(value: Any, result: CloudInput) -> None:
    if isinstance(value, list):
        if not value:
            result.incomplete = True
        for item in value:
            _kubernetes(item, result)
        return
    if not isinstance(value, dict):
        result.incomplete = True
        return
    kind = value.get("kind")
    if kind == "List":
        _kubernetes(value.get("items"), result)
    elif kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
        spec = value.get("spec")
        if kind == "CronJob" and isinstance(spec, dict):
            spec = spec.get("jobTemplate", {}).get("spec") if isinstance(spec.get("jobTemplate"), dict) else None
        if kind != "Pod" and isinstance(spec, dict):
            spec = spec.get("template", {}).get("spec") if isinstance(spec.get("template"), dict) else None
        if not isinstance(spec, dict) or not isinstance(spec.get("containers"), list) or not spec["containers"]:
            result.incomplete = True
            return
        contexts = [spec.get("securityContext", {})]
        if any(spec.get(flag) is True for flag in ("hostNetwork", "hostPID", "hostIPC")):
            result.codes.add("workload_privilege")
        for key in ("containers", "initContainers", "ephemeralContainers"):
            containers = spec.get(key, [])
            if not isinstance(containers, list):
                result.incomplete = True
                continue
            for container in containers:
                if not isinstance(container, dict):
                    result.incomplete = True
                else:
                    contexts.append(container.get("securityContext", {}))
        for context in contexts:
            if not isinstance(context, dict):
                result.incomplete = True
            elif context.get("privileged") is True or context.get("runAsNonRoot") is False or type(context.get("runAsUser")) is int and context["runAsUser"] == 0:
                result.codes.add("workload_privilege")
    elif kind in {"Role", "ClusterRole"}:
        rules = value.get("rules")
        if not isinstance(rules, list):
            result.incomplete = True
            return
        for rule in rules:
            if not isinstance(rule, dict) or _strings(rule.get("verbs")) is None:
                result.incomplete = True
                continue
            resources = _strings(rule.get("resources", rule.get("nonResourceURLs")))
            if resources is None:
                result.incomplete = True
            elif "*" in rule["verbs"] or "*" in resources:
                result.codes.add("iam_wildcard")
    elif kind == "NetworkPolicy":
        spec = value.get("spec")
        if not isinstance(spec, dict) or not isinstance(spec.get("podSelector"), dict):
            result.incomplete = True
            return
        ingress = spec.get("ingress", [])
        if not isinstance(ingress, list):
            result.incomplete = True
            return
        for rule in ingress:
            if not isinstance(rule, dict):
                result.incomplete = True
                continue
            peers = rule.get("from", [])
            if not isinstance(peers, list):
                result.incomplete = True
            elif not peers:
                result.codes.add("internet_ingress")
            else:
                for peer in peers:
                    if _network_policy_peer_world(peer, result):
                        result.codes.add("internet_ingress")
    else:
        result.incomplete = True


def _azure(value: Any, result: CloudInput) -> None:
    if not isinstance(value, dict):
        result.incomplete = True
        return
    if "value" in value:
        if not isinstance(value["value"], list):
            result.incomplete = True
        else:
            for item in value["value"]:
                _azure(item, result)
        return
    properties = value.get("properties")
    if not isinstance(properties, dict):
        result.incomplete = True
    elif str(value.get("type", "")).lower() == "microsoft.network/networksecuritygroups":
        rules = properties.get("securityRules")
        if not isinstance(rules, list):
            result.incomplete = True
            return
        for rule in rules:
            prop = rule.get("properties") if isinstance(rule, dict) else None
            if not isinstance(prop, dict) or prop.get("direction") not in {"Inbound", "Outbound"} or prop.get("access") not in {"Allow", "Deny"}:
                result.incomplete = True
                continue
            if prop["direction"] == "Inbound" and prop["access"] == "Allow":
                sources = _strings(prop.get("sourceAddressPrefixes", prop.get("sourceAddressPrefix")))
                if sources is None:
                    result.incomplete = True
                elif any(_world(source) for source in sources):
                    result.codes.add("internet_ingress")
    elif str(value.get("type", "")).lower() == "microsoft.storage/storageaccounts":
        if properties.get("allowBlobPublicAccess") is True:
            result.codes.add("public_storage")
        elif properties.get("allowBlobPublicAccess") is not False:
            result.incomplete = True
    else:
        result.incomplete = True


def _gcp(value: Any, result: CloudInput) -> None:
    if not isinstance(value, dict):
        result.incomplete = True
        return
    if value.get("kind") == "compute#firewall":
        if value.get("disabled") is True or value.get("direction", "INGRESS") == "EGRESS":
            return
        if value.get("direction", "INGRESS") != "INGRESS" or not isinstance(value.get("allowed"), list):
            result.incomplete = True
            return
        sources = _strings(value.get("sourceRanges"))
        if sources is None:
            result.incomplete = True
        elif value["allowed"] and any(_world(source) for source in sources):
            result.codes.add("internet_ingress")
    elif "bindings" in value:
        bindings = value["bindings"]
        if not isinstance(bindings, list):
            result.incomplete = True
            return
        for binding in bindings:
            if not isinstance(binding, dict) or not isinstance(binding.get("role"), str) or _strings(binding.get("members")) is None:
                result.incomplete = True
            elif binding["role"] in {"roles/owner", "roles/editor"}:
                result.codes.add("iam_wildcard")
            elif binding["role"].startswith("roles/storage.") and {"allUsers", "allAuthenticatedUsers"}.intersection(binding["members"]):
                result.codes.add("public_storage")
    else:
        result.incomplete = True


def _terraform_resource(kind: str, values: Any, result: CloudInput) -> None:
    if not isinstance(values, dict):
        result.incomplete = True
    elif kind in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy", "aws_s3_bucket_policy"}:
        _iam(values.get("policy"), result)
    elif kind in {"aws_s3_bucket_acl", "aws_s3_bucket"}:
        acl = values.get("acl")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            result.codes.add("public_storage")
        elif acl != "private":
            result.incomplete = True
    elif kind in {"aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}:
        if kind == "aws_security_group_rule" and values.get("type") == "egress":
            return
        rules = values.get("ingress", []) if kind == "aws_security_group" else [values]
        if not isinstance(rules, list):
            result.incomplete = True
            return
        for rule in rules:
            if not isinstance(rule, dict):
                result.incomplete = True
                continue
            for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
                sources = _strings(rule.get(key, []))
                if sources is None:
                    result.incomplete = True
                elif any(_world(source) for source in sources):
                    result.codes.add("internet_ingress")
    elif kind in {"kubernetes_manifest", "kubernetes_manifest_v1"}:
        _kubernetes(values.get("manifest"), result)
    else:
        result.incomplete = True


def _terraform(value: Any, result: CloudInput) -> None:
    if not isinstance(value, dict) or not str(value.get("format_version", "")).startswith("1."):
        result.incomplete = True
        return
    if "resource_changes" in value:
        changes = value["resource_changes"]
        if not isinstance(changes, list):
            result.incomplete = True
            return
        for item in changes:
            change = item.get("change") if isinstance(item, dict) else None
            if not isinstance(change, dict) or not isinstance(change.get("actions"), list):
                result.incomplete = True
                continue
            if item.get("mode") == "data" or change["actions"] == ["delete"]:
                continue
            if not change["actions"] or set(change["actions"]) - {"create", "read", "update", "delete", "no-op"}:
                result.incomplete = True
                continue
            if any(bool(child) for child in _unknown_leaves(change.get("after_unknown", {}))):
                result.incomplete = True
            _terraform_resource(item.get("type", ""), change.get("after"), result)
    elif isinstance(value.get("planned_values"), dict):
        pending = [value["planned_values"].get("root_module")]
        while pending:
            module = pending.pop()
            if not isinstance(module, dict) or not isinstance(module.get("resources", []), list) or not isinstance(module.get("child_modules", []), list):
                result.incomplete = True
                continue
            for item in module.get("resources", []):
                if not isinstance(item, dict):
                    result.incomplete = True
                elif item.get("mode") != "data":
                    _terraform_resource(item.get("type", ""), item.get("values"), result)
            pending.extend(module.get("child_modules", []))
    else:
        result.incomplete = True


def _unknown_leaves(value: Any) -> list[Any]:
    pending = [value]
    leaves = []
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        else:
            leaves.append(item)
    return leaves


def cloud_input(kind: str, value: Any) -> CloudInput:
    result = CloudInput()
    parsers = {"terraform_plan": _terraform, "kubernetes_rendered": _kubernetes, "helm_rendered_json": _kubernetes, "aws_export": _aws, "azure_export": _azure, "gcp_export": _gcp}
    try:
        parsers[kind](value, result)
    except (TypeError, ValueError, AttributeError):
        # Nested JSON with the wrong field types remains evidence of a gap.
        result.incomplete = True
    return result
