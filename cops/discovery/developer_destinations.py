"""Exact destination scope and offline routing for developer interface work."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class DestinationScopeError(ValueError):
    """A requested destination is outside the declared engagement scope."""


_POLICY_KEYS = frozenset({"hosts", "resolved_ips", "repositories", "images", "runtimes", "clusters"})
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _host(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("host must be a nonempty hostname or IP literal")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    host = value.lower()
    if len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("host must be an exact hostname or IP literal")
    return host


def _exact(value: str, dimension: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{dimension} must be a nonempty exact value")
    if any(char in value for char in ("*", "?", "[", "]")) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{dimension} must not contain a pattern or control character")
    return value


@dataclass(frozen=True)
class DeveloperDestinationPolicy:
    """Explicit exact-match allowlists for all developer workflow destinations."""

    hosts: frozenset[str] = frozenset()
    resolved_ips: frozenset[str] = frozenset()
    repositories: frozenset[str] = frozenset()
    images: frozenset[str] = frozenset()
    runtimes: frozenset[str] = frozenset()
    clusters: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeveloperDestinationPolicy:
        if not isinstance(data, dict) or set(data) - _POLICY_KEYS:
            raise ValueError("destination policy contains unknown keys or is not an object")
        values: dict[str, frozenset[str]] = {}
        for key in _POLICY_KEYS:
            entries = data.get(key, [])
            if not isinstance(entries, list) or any(not isinstance(entry, str) for entry in entries):
                raise ValueError(f"{key} must be a list of exact strings")
            if key == "hosts":
                values[key] = frozenset(_host(entry) for entry in entries)
            elif key == "resolved_ips":
                try:
                    values[key] = frozenset(str(ipaddress.ip_address(entry)) for entry in entries)
                except ValueError as err:
                    raise ValueError("resolved_ips must contain exact IP addresses") from err
            else:
                values[key] = frozenset(_exact(entry, key) for entry in entries)
        return cls(**values)

    @classmethod
    def load(cls, path: str | Path) -> DeveloperDestinationPolicy:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def authorize_host(self, host: str) -> None:
        if _host(host) not in self.hosts:
            raise DestinationScopeError("host is outside the destination allowlist")

    def authorize_ip(self, address: str) -> None:
        try:
            canonical = str(ipaddress.ip_address(address))
        except ValueError as err:
            raise DestinationScopeError("resolved address is not an IP literal") from err
        if canonical not in self.resolved_ips:
            raise DestinationScopeError("resolved address is outside the destination allowlist")

    def authorize(self, dimension: str, value: str) -> None:
        if dimension not in {"repositories", "images", "runtimes", "clusters"}:
            raise ValueError("unknown destination dimension")
        if _exact(value, dimension) not in getattr(self, dimension):
            raise DestinationScopeError(f"{dimension} destination is outside the allowlist")


def _named_entry(entries: Any, name: str, field: str) -> dict[str, Any]:
    if not isinstance(entries, list):
        raise DestinationScopeError(f"Kubernetes {field} list is missing")
    matches = [item for item in entries if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1 or not isinstance(matches[0].get(field), dict):
        raise DestinationScopeError(f"Kubernetes {field} entry is missing or ambiguous")
    return matches[0][field]


def prepare_developer_handoff(
    *,
    kind: str,
    target_host: str,
    policy: DeveloperDestinationPolicy,
    repository: str | None = None,
    image: str | None = None,
    runtime: str | None = None,
    cluster: str | None = None,
    kubeconfig: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check destinations and Kubernetes metadata without contacting a service."""
    routes = {
        "application": "cops-web-specialist",
        "host": "cops-pentest-specialist",
        "cluster": "cops-cloud-specialist",
    }
    if kind not in routes:
        raise ValueError("handoff kind must be application, host, or cluster")
    policy.authorize_host(target_host)
    supplied = {"repositories": repository, "images": image, "runtimes": runtime, "clusters": cluster}
    for dimension, value in supplied.items():
        if value is not None:
            policy.authorize(dimension, value)

    handoff: dict[str, Any] = {
        "specialist": routes[kind],
        "kind": kind,
        "target_host": _host(target_host),
        "repository": repository,
        "image": image,
        "runtime": runtime,
        "cluster": cluster,
        "connectivity_verified": False,
    }
    if kind != "cluster":
        if cluster is not None:
            raise DestinationScopeError("cluster destination requires a cluster handoff")
        if kubeconfig is not None:
            raise DestinationScopeError("Kubernetes context only applies to cluster handoff")
        return handoff

    if cluster is None or not isinstance(kubeconfig, dict):
        raise DestinationScopeError("cluster handoff requires an allowed cluster and Kubernetes context")
    context_name = kubeconfig.get("current-context")
    if not isinstance(context_name, str) or not context_name:
        raise DestinationScopeError("Kubernetes current-context is missing")
    try:
        _exact(context_name, "Kubernetes context")
    except ValueError as err:
        raise DestinationScopeError("Kubernetes current-context is invalid") from err
    context = _named_entry(kubeconfig.get("contexts"), context_name, "context")
    if context.get("cluster") != cluster:
        raise DestinationScopeError("Kubernetes context does not select the allowed cluster")
    cluster_data = _named_entry(kubeconfig.get("clusters"), cluster, "cluster")
    server = cluster_data.get("server")
    if not isinstance(server, str):
        raise DestinationScopeError("Kubernetes API server is missing")
    if any(ord(char) < 32 or ord(char) == 127 for char in server):
        raise DestinationScopeError("Kubernetes API server is invalid")
    try:
        parsed = urlsplit(server)
    except ValueError as err:
        raise DestinationScopeError("Kubernetes API server is invalid") from err
    try:
        valid_port = parsed.port is None or 1 <= parsed.port <= 65535
    except ValueError as err:
        raise DestinationScopeError("Kubernetes API server port is invalid") from err
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not valid_port
    ):
        raise DestinationScopeError("Kubernetes API server must be an HTTPS origin")
    policy.authorize_host(parsed.hostname)
    namespace = context.get("namespace", "default")
    if not isinstance(namespace, str) or not namespace:
        raise DestinationScopeError("Kubernetes namespace is invalid")
    try:
        _exact(namespace, "Kubernetes namespace")
    except ValueError as err:
        raise DestinationScopeError("Kubernetes namespace is invalid") from err
    handoff.update(
        {
            "kubernetes_context": context_name,
            "kubernetes_namespace": namespace,
            "kubernetes_api_host": _host(parsed.hostname),
        }
    )
    return handoff
