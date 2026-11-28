"""Tenant-qualified observations, provenance, bounded work, and scope ancestry."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from .._runtime.cops.evidence.canonical import canonical, timestamp


class AzureError(ValueError):
    """Stable error codes contain no paths or source payload values."""


class Budget(AzureError):
    pass


DEFAULTS = {"file_bytes": 4194304, "total_bytes": 67108864, "files": 64,
            "line_bytes": 1048576, "records": 50000, "json_depth": 32,
            "nodes": 50000, "edges": 200000, "hops": 12,
            "paths": 1000, "expansions": 200000, "output_bytes": 33554432}
CEILINGS = {"file_bytes": 16777216, "total_bytes": 268435456, "files": 256,
            "line_bytes": 4194304, "records": 200000, "json_depth": 64,
            "nodes": 200000, "edges": 1000000, "hops": 32,
            "paths": 5000, "expansions": 2000000, "output_bytes": 134217728}


def stable(value):
    return hashlib.sha256(canonical(value, max_bytes=CEILINGS["output_bytes"])).hexdigest()


def arm(value):
    if not isinstance(value, str) or len(value) > 2048 or not value.startswith("/") or any(ord(c) < 32 for c in value) or any(c in value for c in "?#\\:"):
        raise AzureError("invalid_scope")
    if value == "/":
        return "/"
    parts = value.strip("/").split("/")
    if any(not p or p in (".", "..") for p in parts):
        raise AzureError("invalid_scope")
    return "/" + "/".join(parts).lower()


def object_id(tenant, identity):
    if not isinstance(tenant, str) or not isinstance(identity, str) or not tenant or not identity or max(len(tenant), len(identity)) > 2048 or ":" in tenant or ":" in identity or any(ord(c) < 32 for c in tenant + identity):
        raise AzureError("invalid_identity")
    return tenant + ":" + (arm(identity) if identity.startswith("/") else identity.lower())


@dataclass
class Row:
    family: str
    tenant: str
    data: dict
    evidence: list[str]
    quality: list[str] = field(default_factory=list)
    key: str = ""

    @property
    def properties(self):
        return self.data.get("properties", self.data)


@dataclass
class Decision:
    state: str
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    cuts: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def export(self):
        return {"decision": self.state, "reasons": sorted(set(self.reasons)),
                "evidence": sorted(set(self.evidence)), "cuts": sorted(set(self.cuts)),
                "assumptions": sorted(set(self.assumptions))}


class Graph:
    def __init__(self, as_of, limits=None):
        try:
            timestamp(as_of)
        except ValueError:
            raise AzureError("invalid_as_of") from None
        if limits is not None and not isinstance(limits, dict):
            raise AzureError("invalid_limit")
        self.as_of = as_of
        self.limits = dict(DEFAULTS)
        if limits:
            for key, value in limits.items():
                if key not in CEILINGS or type(value) is not int or not 0 < value <= CEILINGS[key]:
                    raise AzureError("invalid_limit")
                self.limits[key] = value
        self.objects = []
        self.index = {}
        self.by_identity = {}
        self.coverage = []
        self.ledger = []
        self.partial = []
        self._budget = [0]
        self.scenario = {}

    @property
    def work(self):
        return self._budget[0]

    @work.setter
    def work(self, value):
        self._budget[0] = value

    def tick(self, amount=1):
        self.work += amount
        if self.work > self.limits["expansions"]:
            raise Budget("expansion_limit")

    def rows(self, family, tenant=None):
        rows = self.index.get(family, [])
        return rows if tenant is None else [r for r in rows if r.tenant == tenant]

    def add(self, family, tenant, data, evidence, quality=None):
        identity = data.get("id")
        if not isinstance(identity, str):
            raise AzureError("missing_object_id")
        oid = object_id(tenant, identity)
        relation = data.get("groupId", data.get("objectId", "")) if family in ("group_members", "owners", "administrative_members", "federated_credentials") else ""
        index_id = oid + "|" + relation + "|" + data.get("plane", "")
        key = stable([family, oid, data])
        for prior in self.by_identity.get((family, index_id), []):
            if prior.key == key:
                prior.evidence = sorted(set(prior.evidence + [evidence]))
                prior.quality = sorted(set(prior.quality + list(quality or [])))
                return prior
            prior.quality = sorted(set(prior.quality + ["conflicting_observation"]))
        if len(self.objects) >= min(self.limits["nodes"], self.limits["edges"]):
            raise Budget("graph_limit")
        row = Row(family, tenant, data, [evidence], list(quality or []), key)
        if (family, index_id) in self.by_identity:
            row.quality.append("conflicting_observation")
        self.objects.append(row)
        self.index.setdefault(family, []).append(row)
        self.by_identity.setdefault((family, index_id), []).append(row)
        return row

    def cover(self, family, tenant, scopes, complete, evidence):
        self.coverage.append({"family": family, "tenant": tenant, "scopes": scopes,
                              "complete": complete, "evidence": evidence})

    def covered(self, family, tenant, scope):
        return any(c["complete"] and c["family"] == family and c["tenant"] == tenant
                   and any(self.contains(s, scope, tenant) for s in c["scopes"])
                   for c in self.coverage)

    def contains(self, parent, child, tenant=None):
        parent, child = arm(parent), arm(child)
        if parent == "/" or child == parent or child.startswith(parent + "/"):
            return True
        # Management-group hierarchy is explicit evidence, never a string guess.
        seen = set()
        current = child
        for _ in range(self.limits["hops"]):
            self.tick()
            subscription = "/" + "/".join(current.strip("/").split("/")[:2])
            link = None
            for row in self.rows("scope_parents", tenant):
                self.tick()
                if not row.quality and arm(row.data["id"]) in (current, subscription):
                    link = row
                    break
            if link is None or current in seen:
                return False
            seen.add(current)
            current = arm(link.data["parentId"])
            if current == parent:
                return True
        return False

    def without(self, cut):
        result = Graph(self.as_of, self.limits)
        result.scenario = self.scenario
        result.coverage = list(self.coverage)
        result.ledger = list(self.ledger)
        result.partial = list(self.partial)
        result._budget = self._budget
        for row in self.objects:
            self.tick()
            if row.key != cut:
                result.objects.append(row)
                result.index.setdefault(row.family, []).append(row)
                identity = object_id(row.tenant, row.data['id'])
                relation = row.data.get('groupId', row.data.get('objectId', '')) if row.family in ('group_members', 'owners', 'administrative_members', 'federated_credentials') else ''
                result.by_identity.setdefault((row.family, identity + '|' + relation + '|' + row.data.get('plane', '')), []).append(row)
        return result

    def export(self):
        nodes, edges = {}, {}
        types = {"users": "user", "groups": "group", "applications": "application",
                 "service_principals": "service_principal", "resources": "resource",
                 "role_definitions": "role_definition", "directory_definitions": "directory_role",
                 "administrative_units": "administrative_unit", "federated_credentials": "federated_credential",
                 "lighthouse": "delegation", "scope_parents": "scope"}
        observed = {entry["record_id"]: entry["observed_at"] for entry in self.ledger}

        def node(identity, tenant, kind, row):
            if identity not in nodes:
                if len(nodes) >= self.limits["nodes"]:
                    self.partial.append("graph_export_limit")
                    return
                nodes[identity] = {"id": identity, "tenant": tenant, "type": kind,
                                   "evidence": [], "uncertainty": []}
            value = nodes[identity]
            if kind != "unresolved":
                value["type"] = kind
                value["uncertainty"] = [q for q in value["uncertainty"] if q != "unresolved_object"]
            value["evidence"] = sorted(set(value["evidence"] + row.evidence))
            value["uncertainty"] = sorted(set(value["uncertainty"] + row.quality))
            if value["type"] == "unresolved":
                value["uncertainty"] = sorted(set(value["uncertainty"] + ["unresolved_object"]))

        try:
            for row in self.objects:
                self.tick()
                identity = object_id(row.tenant, row.data["id"]) if row.family in types else "observation:" + row.key
                node(identity, row.tenant, types.get(row.family, row.family), row)
                p, pairs = row.properties, []
                if row.family == "group_members":
                    pairs = [(row.tenant, row.data["id"], row.tenant, row.data["groupId"], "member_of")]
                elif row.family in ("role_assignments", "directory_assignments", "pim_eligible", "pim_active"):
                    pairs = [(row.tenant, p["principalId"], row.tenant, p["roleDefinitionId"], row.family)]
                elif row.family in ("owners", "administrative_members"):
                    pairs = [(row.tenant, row.data["id"], row.tenant, row.data["objectId"],
                              "owns" if row.family == "owners" else "administrative_member")]
                elif row.family == "federated_credentials":
                    pairs = [(row.tenant, row.data["objectId"], row.tenant, row.data["id"], "federates")]
                elif row.family == "scope_parents":
                    pairs = [(row.tenant, row.data["id"], row.tenant, row.data["parentId"], "scope_parent")]
                elif row.family == "applications" and row.data.get("appId"):
                    for sp in self.rows("service_principals", row.tenant):
                        self.tick()
                        if sp.data.get("appId", "").lower() == row.data["appId"].lower():
                            pairs.append((row.tenant, row.data["id"], row.tenant, sp.data["id"], "application_instance"))
                elif row.family == "lighthouse" and p.get("managedByTenantId"):
                    for authorization in p.get("authorizations", []) + p.get("eligibleAuthorizations", []):
                        if authorization.get("principalId"):
                            pairs.append((p["managedByTenantId"], authorization["principalId"], row.tenant, row.data["id"], "delegated_customer_role"))
                elif row.family == "resources":
                    mi = row.data.get("identity", {})
                    if mi.get("principalId"):
                        pairs.append((row.tenant, row.data["id"], row.tenant, mi["principalId"], "system_identity"))
                    for rid in mi.get("userAssignedIdentities", {}):
                        pairs.append((row.tenant, row.data["id"], row.tenant, rid, "user_identity"))
                    if row.data.get("type", "").lower() == "microsoft.managedidentity/userassignedidentities" and p.get("principalId"):
                        pairs.append((row.tenant, row.data["id"], row.tenant, p["principalId"], "identity_principal"))
                for st, source, tt, target, relation in pairs:
                    sid, tid = object_id(st, source), object_id(tt, target)
                    node(sid, st, "unresolved", row)
                    node(tid, tt, "unresolved", row)
                    eid = stable([row.key, sid, tid, relation])
                    if (eid not in edges and len(edges) >= self.limits["edges"]) or sid not in nodes or tid not in nodes:
                        self.partial.append("graph_export_limit")
                        continue
                    edges[eid] = {"id": eid, "source": sid, "target": tid, "relation": relation,
                        "scope": p.get("scope", p.get("directoryScopeId")), "observed_at": sorted({observed[r] for r in row.evidence if observed.get(r)}),
                        "start": p.get("startDateTime"), "end": p.get("endDateTime"),
                        "evidence": row.evidence, "uncertainty": row.quality}
        except Budget as exc:
            self.partial.append(str(exc))
        return {"schema_version": "attackpath.azure.graph/v1", "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
                "edges": sorted(edges.values(), key=lambda e: e["id"]), "coverage": self.coverage}


def absolute_parts(path):
    """Lexical absolute components; only fixed macOS mount aliases are allowed."""
    parts = list(Path(os.path.abspath(path)).parts[1:])
    if parts and parts[0] in ("tmp", "var") and Path("/" + parts[0]).is_symlink():
        parts = ["private"] + parts
    return parts
