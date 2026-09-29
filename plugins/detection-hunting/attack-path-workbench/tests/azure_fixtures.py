"""Synthetic documented Graph/ARM pages wrapped in the canonical SDK contract."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from attackpath._runtime.cops.evidence.contract import build_envelope
from attackpath._runtime.cops.evidence.canonical import canonical
from attackpath.azure.collection import GRAPH_CATALOG, ARM_CATALOG, RESOURCE_APIS, source_contract

NOW = "2026-09-28T12:00:00Z"
S = "/subscriptions/sub-a"


def write_bundle(root, graph, *, status="complete", observed_at=NOW, limits=None):
    root = Path(root)
    groups = {}
    for row in graph.objects:
        data = deepcopy(row.data)
        family = row.family
        if family.startswith("pim_"):
            family = data.pop("plane") + "_" + family
            data.pop("requirements", None)
        api = "v1.0" if family in {r[0] for r in GRAPH_CATALOG} else next((r[2] for r in ARM_CATALOG if r[0] == family), None)
        if family == "resources":
            api = RESOURCE_APIS[data["type"].lower()]
        context = {}
        if family in ("group_members", "owners", "administrative_members", "federated_credentials"):
            key = "groupId" if family == "group_members" else "objectId"
            context = {key: data.pop(key)}
            if family == "federated_credentials" and context[key].startswith("/"):
                api = "2023-01-31"
        key = (family, row.tenant, api, tuple(context.items()))
        groups.setdefault(key, []).append(data)
    # Explicit complete empty acquisitions establish absence for these families.
    for tenant in {t["tenant"] for t in graph.scenario["targets"]}:
        for family in ("deny_assignments", "azure_pim_active", "azure_pim_eligible"):
            api = next(r[2] for r in ARM_CATALOG if r[0] == family)
            groups.setdefault((family, tenant, api, ()), [])
    sources = []
    for index, ((family, tenant, api, pairs), values) in enumerate(sorted(groups.items())):
        sid = family + "-" + str(index)
        scopes = ["/"] if source_contract(family, api) == "MicrosoftGraph" else [S]
        envelope = build_envelope(acquisition_id=sid, product=source_contract(family, api), api=api,
            tenant=tenant, scope=scopes, identity=sid, locator=sid, payload={"value": values},
            acquired_at=NOW, transformed_at=NOW, observed_at=observed_at,
            request_fingerprint="a"*64, page=1)
        raw = canonical(envelope) + b"\n"
        receipt = {"schema_version":"cops.acquisition/v1", "acquisition_id":sid, "generation":1,
            "adapter":"azure-synthetic-fixture", "adapter_version":"1", "tenant":tenant, "scope":scopes,
            "request_fingerprint":"a"*64, "started_at":NOW, "finished_at":NOW,
            "status":status, "reasons":[] if status == "complete" else ["page_limit"], "consistency":"unknown",
            "limits":{"pages":10,"attempts":10,"records":10,"response_bytes":1048576,
                "total_bytes":10485760,"record_bytes":1048576,"storage_bytes":10485760,
                "depth":32,"request_seconds":10,"active_seconds":100,"retries":1},
            "consumed":{"pages":1,"attempts":1,"records":1,"duplicates":0,"bytes":len(raw),
                "storage_bytes":len(raw),"active_seconds":1}}
        rec = canonical(receipt)
        (root / (sid + ".jsonl")).write_bytes(raw)
        (root / (sid + ".receipt.json")).write_bytes(rec)
        sources.append({"id":sid, "family":family,"api":api,"tenant":tenant,"scopes":scopes,
            "path":sid+".jsonl","sha256":hashlib.sha256(raw).hexdigest(),
            "receipt":sid+".receipt.json","receipt_sha256":hashlib.sha256(rec).hexdigest(),
            "max_age_seconds":3600,"context":dict(pairs)})
    manifest = {"schema_version":"attackpath.azure.input/v1","sources":sources,"scenario":deepcopy(graph.scenario)}
    if limits is not None: manifest["limits"] = limits
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest))
    return path
