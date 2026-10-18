"""Tenant-bound correlation of imported consent evidence assertions.

Risk labels and export completeness are assertions supplied by the evidence
producer. This bounded correlation does not establish a production verdict.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


SCHEMA = "cops.consent-evidence/v1"


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None
        return parsed if parsed and parsed.utcoffset() is not None else None
    except ValueError:
        return None


def assess_consent(evidence: dict[str, Any]) -> dict[str, Any]:
    """Require complete, unique, in-window records before proposing a target."""
    limitations = ["imported risk and completeness assertions; production Entra validation unverified"]
    unresolved = {"status": "insufficient_evidence", "targets": [], "evidence_refs": [],
                  "limitations": limitations + ["missing, malformed, or conflicting tenant-bound evidence"]}
    if not isinstance(evidence, dict) or evidence.get("schema_version") != SCHEMA:
        return unresolved
    coverage = evidence.get("coverage")
    if not isinstance(coverage, dict):
        return unresolved
    tenant = coverage.get("tenant_id")
    start, end = _time(coverage.get("window_start")), _time(coverage.get("window_end"))
    if not isinstance(tenant, str) or not tenant or not start or not end or start >= end:
        return unresolved
    records = {}
    for kind in ("grants", "service_principals", "signins"):
        items = evidence.get(kind)
        if coverage.get(kind + "_complete") is not True or not isinstance(items, list) or not items:
            return unresolved
        seen = set()
        for item in items:
            if not isinstance(item, dict) or any(not isinstance(item.get(key), str) or not item[key]
                                                 for key in ("id", "tenant_id", "evidence_ref")):
                return unresolved
            observed = _time(item.get("observed_at"))
            if item["tenant_id"] != tenant or not observed or not start <= observed <= end or item["id"] in seen:
                return unresolved
            seen.add(item["id"])
        records[kind] = items
    principals = {item["id"]: item for item in records["service_principals"]}
    if any(not isinstance(item.get("app_id"), str) or not item["app_id"] for item in principals.values()):
        return unresolved
    if len({item["app_id"] for item in principals.values()}) != len(principals):
        return unresolved
    for signin in records["signins"]:
        if (type(signin.get("suspicious")) is not bool or not isinstance(signin.get("user_id"), str)
                or not signin["user_id"] or not isinstance(signin.get("app_id"), str)
                or signin["app_id"] not in {item["app_id"] for item in principals.values()}):
            return unresolved
    targets, refs = [], set()
    for grant in records["grants"]:
        principal = principals.get(grant.get("client_id")) if isinstance(grant.get("client_id"), str) else None
        consent_type = grant.get("consent_type")
        if (not principal or type(grant.get("high_privilege")) is not bool
                or not isinstance(consent_type, str) or consent_type not in {"AllPrincipals", "Principal"}):
            return unresolved
        if consent_type == "Principal" and (not isinstance(grant.get("principal_id"), str) or not grant["principal_id"]):
            return unresolved
        matches = [item for item in records["signins"] if item["app_id"] == principal["app_id"]
                   and (consent_type == "AllPrincipals" or item["user_id"] == grant["principal_id"])]
        if not matches:
            return unresolved
        suspicious = [item for item in matches if item["suspicious"]]
        refs.update([grant["evidence_ref"], principal["evidence_ref"], *(item["evidence_ref"] for item in matches)])
        if grant["high_privilege"] and suspicious:
            targets.append(
                {
                    "tenant_id": tenant,
                    "grant_id": grant["id"],
                    "client_id": grant["client_id"],
                    "app_id": principal["app_id"],
                }
            )
    return {
        "status": "suspicious_consent_observed" if targets else "no_suspicious_consent_observed",
        "targets": sorted(targets, key=lambda item: item["grant_id"]),
        "evidence_refs": sorted(refs),
        "limitations": limitations,
    }
