"""Offline intake and normalization for multi-source SOC exports (Sentinel, Splunk, Entra).

Parses CSV and JSON exports, enforces tenant and time scope, extracts entities with
case-scoped HMAC-like digests, builds deterministic timelines and competing hypotheses,
and emits a validated case snapshot.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from .engine import ContractError, Document, alias, require, utc, validate
from .files import read_regular

ID_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
ISO_TZ_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class RawRecord:
    """Intermediate normalized event before case integration."""

    def __init__(
        self,
        source_system: str,
        record_ref: str,
        timestamp_utc: str,
        summary: str,
        entities: list[tuple[str, str]],  # (kind, raw_value)
        indicators: dict[str, Any],
        raw_payload: dict[str, Any],
        tenant_id: str | None = None,
    ) -> None:
        self.source_system = source_system
        self.record_ref = record_ref
        self.timestamp_utc = timestamp_utc
        self.summary = summary
        self.entities = entities
        self.indicators = indicators
        self.raw_payload = raw_payload
        self.tenant_id = tenant_id


def parse_timestamp(value: Any) -> str:
    """Convert any supported ISO-8601 or common log timestamp into canonical UTC Z format."""
    if not isinstance(value, str) or not value.strip():
        raise ContractError("Timestamp must be a non-empty string.")
    cleaned = value.strip().replace(" ", "T")
    match = ISO_TZ_PATTERN.match(cleaned)
    if not match:
        # Try unix epoch in seconds
        try:
            epoch = float(cleaned)
            dt = datetime.fromtimestamp(epoch, tz=UTC)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError, OSError) as exc:
            raise ContractError(f"Unrecognized timestamp format: {value}") from exc

    base_time, offset = match.groups()
    dt = datetime.fromisoformat(base_time)
    if not offset or offset == "Z":
        dt = dt.replace(tzinfo=UTC)
    else:
        # Normalize offset format (e.g. +0500 -> +05:00)
        norm_offset = offset
        if len(norm_offset) == 5 and ":" not in norm_offset:
            norm_offset = f"{norm_offset[:3]}:{norm_offset[3:]}"
        hours = int(norm_offset[1:3])
        minutes = int(norm_offset[4:6])
        sign = 1 if norm_offset[0] == "+" else -1
        delta_tz = timezone(sign * timedelta(hours=hours, minutes=minutes))
        dt = dt.replace(tzinfo=delta_tz).astimezone(UTC)

    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_digest(source: str, index: int, data: dict[str, Any]) -> str:
    serialized = json.dumps(
        {"source": source, "index": index, "data": data},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def parse_sentinel(content: bytes, filename: str, expected_tenant: str | None) -> list[RawRecord]:
    """Parse Microsoft Sentinel incident or query export (JSON or CSV)."""
    records: list[RawRecord] = []
    text = content.decode("utf-8", errors="replace")

    # Try JSON array first
    is_json = False
    try:
        raw_json = json.loads(text)
        is_json = True
        items = raw_json if isinstance(raw_json, list) else raw_json.get("value", raw_json.get("records", [raw_json]))
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            rec_tenant = item.get("TenantId") or item.get("tenant_id") or item.get("AadTenantId")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Sentinel export: {rec_tenant}")

            raw_ts = (
                item.get("TimeGenerated")
                or item.get("CreatedTimeUtc")
                or item.get("FirstActivityTimeUtc")
                or item.get("event_time")
            )
            if not raw_ts:
                continue
            ts = parse_timestamp(str(raw_ts))

            title = item.get("Title") or item.get("AlertName") or item.get("Activity") or "Sentinel Event"
            severity = item.get("Severity") or item.get("AlertSeverity") or "Informational"
            status = item.get("Status") or "Active"

            entities: list[tuple[str, str]] = []
            if item.get("Account") or item.get("UserPrincipalName") or item.get("AccountName"):
                entities.append(("account", str(item.get("Account") or item.get("UserPrincipalName") or item.get("AccountName"))))
            if item.get("IPAddress") or item.get("ClientIP") or item.get("CallerIpAddress"):
                entities.append(("ip", str(item.get("IPAddress") or item.get("ClientIP") or item.get("CallerIpAddress"))))
            if item.get("AppDisplayName") or item.get("AppId") or item.get("ApplicationId"):
                entities.append(("app", str(item.get("AppDisplayName") or item.get("AppId") or item.get("ApplicationId"))))
            if item.get("ResourceId") or item.get("Resource"):
                entities.append(("resource", str(item.get("ResourceId") or item.get("Resource"))))
            if item.get("DeviceName") or item.get("Computer"):
                entities.append(("device", str(item.get("DeviceName") or item.get("Computer"))))

            summary = f"Sentinel {severity} alert: {title} (Status: {status})"
            if len(summary) > 2000:
                summary = summary[:1997] + "..."

            ref = _record_digest(filename, idx, item)
            records.append(
                RawRecord(
                    source_system="sentinel",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary,
                    entities=entities,
                    indicators={"severity": str(severity), "status": str(status)},
                    raw_payload=item,
                    tenant_id=str(rec_tenant) if rec_tenant else None,
                )
            )
    except json.JSONDecodeError:
        pass

    if not is_json:
        # Fallback to CSV
        reader = csv.DictReader(io.StringIO(text))
        for idx, row in enumerate(reader):
            rec_tenant = row.get("TenantId") or row.get("tenant_id")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Sentinel CSV: {rec_tenant}")

            raw_ts = (
                row.get("TimeGenerated")
                or row.get("CreatedTimeUtc")
                or row.get("FirstActivityTimeUtc")
                or row.get("event_time")
            )
            if not raw_ts:
                continue
            ts = parse_timestamp(raw_ts)
            title = row.get("Title") or row.get("AlertName") or "Sentinel Event"
            severity = row.get("Severity") or "Informational"

            entities = []
            if row.get("Account") or row.get("UserPrincipalName"):
                entities.append(("account", row.get("Account") or row.get("UserPrincipalName")))
            if row.get("IPAddress") or row.get("ClientIP"):
                entities.append(("ip", row.get("IPAddress") or row.get("ClientIP")))
            if row.get("AppDisplayName") or row.get("AppId"):
                entities.append(("app", row.get("AppDisplayName") or row.get("AppId")))

            summary = f"Sentinel {severity} event: {title}"
            ref = _record_digest(filename, idx, row)
            records.append(
                RawRecord(
                    source_system="sentinel",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary[:2000],
                    entities=entities,
                    indicators={"severity": severity},
                    raw_payload=row,
                    tenant_id=rec_tenant,
                )
            )

    return records


def parse_splunk(content: bytes, filename: str, expected_tenant: str | None) -> list[RawRecord]:
    """Parse Splunk search export (JSON or CSV)."""
    records: list[RawRecord] = []
    text = content.decode("utf-8", errors="replace")

    is_json = False
    try:
        raw_json = json.loads(text)
        is_json = True
        items = raw_json if isinstance(raw_json, list) else raw_json.get("results", [raw_json])
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            rec_tenant = item.get("tenant_id") or item.get("tenant")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Splunk export: {rec_tenant}")

            raw_ts = item.get("_time") or item.get("timestamp") or item.get("time")
            if not raw_ts:
                continue
            ts = parse_timestamp(str(raw_ts))

            action = item.get("action") or item.get("status") or "observed"
            sig = item.get("signature") or item.get("event_name") or item.get("sourcetype") or "Splunk Event"

            entities = []
            if item.get("user") or item.get("src_user"):
                entities.append(("account", str(item.get("user") or item.get("src_user"))))
            if item.get("src_ip") or item.get("src"):
                entities.append(("ip", str(item.get("src_ip") or item.get("src"))))
            if item.get("dest_ip") or item.get("dest"):
                entities.append(("ip", str(item.get("dest_ip") or item.get("dest"))))
            if item.get("host") or item.get("dvc"):
                entities.append(("device", str(item.get("host") or item.get("dvc"))))
            if item.get("app"):
                entities.append(("app", str(item.get("app"))))

            summary = f"Splunk {sig}: action={action}"
            ref = _record_digest(filename, idx, item)
            records.append(
                RawRecord(
                    source_system="splunk",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary[:2000],
                    entities=entities,
                    indicators={"action": str(action), "signature": str(sig)},
                    raw_payload=item,
                    tenant_id=str(rec_tenant) if rec_tenant else None,
                )
            )
    except json.JSONDecodeError:
        pass

    if not is_json:
        reader = csv.DictReader(io.StringIO(text))
        for idx, row in enumerate(reader):
            rec_tenant = row.get("tenant_id") or row.get("tenant")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Splunk CSV: {rec_tenant}")

            raw_ts = row.get("_time") or row.get("timestamp") or row.get("time")
            if not raw_ts:
                continue
            ts = parse_timestamp(raw_ts)

            entities = []
            if row.get("user"):
                entities.append(("account", row.get("user")))
            if row.get("src_ip"):
                entities.append(("ip", row.get("src_ip")))
            if row.get("host"):
                entities.append(("device", row.get("host")))

            summary = f"Splunk event: {row.get('signature', 'activity')} action={row.get('action', 'none')}"
            ref = _record_digest(filename, idx, row)
            records.append(
                RawRecord(
                    source_system="splunk",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary[:2000],
                    entities=entities,
                    indicators={"action": row.get("action", "unknown")},
                    raw_payload=row,
                    tenant_id=rec_tenant,
                )
            )

    return records


def parse_entra(content: bytes, filename: str, expected_tenant: str | None) -> list[RawRecord]:
    """Parse Microsoft Entra ID sign-in or audit logs (JSON or CSV)."""
    records: list[RawRecord] = []
    text = content.decode("utf-8", errors="replace")

    is_json = False
    try:
        raw_json = json.loads(text)
        is_json = True
        items = raw_json if isinstance(raw_json, list) else raw_json.get("value", [raw_json])
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            rec_tenant = item.get("tenantId") or item.get("resourceTenantId")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Entra export: {rec_tenant}")

            raw_ts = item.get("createdDateTime") or item.get("activityDateTime") or item.get("TimeGenerated")
            if not raw_ts:
                continue
            ts = parse_timestamp(str(raw_ts))

            # Distinguish Sign-in vs. Audit
            is_signin = "createdDateTime" in item or "userPrincipalName" in item
            entities = []
            indicators = {}

            if is_signin:
                upn = item.get("userPrincipalName") or item.get("userId")
                if upn:
                    entities.append(("account", str(upn)))
                ip = item.get("ipAddress")
                if ip:
                    entities.append(("ip", str(ip)))
                app = item.get("appDisplayName") or item.get("appId")
                if app:
                    entities.append(("app", str(app)))

                status_obj = item.get("status", {})
                err_code = status_obj.get("errorCode", 0) if isinstance(status_obj, dict) else 0
                failure = status_obj.get("failureReason", "") if isinstance(status_obj, dict) else ""
                risk = item.get("riskDetail", "none")
                ca_status = item.get("conditionalAccessStatus", "notApplied")

                indicators = {"error_code": err_code, "risk": risk, "conditional_access": ca_status}
                if err_code == 0:
                    summary = f"Entra sign-in: success for {upn} to {app} from {ip}"
                else:
                    summary = f"Entra sign-in failure ({err_code}): {upn} to {app} ({failure})"
            else:
                # Audit activity
                activity = item.get("activityDisplayName") or "Entra Directory Activity"
                initiated = item.get("initiatedBy", {})
                user_init = initiated.get("user", {}).get("userPrincipalName") if isinstance(initiated, dict) else None
                app_init = initiated.get("app", {}).get("displayName") if isinstance(initiated, dict) else None
                actor = user_init or app_init or "System"

                if user_init:
                    entities.append(("account", str(user_init)))
                if app_init:
                    entities.append(("app", str(app_init)))

                result = item.get("result", "success")
                indicators = {"result": result, "activity": activity}
                summary = f"Entra audit: {activity} by {actor} (Result: {result})"

            ref = _record_digest(filename, idx, item)
            records.append(
                RawRecord(
                    source_system="entra",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary[:2000],
                    entities=entities,
                    indicators=indicators,
                    raw_payload=item,
                    tenant_id=str(rec_tenant) if rec_tenant else None,
                )
            )
    except json.JSONDecodeError:
        pass

    if not is_json:
        reader = csv.DictReader(io.StringIO(text))
        for idx, row in enumerate(reader):
            rec_tenant = row.get("tenantId")
            if expected_tenant and rec_tenant and str(rec_tenant) != expected_tenant:
                raise ContractError(f"Cross-tenant record detected in Entra CSV: {rec_tenant}")

            raw_ts = row.get("createdDateTime") or row.get("activityDateTime")
            if not raw_ts:
                continue
            ts = parse_timestamp(raw_ts)

            entities = []
            if row.get("userPrincipalName"):
                entities.append(("account", row.get("userPrincipalName")))
            if row.get("ipAddress"):
                entities.append(("ip", row.get("ipAddress")))
            if row.get("appDisplayName"):
                entities.append(("app", row.get("appDisplayName")))

            summary = f"Entra log: user={row.get('userPrincipalName', 'none')} app={row.get('appDisplayName', 'none')}"
            ref = _record_digest(filename, idx, row)
            records.append(
                RawRecord(
                    source_system="entra",
                    record_ref=ref,
                    timestamp_utc=ts,
                    summary=summary[:2000],
                    entities=entities,
                    indicators={},
                    raw_payload=row,
                    tenant_id=rec_tenant,
                )
            )

    return records


def ingest_sources(
    source_specs: list[str],
    case_id: str,
    tenant: str,
    workspace: str,
    start: str,
    end: str,
) -> Document:
    """Ingest multiple export sources, normalize into timeline and evidence, and emit a valid case."""
    alias(case_id)
    alias(tenant)
    alias(workspace)
    start_dt = utc(start)
    end_dt = utc(end)
    require(start_dt < end_dt, "Case time interval must increase.")

    all_records: list[RawRecord] = []
    for spec in source_specs:
        parts = spec.split(":", 1)
        if len(parts) == 2:
            kind, path_str = parts
        else:
            kind, path_str = "auto", parts[0]

        path = Path(path_str)
        content = read_regular(path)
        filename = path.name

        if kind == "sentinel":
            records = parse_sentinel(content, filename, tenant)
        elif kind == "splunk":
            records = parse_splunk(content, filename, tenant)
        elif kind == "entra":
            records = parse_entra(content, filename, tenant)
        else:
            # Auto-detect format
            if "sentinel" in filename.lower():
                records = parse_sentinel(content, filename, tenant)
            elif "splunk" in filename.lower():
                records = parse_splunk(content, filename, tenant)
            elif "entra" in filename.lower() or "signin" in filename.lower():
                records = parse_entra(content, filename, tenant)
            else:
                # Try Sentinel, then Entra, then Splunk
                records = parse_sentinel(content, filename, tenant)
                if not records:
                    records = parse_entra(content, filename, tenant)
                if not records:
                    records = parse_splunk(content, filename, tenant)

        all_records.extend(records)

    # Filter records within case interval [start, end)
    scoped_records = [
        r for r in all_records if start_dt <= utc(r.timestamp_utc) < end_dt
    ]
    require(bool(scoped_records), "No records found within the specified case time window.")

    # Sort deterministically: timestamp, source, record_ref
    scoped_records.sort(key=lambda r: (r.timestamp_utc, r.source_system, r.record_ref))

    # Deduplicate entities and assign deterministic keys and aliases
    entity_key_to_alias: dict[str, str] = {}
    entities_list: list[Document] = []
    alias_counters: dict[str, int] = {"account": 0, "app": 0, "ip": 0, "device": 0, "resource": 0}

    def get_or_create_entity(kind: str, raw_value: str) -> str:
        clean_val = raw_value.strip().lower()
        key = sha256(f"{case_id}:{kind}:{clean_val}".encode()).hexdigest()
        if key in entity_key_to_alias:
            return entity_key_to_alias[key]

        alias_counters[kind] += 1
        prefix = kind[:3] if kind != "device" else "dev"
        ent_alias = f"{prefix}-{alias_counters[kind]:02d}"
        entity_key_to_alias[key] = ent_alias
        entities_list.append({"id": ent_alias, "kind": kind, "key": key})
        return ent_alias

    # Define standard competing hypotheses
    hypotheses = [
        {
            "id": "malicious-activity",
            "kind": "malicious",
            "statement": "Observed activity represents unauthorized access, credential abuse, or policy violation.",
        },
        {
            "id": "benign-explanation",
            "kind": "benign",
            "statement": "Observed activity represents authorized administrative operations, legitimate user workflow, or benign diagnostic noise.",
        },
    ]

    evidence_list: list[Document] = []
    seen_provenance = set()
    ev_counter = 0

    for rec in scoped_records:
        source_alias = f"{rec.source_system}-export"
        prov = (source_alias, rec.record_ref)
        if prov in seen_provenance:
            continue
        seen_provenance.add(prov)

        ev_counter += 1
        ev_id = f"ev-{ev_counter:02d}"

        # Resolve entity aliases
        ent_aliases: list[str] = []
        for ent_kind, ent_val in rec.entities:
            a = get_or_create_entity(ent_kind, ent_val)
            if a not in ent_aliases:
                ent_aliases.append(a)

        if not ent_aliases:
            # Must associate with at least one entity per case contract
            fallback_alias = get_or_create_entity("resource", "unspecified-system")
            ent_aliases.append(fallback_alias)

        # Build initial assessments based on indicators
        assessments: list[Document] = []
        is_suspicious = False

        if rec.indicators.get("severity") in ("High", "Critical", "Medium"):
            is_suspicious = True
        elif rec.indicators.get("error_code") and rec.indicators.get("error_code") != 0:
            is_suspicious = True
        elif rec.indicators.get("risk") not in ("none", "", None):
            is_suspicious = True
        elif rec.indicators.get("action") in ("blocked", "failure"):
            is_suspicious = True

        if is_suspicious:
            assessments.append({
                "hypothesis_id": "malicious-activity",
                "stance": "supports",
                "reason": f"Observed anomaly or security alert ({rec.summary}) in {rec.source_system}.",
            })
            assessments.append({
                "hypothesis_id": "benign-explanation",
                "stance": "refutes",
                "reason": "Alert severity or failure code contradicts expected benign workflow.",
            })
        else:
            assessments.append({
                "hypothesis_id": "benign-explanation",
                "stance": "supports",
                "reason": f"Activity in {rec.source_system} conforms to standard event baseline.",
            })
            assessments.append({
                "hypothesis_id": "malicious-activity",
                "stance": "refutes",
                "reason": "Clean completion or normal telemetry weakens compromise hypothesis.",
            })

        evidence_list.append({
            "id": ev_id,
            "source": source_alias,
            "record_ref": rec.record_ref,
            "scope": {"tenant": tenant, "workspace": workspace},
            "event_time": rec.timestamp_utc,
            "entities": sorted(ent_aliases),
            "assessments": assessments,
            "summary": rec.summary,
        })

    # Generate initial investigative inquiry steps
    primary_entities = [e["id"] for e in entities_list[:2]]
    steps: list[Document] = [
        {
            "id": "signin-triage",
            "question": "Are there anomalous authentication events or password spray attempts matching the involved accounts?",
            "hypothesis_ids": ["malicious-activity"],
            "basis": [e["id"] for e in evidence_list[:1]],
            "depends_on": [],
            "when": [],
            "query": {
                "hunt_id": "H01",
                "surface": "sentinel_analytics",
                "entities": primary_entities,
                "start": start,
                "end": end,
            },
            "expected": {
                "supports": "Assess explicit findings against the named hypotheses.",
                "refutes": "Record disconfirming observations without silently discarding support.",
                "empty": "No matching observation with complete coverage; retain alternatives.",
                "unavailable": "Record telemetry gap and seek an authorized alternative source.",
                "inconclusive": "Record uncertainty and reconsider the next discriminating question.",
            },
            "value": {
                "information_gain": 4,
                "urgency": 3,
                "impact": 4,
                "cost": 2,
            },
        },
        {
            "id": "token-audit",
            "question": "Were any high-privilege tokens or OAuth applications consented during this interval?",
            "hypothesis_ids": ["malicious-activity"],
            "basis": [],
            "depends_on": ["signin-triage"],
            "when": [
                {
                    "step_id": "signin-triage",
                    "outcomes": ["supports", "inconclusive"],
                }
            ],
            "query": {
                "hunt_id": "H02",
                "surface": "sentinel_analytics",
                "entities": primary_entities,
                "start": start,
                "end": end,
            },
            "expected": {
                "supports": "Assess explicit findings against the named hypotheses.",
                "refutes": "Record disconfirming observations without silently discarding support.",
                "empty": "No matching observation with complete coverage; retain alternatives.",
                "unavailable": "Record telemetry gap and seek an authorized alternative source.",
                "inconclusive": "Record uncertainty and reconsider the next discriminating question.",
            },
            "value": {
                "information_gain": 5,
                "urgency": 4,
                "impact": 5,
                "cost": 3,
            },
        },
    ]

    case_doc: Document = {
        "schema_version": 1,
        "id": case_id,
        "scope": {
            "tenant": tenant,
            "workspace": workspace,
            "start": start,
            "end": end,
        },
        "budget": {
            "max_steps": 6,
            "max_cost": 15,
            "max_no_progress": 2,
        },
        "hypotheses": hypotheses,
        "entities": entities_list,
        "steps": steps,
        "evidence": evidence_list,
        "results": [],
    }

    return validate(case_doc)
