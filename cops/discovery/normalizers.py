"""Asset normalization across DNS, certificates, IP addresses, endpoints, and cloud exports."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from .models import DiscoveredAsset, EvidenceProvenance

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def _compute_asset_id(asset_type: str, identifier: str) -> str:
    """Deterministic 24-character asset hash."""
    seed = f"{asset_type}:{identifier.strip().lower()}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:24]


def _canonical_domain(raw: str) -> str:
    cleaned = raw.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid domain name: {raw}")
    return cleaned


def _canonical_ip(raw: str) -> str:
    cleaned = raw.strip()
    return str(ipaddress.ip_address(cleaned))


def normalize_dns_record(
    record: dict[str, Any],
    provenance: EvidenceProvenance,
) -> DiscoveredAsset:
    """Normalize raw DNS record into DiscoveredAsset."""
    hostname_raw = record.get("hostname") or record.get("domain") or record.get("name")
    if not hostname_raw:
        raise ValueError("DNS record missing hostname/domain/name field")

    hostname = _canonical_domain(str(hostname_raw))
    record_type = str(record.get("record_type") or record.get("type", "A")).upper()
    value = record.get("value") or record.get("data") or record.get("target")

    attributes: dict[str, Any] = {
        "domain": hostname,
        "record_type": record_type,
    }
    if value:
        attributes["target_value"] = str(value)
        # Check if value is IP
        try:
            attributes["target_ip"] = _canonical_ip(str(value))
        except ValueError:
            pass

    for opt in ("ttl", "zone", "owner", "environment", "notes", "stale", "target_status"):
        if opt in record and record[opt] is not None:
            attributes[opt] = record[opt]

    asset_id = _compute_asset_id("dns", f"{hostname}:{record_type}")

    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="dns",
        identifier=hostname,
        attributes=attributes,
        provenance=[provenance],
        status="quarantined",
        quarantine_reasons=[],
    )


def normalize_certificate_record(
    record: dict[str, Any],
    provenance: EvidenceProvenance,
) -> DiscoveredAsset:
    """Normalize Certificate Transparency or TLS certificate record."""
    subject_raw = record.get("subject_cn") or record.get("hostname") or record.get("domain")
    if not subject_raw:
        raise ValueError("Certificate record missing subject/hostname field")

    subject = _canonical_domain(str(subject_raw))

    sans = []
    raw_sans = record.get("sans") or record.get("subject_alt_names") or []
    if isinstance(raw_sans, list):
        for s in raw_sans:
            try:
                sans.append(_canonical_domain(str(s)))
            except ValueError:
                pass
    sans = sorted(set(sans))

    attributes: dict[str, Any] = {
        "subject_cn": subject,
        "sans": sans,
        "issuer": record.get("issuer"),
        "serial_number": record.get("serial_number"),
        "not_before": record.get("not_before"),
        "not_after": record.get("not_after"),
    }
    for opt in ("fingerprint_sha256", "owner", "environment"):
        if opt in record and record[opt] is not None:
            attributes[opt] = record[opt]

    asset_id = _compute_asset_id("certificate", f"{subject}:{record.get('serial_number', 'cert')}")

    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="certificate",
        identifier=subject,
        attributes=attributes,
        provenance=[provenance],
        status="quarantined",
        quarantine_reasons=[],
    )


def normalize_ip_record(
    record: dict[str, Any],
    provenance: EvidenceProvenance,
) -> DiscoveredAsset:
    """Normalize IP allocation or subnet record."""
    raw_ip = record.get("ip") or record.get("address") or record.get("ip_address")
    if not raw_ip:
        raise ValueError("IP record missing ip/address field")

    ip_str = _canonical_ip(str(raw_ip))
    attributes: dict[str, Any] = {
        "ip": ip_str,
        "version": ipaddress.ip_address(ip_str).version,
    }
    for opt in ("asn", "cidr", "hostname", "ptr", "owner", "environment", "cloud_provider"):
        if opt in record and record[opt] is not None:
            attributes[opt] = record[opt]

    asset_id = _compute_asset_id("ip_address", ip_str)

    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="ip_address",
        identifier=ip_str,
        attributes=attributes,
        provenance=[provenance],
        status="quarantined",
        quarantine_reasons=[],
    )


def normalize_endpoint_record(
    record: dict[str, Any],
    provenance: EvidenceProvenance,
) -> DiscoveredAsset:
    """Normalize web endpoint / URL record."""
    raw_url = record.get("url") or record.get("endpoint")
    if not raw_url:
        raise ValueError("Endpoint record missing url/endpoint field")

    parsed = urlsplit(str(raw_url).strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Endpoint scheme must be http or https, got {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError("Endpoint URL missing valid host")

    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    canonical_url = f"{parsed.scheme}://{host}:{port}{parsed.path or '/'}"

    attributes: dict[str, Any] = {
        "url": canonical_url,
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "path": parsed.path or "/",
    }
    for opt in ("methods", "service_hint", "owner", "environment"):
        if opt in record and record[opt] is not None:
            attributes[opt] = record[opt]

    asset_id = _compute_asset_id("endpoint", canonical_url)

    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="endpoint",
        identifier=canonical_url,
        attributes=attributes,
        provenance=[provenance],
        status="quarantined",
        quarantine_reasons=[],
    )


def normalize_cloud_export(
    record: dict[str, Any],
    provenance: EvidenceProvenance,
) -> DiscoveredAsset:
    """Normalize cloud provider asset export record (e.g. Azure Resource Graph)."""
    raw_id = record.get("id") or record.get("resource_id") or record.get("arn")
    if not raw_id:
        raise ValueError("Cloud export record missing id/resource_id/arn")

    resource_id = str(raw_id).strip()
    provider = record.get("provider", "azure" if resource_id.startswith("/") else "aws")

    attributes: dict[str, Any] = {
        "resource_id": resource_id,
        "provider": provider,
        "name": record.get("name"),
        "resource_type": record.get("type") or record.get("resource_type"),
        "tenant_id": record.get("tenant_id"),
        "subscription_id": record.get("subscription_id") or record.get("account_id"),
        "public_endpoint": record.get("public_endpoint") is True,
        "ip": record.get("ip") or record.get("public_ip"),
    }
    for opt in ("owner", "environment", "tags"):
        if opt in record and record[opt] is not None:
            attributes[opt] = record[opt]

    asset_id = _compute_asset_id("cloud_resource", resource_id)

    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="cloud_resource",
        identifier=resource_id,
        attributes=attributes,
        provenance=[provenance],
        status="quarantined",
        quarantine_reasons=[],
    )
