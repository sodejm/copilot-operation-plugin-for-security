"""Offline tool output importers for Masscan and Nmap active assessment results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from cops.evidence.canonical import utc_now
from .active_models import (
    ActiveScanSession,
    ActiveServiceAssessment,
    ConfidenceLevel,
    InferredFingerprint,
    ObservedConfiguration,
    ObservedTLS,
    PortState,
    Protocol,
    ScanBudget,
    ScanVantage,
    ServiceReachability,
)
from .fingerprinter import infer_service_fingerprint
from .models import EvidenceProvenance


def import_masscan_json(
    filepath: Path | str,
    vantage: str = ScanVantage.EXTERNAL.value,
    scope_ref: str = "masscan-import",
) -> ActiveScanSession:
    """Import Masscan JSON scan results into an ActiveScanSession."""
    path = Path(filepath)
    raw_content = path.read_text(encoding="utf-8").strip()
    data = json.loads(raw_content) if raw_content else []

    file_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
    prov = EvidenceProvenance(
        source_id="S01",
        source_type="masscan_export",
        sha256=file_hash,
        timestamp=utc_now(),
        path_or_uri=str(path),
    )

    targets: set[str] = set()
    ports: set[int] = set()
    assessments: list[ActiveServiceAssessment] = []
    completed_keys: set[str] = set()

    for entry in data:
        ip = entry.get("ip")
        if not ip:
            continue
        targets.add(ip)

        for p_info in entry.get("ports", []):
            port = int(p_info.get("port", 0))
            proto = p_info.get("proto", "tcp").lower()
            status = p_info.get("status", "open").lower()
            ports.add(port)

            probe_key = ActiveScanSession.make_probe_key(vantage, proto, ip, port)
            completed_keys.add(probe_key)
            probe_id = hashlib.sha256(f"{probe_key}:{file_hash}".encode("utf-8")).hexdigest()[:24]

            port_state = PortState.OPEN.value if status == "open" else PortState.CLOSED.value
            reachability = ServiceReachability.REACHABLE.value if status == "open" else ServiceReachability.UNREACHABLE.value

            obs = ObservedConfiguration(
                protocol_metadata={
                    "reason": p_info.get("reason"),
                    "ttl": p_info.get("ttl"),
                }
            )
            fp = infer_service_fingerprint(ip, port, proto, obs)

            assessments.append(
                ActiveServiceAssessment(
                    probe_id=probe_id,
                    target_host=ip,
                    resolved_ip=ip,
                    port=port,
                    protocol=proto,
                    vantage=vantage,
                    port_state=port_state,
                    reachability=reachability,
                    observed_config=obs,
                    inferred_fingerprint=fp,
                    timestamp_utc=utc_now(),
                    provenance=prov,
                )
            )

    session_id = hashlib.sha256(f"{scope_ref}:{file_hash}".encode("utf-8")).hexdigest()[:16]
    session = ActiveScanSession(
        session_id=session_id,
        scope_reference=scope_ref,
        approved_targets=sorted(targets),
        approved_ports=sorted(ports),
        vantage=vantage,
        budget=ScanBudget(rate_limit_pps=100.0),
        started_at=utc_now(),
        completed_at=utc_now(),
        status="completed",
        completed_probe_keys=completed_keys,
        assessments=assessments,
        total_probes_dispatched=len(assessments),
        total_side_effects=len(assessments),
    )
    return session


def import_nmap_xml(
    filepath: Path | str,
    vantage: str = ScanVantage.EXTERNAL.value,
    scope_ref: str = "nmap-import",
) -> ActiveScanSession:
    """Import Nmap XML output (-oX) into an ActiveScanSession."""
    path = Path(filepath)
    raw_content = path.read_text(encoding="utf-8")
    root = ET.fromstring(raw_content)

    file_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
    prov = EvidenceProvenance(
        source_id="S02",
        source_type="nmap_xml_export",
        sha256=file_hash,
        timestamp=utc_now(),
        path_or_uri=str(path),
    )

    targets: set[str] = set()
    ports: set[int] = set()
    assessments: list[ActiveServiceAssessment] = []
    completed_keys: set[str] = set()

    for host_node in root.findall("host"):
        # Extract addresses
        addr_ip = None
        for addr in host_node.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                addr_ip = addr.get("addr")
                break
        if not addr_ip:
            continue

        # Extract hostnames
        hostnames: list[str] = []
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            for hn in hostnames_node.findall("hostname"):
                name = hn.get("name")
                if name:
                    hostnames.append(name)

        target_host = hostnames[0] if hostnames else addr_ip
        targets.add(target_host)

        # Extract ports
        ports_node = host_node.find("ports")
        if ports_node is None:
            continue

        for p_node in ports_node.findall("port"):
            port_id = int(p_node.get("portid", 0))
            proto = p_node.get("protocol", "tcp").lower()
            ports.add(port_id)

            state_node = p_node.find("state")
            state_str = state_node.get("state", "closed").lower() if state_node is not None else "closed"

            if state_str == "open":
                port_state = PortState.OPEN.value
                reachability = ServiceReachability.REACHABLE.value
            elif state_str in ("filtered", "open|filtered"):
                port_state = PortState.FILTERED.value
                reachability = ServiceReachability.FILTERED.value
            else:
                port_state = PortState.CLOSED.value
                reachability = ServiceReachability.REACHABLE.value

            # Extract service info
            svc_node = p_node.find("service")
            svc_name = svc_node.get("name", "unknown") if svc_node is not None else "unknown"
            product = svc_node.get("product") if svc_node is not None else None
            version = svc_node.get("version") if svc_node is not None else None
            extrainfo = svc_node.get("extrainfo") if svc_node is not None else None

            # Extract scripts (e.g. ssl-cert)
            tls_obj = None
            for script_node in p_node.findall("script"):
                if script_node.get("id") == "ssl-cert":
                    output = script_node.get("output", "")
                    # Extract CN if available
                    cn = None
                    for line in output.splitlines():
                        if "commonName=" in line:
                            cn = line.split("commonName=")[-1].split("/")[0].strip()
                            break
                    tls_obj = ObservedTLS(subject_cn=cn)

            obs = ObservedConfiguration(
                tls=tls_obj,
                protocol_metadata={
                    "service_tunnel": svc_node.get("tunnel") if svc_node is not None else None,
                    "extrainfo": extrainfo,
                },
            )

            # Build or infer fingerprint
            if product:
                uncertainty_reasons: list[str] = []
                if "proxy" in (extrainfo or "").lower() or "loadbalancer" in (extrainfo or "").lower():
                    uncertainty_reasons.append("Nmap extrainfo indicates fronting reverse proxy or load balancer")
                    conf = ConfidenceLevel.MEDIUM.value
                else:
                    conf = ConfidenceLevel.HIGH.value

                fp = InferredFingerprint(
                    service_name=svc_name,
                    product=product,
                    version=version,
                    confidence=conf,
                    uncertainty_reasons=uncertainty_reasons,
                    evidence_sources=["nmap_service_scan"],
                )
            else:
                fp = infer_service_fingerprint(target_host, port_id, proto, obs)

            probe_key = ActiveScanSession.make_probe_key(vantage, proto, target_host, port_id)
            completed_keys.add(probe_key)
            probe_id = hashlib.sha256(f"{probe_key}:{file_hash}".encode("utf-8")).hexdigest()[:24]

            assessments.append(
                ActiveServiceAssessment(
                    probe_id=probe_id,
                    target_host=target_host,
                    resolved_ip=addr_ip,
                    port=port_id,
                    protocol=proto,
                    vantage=vantage,
                    port_state=port_state,
                    reachability=reachability,
                    observed_config=obs,
                    inferred_fingerprint=fp,
                    timestamp_utc=utc_now(),
                    provenance=prov,
                )
            )

    session_id = hashlib.sha256(f"{scope_ref}:{file_hash}".encode("utf-8")).hexdigest()[:16]
    session = ActiveScanSession(
        session_id=session_id,
        scope_reference=scope_ref,
        approved_targets=sorted(targets),
        approved_ports=sorted(ports),
        vantage=vantage,
        budget=ScanBudget(rate_limit_pps=20.0),
        started_at=utc_now(),
        completed_at=utc_now(),
        status="completed",
        completed_probe_keys=completed_keys,
        assessments=assessments,
        total_probes_dispatched=len(assessments),
        total_side_effects=len(assessments),
    )
    return session
