"""Infrastructure and identity-facing service collectors, assessment engine, and attack-path extraction."""

from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import time
from typing import Any

from cops.evidence.canonical import utc_now
from .infra_models import (
    AuthPrerequisite,
    IdentityAttackPathCandidate,
    IdentityAttackPathType,
    InfraAssessmentReport,
    InfraServiceAssessment,
    InfraServiceType,
    ServiceExposureStatus,
)
from .models import EvidenceProvenance


class InfraCollector(ABC):
    """Abstract interface for protocol-specific infrastructure collectors."""

    @abstractmethod
    def resolve_target(self, target_host: str) -> str:
        """Resolve target host to IP address."""

    @abstractmethod
    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        vantage: str = "external",
        canary_id: str | None = None,
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        """Probe an infrastructure or identity-facing service."""

    def assess_dns(
        self,
        target_host: str,
        canary_id: str | None = "canary.corp.internal",
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.DNS.value, 53, "udp", vantage, canary_id, timeout)

    def assess_snmp(
        self,
        target_host: str,
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.SNMP.value, 161, "udp", vantage, None, timeout)

    def assess_ntp(
        self,
        target_host: str,
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.NTP.value, 123, "udp", vantage, None, timeout)

    def assess_rpc(
        self,
        target_host: str,
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.RPC.value, 135, "tcp", vantage, None, timeout)

    def assess_ldap(
        self,
        target_host: str,
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.LDAP.value, 389, "tcp", vantage, None, timeout)

    def assess_kerberos(
        self,
        target_host: str,
        canary_id: str | None = "canary-user@CORP.INTERNAL",
        vantage: str = "external",
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, InfraServiceType.KERBEROS.value, 88, "tcp", vantage, canary_id, timeout)


class OfflineSyntheticInfraCollector(InfraCollector):
    """Deterministic offline synthetic collector for infrastructure tests and fixtures."""

    def __init__(
        self,
        targets: dict[str, dict[str, Any]] | None = None,
        service_db: dict[str, dict[str, Any]] | None = None,
        dns_map: dict[str, str] | None = None,
    ) -> None:
        self.targets = targets or service_db or {}
        self.dns_map = dns_map or {}
        self.probes_dispatched: list[dict[str, Any]] = []

    def resolve_target(self, target_host: str) -> str:
        if target_host in self.dns_map:
            return self.dns_map[target_host]
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_host):
            return target_host
        h = hashlib.sha256(target_host.encode("utf-8")).hexdigest()
        return f"198.51.100.{int(h[:2], 16) % 250 + 1}"

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        vantage: str = "external",
        canary_id: str | None = None,
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        self.probes_dispatched.append({
            "target_host": target_host,
            "resolved_ip": resolved_ip,
            "service_type": service_type,
            "port": port,
            "protocol": protocol,
            "vantage": vantage,
            "canary_id": canary_id,
        })

        t_data = self.targets.get(target_host) or self.targets.get(resolved_ip) or {}
        svc_data = t_data.get(service_type) or t_data.get(f"{service_type}:{port}")

        # 1. Inaccessible Check (Crucial Truth Boundary: Inaccessible != Secure)
        if (
            svc_data is None
            or t_data.get("unreachable")
            or svc_data.get("inaccessible")
            or svc_data.get("state") in ("filtered", "closed", "timeout")
        ):
            return InfraServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=ServiceExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_id,
                authentication_required=None,
                auth_prerequisite=AuthPrerequisite.UNKNOWN.value,
                uncertainty_notes=[
                    "Service was inaccessible from probe vantage; this cannot be reported as secure or hardened"
                ],
                error_message="Probe connection timed out or network route unreachable",
            )

        details = dict(svc_data.get("details", {}))
        for k, v in svc_data.items():
            if k not in (
                "details",
                "vulnerabilities",
                "versions",
                "status",
                "protected",
                "inaccessible",
                "state",
                "auth_prerequisite",
                "authentication_required",
            ):
                details.setdefault(k, v)

        # 2. Protected Service Check (Service actively enforces authentication and denies unauthenticated access)
        is_explicitly_protected = svc_data.get("protected", False)
        if service_type == InfraServiceType.LDAP.value and details.get("anonymous_root_dse") is False:
            is_explicitly_protected = True
        elif service_type == InfraServiceType.KERBEROS.value and (
            details.get("preauth_disabled_accounts") == [] and not svc_data.get("asrep_roastable")
        ):
            is_explicitly_protected = True
        elif service_type == InfraServiceType.DNS.value and details.get("open_recursion") is False:
            is_explicitly_protected = True
        elif service_type == InfraServiceType.NTP.value and details.get("monlist_enabled") is False:
            is_explicitly_protected = True
        elif service_type == InfraServiceType.SNMP.value and details.get("community_strings") == []:
            is_explicitly_protected = True
        elif service_type == InfraServiceType.RPC.value and details.get("interfaces") == []:
            is_explicitly_protected = True

        canary_active = bool(
            canary_id
            or details.get("canary_resolved")
            or details.get("canary_user_preauth_required")
        )

        if is_explicitly_protected:
            versions = svc_data.get("versions") or [details.get("version", "Standard")]
            return InfraServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=ServiceExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_id,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", AuthPrerequisite.DOMAIN_USER.value),
                applicable_versions=versions,
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified protected against unauthenticated access; authenticated attack vectors not evaluated"
                ],
            )

        # 3. Protocol-Specific Exposed / Misconfigured Behaviors
        vulns = list(svc_data.get("vulnerabilities", []))
        applicable_versions = list(svc_data.get("versions", []))
        if not applicable_versions and "version" in details:
            applicable_versions.append(str(details["version"]))
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get("auth_prerequisite", AuthPrerequisite.NONE.value)
        status = svc_data.get("status", ServiceExposureStatus.EXPOSED.value)
        candidates: list[IdentityAttackPathCandidate] = []

        if service_type == InfraServiceType.LDAP.value:
            if details.get("anonymous_root_dse") or not auth_req:
                status = ServiceExposureStatus.EXPOSED.value
                auth_prereq = AuthPrerequisite.NONE.value
                vulns.append("Unauthenticated LDAP anonymous bind permitted")
                domain = details.get("defaultNamingContext") or (
                    details.get("naming_contexts", ["DC=corp,DC=internal"])[0]
                )
                candidate_id = hashlib.sha256(f"ldap:{target_host}:{port}:{domain}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    IdentityAttackPathCandidate(
                        candidate_id=f"cand-{candidate_id}",
                        service_type=service_type,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        attack_path_type=IdentityAttackPathType.LDAP_ANONYMOUS_RECONNAISSANCE.value,
                        auth_prerequisites=AuthPrerequisite.NONE.value,
                        ad_domain_realm=domain,
                        applicable_versions=applicable_versions,
                        supporting_evidence={
                            "rootDSE": details,
                            "anonymous_bind_succeeded": True,
                        },
                    )
                )

        elif service_type == InfraServiceType.KERBEROS.value:
            realm = details.get("realm", "CORP.INTERNAL")
            preauth_disabled = details.get("preauth_disabled_accounts", [])
            if preauth_disabled or svc_data.get("asrep_roastable"):
                status = ServiceExposureStatus.EXPOSED.value
                auth_prereq = AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value
                vulns.append("Kerberos pre-authentication disabled for one or more accounts")
                for acc in (preauth_disabled or ["vulnerable_account"]):
                    principal = f"{acc}@{realm}" if "@" not in acc else acc
                    candidate_id = hashlib.sha256(f"krb:{target_host}:{port}:{principal}".encode("utf-8")).hexdigest()[:16]
                    candidates.append(
                        IdentityAttackPathCandidate(
                            candidate_id=f"cand-{candidate_id}",
                            service_type=service_type,
                            target_host=target_host,
                            port=port,
                            vantage=vantage,
                            attack_path_type=IdentityAttackPathType.ASREP_ROASTING.value,
                            auth_prerequisites=AuthPrerequisite.KERBEROS_PREAUTH_DISABLED.value,
                            target_principal=principal,
                            ad_domain_realm=realm,
                            applicable_versions=applicable_versions,
                            supporting_evidence={
                                "realm": realm,
                                "account": acc,
                                "asrep_roastable": True,
                            },
                        )
                    )

        elif service_type == InfraServiceType.RPC.value:
            interfaces = details.get("interfaces") or details.get("registered_interfaces", [])
            if interfaces:
                status = ServiceExposureStatus.EXPOSED.value
                auth_prereq = AuthPrerequisite.NONE.value
                vulns.append(f"RPC Endpoint Mapper discloses {len(interfaces)} registered interfaces without authentication")
                candidate_id = hashlib.sha256(f"rpc:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    IdentityAttackPathCandidate(
                        candidate_id=f"cand-{candidate_id}",
                        service_type=service_type,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        attack_path_type=IdentityAttackPathType.RPC_ENDPOINT_ENUMERATION.value,
                        auth_prerequisites=AuthPrerequisite.NONE.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"interfaces": interfaces},
                    )
                )

        elif service_type == InfraServiceType.SNMP.value:
            comm_list = details.get("community_strings") or (
                [details["community_string"]] if "community_string" in details else ["public"]
            )
            default_comm = [c for c in comm_list if c in ("public", "private", "default")]
            if default_comm:
                status = ServiceExposureStatus.EXPOSED.value
                auth_prereq = AuthPrerequisite.DEFAULT_CREDENTIALS.value
                vulns.append(f"SNMP agent accessible via default community strings: {', '.join(default_comm)}")
                candidate_id = hashlib.sha256(f"snmp:{target_host}:{port}:{default_comm[0]}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    IdentityAttackPathCandidate(
                        candidate_id=f"cand-{candidate_id}",
                        service_type=service_type,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        attack_path_type=IdentityAttackPathType.SNMP_CREDENTIAL_LEAK.value,
                        auth_prerequisites=AuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={
                            "community_strings": default_comm,
                            "sys_descr": details.get("sys_descr") or details.get("sysDescr"),
                        },
                    )
                )

        elif service_type == InfraServiceType.DNS.value:
            if details.get("open_recursion"):
                status = ServiceExposureStatus.MISCONFIGURED.value
                auth_prereq = AuthPrerequisite.NONE.value
                vulns.append("DNS resolver permits open recursion from external vantage")
                candidate_id = hashlib.sha256(f"dns:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    IdentityAttackPathCandidate(
                        candidate_id=f"cand-{candidate_id}",
                        service_type=service_type,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        attack_path_type=IdentityAttackPathType.OPEN_DNS_RECURSION.value,
                        auth_prerequisites=AuthPrerequisite.NONE.value,
                        supporting_evidence={"recursion_test": "succeeded"},
                    )
                )

        elif service_type == InfraServiceType.NTP.value:
            if details.get("monlist_enabled"):
                status = ServiceExposureStatus.MISCONFIGURED.value
                auth_prereq = AuthPrerequisite.NONE.value
                vulns.append("NTP daemon responds to Mode 6 / monlist enumeration queries")
                candidate_id = hashlib.sha256(f"ntp:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    IdentityAttackPathCandidate(
                        candidate_id=f"cand-{candidate_id}",
                        service_type=service_type,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        attack_path_type=IdentityAttackPathType.NTP_MODE6_AMPLIFICATION.value,
                        auth_prerequisites=AuthPrerequisite.NONE.value,
                        supporting_evidence={"monlist_amplification_factor": details.get("amplification_factor", 10.0)},
                    )
                )

        return InfraServiceAssessment(
            target_host=target_host,
            resolved_ip=resolved_ip,
            service_type=service_type,
            port=port,
            protocol=protocol,
            vantage=vantage,
            exposure_status=status,
            canary_validated=canary_active,
            canary_identifier=canary_id,
            authentication_required=auth_req,
            auth_prerequisite=auth_prereq,
            applicable_versions=applicable_versions,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            attack_path_candidate=candidates[0] if candidates else None,
            candidates_list=candidates,
        )


class StandardSocketInfraCollector(InfraCollector):
    """Standard-library live TCP socket collector for infrastructure and identity service probes."""

    def resolve_target(self, target_host: str) -> str:
        return socket.gethostbyname(target_host)

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        vantage: str = "external",
        canary_id: str | None = None,
        timeout: float = 2.0,
    ) -> InfraServiceAssessment:
        # Standard socket connect probe
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                # Service is reachable; report observed connection
                return InfraServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=ServiceExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_id),
                    canary_identifier=canary_id,
                    authentication_required=None,
                    auth_prerequisite=AuthPrerequisite.UNKNOWN.value,
                    configuration_details={"socket_connected": True},
                    uncertainty_notes=["Service reachable via TCP; protocol-specific authentication check requires credentials"],
                )
        except (socket.timeout, ConnectionRefusedError, OSError) as err:
            return InfraServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=ServiceExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_id,
                authentication_required=None,
                auth_prerequisite=AuthPrerequisite.UNKNOWN.value,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


DEFAULT_INFRA_PORTS: dict[str, tuple[int, str]] = {
    InfraServiceType.DNS.value: (53, "udp"),
    InfraServiceType.MDNS.value: (5353, "udp"),
    InfraServiceType.SNMP.value: (161, "udp"),
    InfraServiceType.NTP.value: (123, "udp"),
    InfraServiceType.RPC.value: (135, "tcp"),
    InfraServiceType.LDAP.value: (389, "tcp"),
    InfraServiceType.KERBEROS.value: (88, "tcp"),
    InfraServiceType.DISCOVERY.value: (137, "udp"),
}


def assess_infrastructure_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: InfraCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_id: str | None = None,
    timeout: float = 2.0,
) -> InfraAssessmentReport:
    """Assess infrastructure and identity-facing services across approved targets."""
    if collector is None:
        collector = OfflineSyntheticInfraCollector()

    selected_services = service_types or list(DEFAULT_INFRA_PORTS.keys())
    assessments: list[InfraServiceAssessment] = []
    candidates: list[IdentityAttackPathCandidate] = []

    summary = {
        "total_services": 0,
        "exposed": 0,
        "protected": 0,
        "inaccessible": 0,
        "misconfigured": 0,
        "attack_path_candidates": 0,
    }

    report_id = hashlib.sha256(f"{scope_ref}:{sorted(targets)}:{sorted(selected_services)}:{vantage}".encode("utf-8")).hexdigest()[:16]

    for target in targets:
        try:
            resolved_ip = collector.resolve_target(target)
        except Exception:
            resolved_ip = "unresolved"

        for svc in selected_services:
            if svc not in DEFAULT_INFRA_PORTS:
                continue

            port, proto = DEFAULT_INFRA_PORTS[svc]
            assessment = collector.probe_service(
                target_host=target,
                resolved_ip=resolved_ip,
                service_type=svc,
                port=port,
                protocol=proto,
                vantage=vantage,
                canary_id=canary_id,
                timeout=timeout,
            )

            assessments.append(assessment)
            summary["total_services"] += 1
            summary[assessment.exposure_status] = summary.get(assessment.exposure_status, 0) + 1

            for cand in assessment.attack_path_candidates:
                candidates.append(cand)
                summary["attack_path_candidates"] += 1

    return InfraAssessmentReport(
        report_id=f"infra-{report_id}",
        scope_reference=scope_ref,
        vantage=vantage,
        services_assessed=assessments,
        attack_path_candidates=candidates,
        summary=summary,
    )
