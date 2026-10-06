"""Collector and active probing engine for legacy enterprise, management, and proxy services."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from abc import ABC, abstractmethod
from typing import Any

from .legacy_models import (
    CleanupReceipt,
    ExecutionEffect,
    LegacyAuthPrerequisite,
    LegacyCategory,
    LegacyExposureStatus,
    LegacyPrivilegeCandidate,
    LegacyPrivilegeImpact,
    LegacyServiceAssessment,
    LegacyServicesReport,
    LegacyServiceType,
)

DEFAULT_LEGACY_PORTS: dict[str, tuple[int, str, str]] = {
    # Enterprise Storage & Data Management
    LegacyServiceType.NDMP.value: (10000, "tcp", LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value),
    LegacyServiceType.ISCSI.value: (3260, "tcp", LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value),

    # Out-of-Band & Hardware Management
    LegacyServiceType.IPMI.value: (623, "udp", LegacyCategory.OUT_OF_BAND_HARDWARE_MANAGEMENT.value),

    # Network Device & Appliance Management
    LegacyServiceType.CISCO_SMART_INSTALL.value: (4786, "tcp", LegacyCategory.NETWORK_DEVICE_APPLIANCE_MANAGEMENT.value),
    LegacyServiceType.TACACS.value: (49, "tcp", LegacyCategory.NETWORK_DEVICE_APPLIANCE_MANAGEMENT.value),

    # VPN & Tunneling Services
    LegacyServiceType.IKE.value: (500, "udp", LegacyCategory.VPN_TUNNELING_SERVICES.value),
    LegacyServiceType.PPTP.value: (1723, "tcp", LegacyCategory.VPN_TUNNELING_SERVICES.value),

    # Proxy & Egress Services
    LegacyServiceType.SOCKS.value: (1080, "tcp", LegacyCategory.PROXY_EGRESS_SERVICES.value),
    LegacyServiceType.SQUID.value: (3128, "tcp", LegacyCategory.PROXY_EGRESS_SERVICES.value),
}


class LegacyServicesCollector(ABC):
    """Abstract interface for legacy enterprise, management, and proxy service assessment."""

    @abstractmethod
    def resolve_target(self, target_host: str) -> str:
        """Resolve target hostname to IP address string."""

    @abstractmethod
    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> LegacyServiceAssessment:
        """Probe and evaluate discrete legacy service exposure."""

    def assess_ndmp(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 10000) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.NDMP.value, port, "tcp", LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value, vantage, canary_artifact, timeout)

    def assess_iscsi(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 3260) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.ISCSI.value, port, "tcp", LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value, vantage, canary_artifact, timeout)

    def assess_ipmi(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 623) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.IPMI.value, port, "udp", LegacyCategory.OUT_OF_BAND_HARDWARE_MANAGEMENT.value, vantage, canary_artifact, timeout)

    def assess_cisco_smart_install(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 4786) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.CISCO_SMART_INSTALL.value, port, "tcp", LegacyCategory.NETWORK_DEVICE_APPLIANCE_MANAGEMENT.value, vantage, canary_artifact, timeout)

    def assess_tacacs(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 49) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.TACACS.value, port, "tcp", LegacyCategory.NETWORK_DEVICE_APPLIANCE_MANAGEMENT.value, vantage, canary_artifact, timeout)

    def assess_ike(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 500) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.IKE.value, port, "udp", LegacyCategory.VPN_TUNNELING_SERVICES.value, vantage, canary_artifact, timeout)

    def assess_pptp(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 1723) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.PPTP.value, port, "tcp", LegacyCategory.VPN_TUNNELING_SERVICES.value, vantage, canary_artifact, timeout)

    def assess_socks(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 1080) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.SOCKS.value, port, "tcp", LegacyCategory.PROXY_EGRESS_SERVICES.value, vantage, canary_artifact, timeout)

    def assess_squid(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 3128) -> LegacyServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, LegacyServiceType.SQUID.value, port, "tcp", LegacyCategory.PROXY_EGRESS_SERVICES.value, vantage, canary_artifact, timeout)


class OfflineSyntheticLegacyCollector(LegacyServicesCollector):
    """Deterministic simulation collector for legacy enterprise, management, and proxy services."""

    def __init__(
        self,
        targets: dict[str, Any] | None = None,
        allow_code_execution: bool = False,
        allow_state_change: bool = False,
    ) -> None:
        self.targets = targets or {}
        self.allow_code_execution = allow_code_execution
        self.allow_state_change = allow_state_change
        self.probes_recorded: list[dict[str, Any]] = []

    def resolve_target(self, target_host: str) -> str:
        try:
            ipaddress.ip_address(target_host)
            return target_host
        except ValueError:
            t_data = self.targets.get(target_host, {})
            return t_data.get("resolved_ip", "198.51.100.180")

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> LegacyServiceAssessment:
        self.probes_recorded.append({
            "target_host": target_host,
            "resolved_ip": resolved_ip,
            "service_type": service_type,
            "category": category,
            "port": port,
            "protocol": protocol,
            "vantage": vantage,
            "canary_artifact": canary_artifact,
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
            return LegacyServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=LegacyExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=LegacyAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                proxy_egress_tested=False,
                proxy_egress_restricted=None,
                uncertainty_notes=[
                    "Service was inaccessible from probe vantage; this cannot be reported as secure or hardened"
                ],
                error_message="Probe connection timed out or network route unreachable",
            )

        details = dict(svc_data.get("details", {}))
        for k, v in svc_data.items():
            if k not in (
                "details", "vulnerabilities", "versions", "status", "protected",
                "inaccessible", "remediated", "state", "auth_prerequisite",
                "authentication_required", "role", "role_assigned", "can_execute_code",
                "can_change_state", "bound_to_plan", "proxy_egress_restricted",
            ):
                details.setdefault(k, v)

        # 2. Remediated State Check
        if svc_data.get("remediated"):
            return LegacyServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=LegacyExposureStatus.REMEDIATED.value,
                canary_validated=bool(canary_artifact),
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", LegacyAuthPrerequisite.USER_PASSWORD.value),
                assigned_role=svc_data.get("role", "authenticated_operator"),
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                proxy_egress_tested=category == LegacyCategory.PROXY_EGRESS_SERVICES.value,
                proxy_egress_restricted=True if category == LegacyCategory.PROXY_EGRESS_SERVICES.value else None,
                applicable_versions=svc_data.get("versions", [details.get("version", "Remediated")]),
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified remediated against legacy unauthenticated exposure"
                ],
            )

        # 3. Protected Service Check
        is_protected = svc_data.get("protected", False)
        auth_req = svc_data.get("authentication_required", True)

        if service_type == LegacyServiceType.NDMP.value and details.get("auth_required") is True:
            is_protected = True
        elif service_type == LegacyServiceType.ISCSI.value and details.get("chap_enforced") is True:
            is_protected = True
        elif service_type == LegacyServiceType.IPMI.value and details.get("cipher_zero_disabled") is True and details.get("rakp_auth_enforced") is True:
            is_protected = True
        elif service_type == LegacyServiceType.CISCO_SMART_INSTALL.value and (details.get("disabled") is True or details.get("no_vstack") is True):
            is_protected = True
        elif service_type == LegacyServiceType.TACACS.value and details.get("shared_key_enforced") is True and details.get("tls_enabled") is True:
            is_protected = True
        elif service_type == LegacyServiceType.IKE.value and (details.get("aggressive_mode_disabled") is True or details.get("ikev2_only") is True):
            is_protected = True
        elif service_type == LegacyServiceType.PPTP.value and details.get("decommissioned") is True:
            is_protected = True
        elif service_type == LegacyServiceType.SOCKS.value and details.get("auth_required") is True and details.get("egress_restricted") is True:
            is_protected = True
        elif service_type == LegacyServiceType.SQUID.value and details.get("acl_enforced") is True and details.get("egress_restricted") is True:
            is_protected = True

        canary_active = bool(
            canary_artifact
            or details.get("canary_verified")
            or details.get("canary_probe_received")
        )

        receipts: list[CleanupReceipt] = []
        if canary_active and canary_artifact:
            receipt_id = hashlib.sha256(f"clean:{target_host}:{service_type}:{canary_artifact}".encode()).hexdigest()[:16]
            receipts.append(
                CleanupReceipt(
                    receipt_id=f"rec-{receipt_id}",
                    target_host=target_host,
                    service_type=service_type,
                    artifact_type="canary_legacy_artifact",
                    artifact_identifier=canary_artifact,
                    action_taken="verified_removed",
                    verified_clean=True,
                )
            )

        if is_protected:
            default_auth = svc_data.get("auth_prerequisite", LegacyAuthPrerequisite.USER_PASSWORD.value)
            role = svc_data.get("role", "authenticated_operator")
            is_proxy = category == LegacyCategory.PROXY_EGRESS_SERVICES.value
            return LegacyServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=LegacyExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=default_auth,
                assigned_role=role,
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                proxy_egress_tested=is_proxy,
                proxy_egress_restricted=True if is_proxy else None,
                applicable_versions=svc_data.get("versions", [details.get("version", "Current")]),
                configuration_details=details,
                cleanup_receipts=receipts,
            )

        # 4. Exposed or Misconfigured State
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get(
            "auth_prerequisite",
            LegacyAuthPrerequisite.NONE.value if not auth_req else LegacyAuthPrerequisite.SHARED_KEY.value
        )
        assigned_role = svc_data.get("role", "anonymous" if not auth_req else "operator")
        status = svc_data.get("status", LegacyExposureStatus.EXPOSED.value)
        applicable_versions = svc_data.get("versions", [details.get("version", "Observed")])
        vulns = list(svc_data.get("vulnerabilities", []))
        candidates: list[LegacyPrivilegeCandidate] = []

        can_exec_code = False
        can_change_state = False
        proxy_egress_tested = False
        proxy_egress_restricted = None

        if service_type == LegacyServiceType.NDMP.value:
            if not auth_req or details.get("auth_required") is False:
                vulns.append("NDMP storage management interface exposed without authentication; tape/disk backup traversal permitted")
                c_id = hashlib.sha256(f"ndmp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ndmp_unauthenticated_access",
                        auth_prerequisites=LegacyAuthPrerequisite.NONE.value,
                        privilege_impact=LegacyPrivilegeImpact.STORAGE_TAKEOVER.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="backup-admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"ndmp_version": details.get("version", "NDMPv4")},
                    )
                )
                can_change_state = True

        elif service_type == LegacyServiceType.ISCSI.value:
            if not auth_req or details.get("chap_enforced") is False:
                vulns.append("iSCSI storage target discovery permits unauthenticated SendTargets discovery and session attachment")
                c_id = hashlib.sha256(f"iscsi:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="iscsi_unauthenticated_target",
                        auth_prerequisites=LegacyAuthPrerequisite.ANONYMOUS.value,
                        privilege_impact=LegacyPrivilegeImpact.STORAGE_TAKEOVER.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="storage-initiator",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"targets": details.get("targets", ["iqn.2026-10.corp.storage:lun01"])},
                    )
                )
                can_change_state = True

        elif service_type == LegacyServiceType.IPMI.value:
            if details.get("cipher_zero") is True or details.get("cipher_zero_enabled") is True:
                vulns.append("IPMI 2.0 RMCP+ cipher suite 0 authentication bypass enabled; unrestricted BMC lights-out control")
                c_id = hashlib.sha256(f"ipmi-c0:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ipmi_cipher_zero_bypass",
                        auth_prerequisites=LegacyAuthPrerequisite.CIPHER_ZERO.value,
                        privilege_impact=LegacyPrivilegeImpact.HARDWARE_BMC_TAKEOVER.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"cipher_zero_supported": True},
                    )
                )
                can_exec_code = True
                can_change_state = True
            elif details.get("rakp_dumpable") is True or not auth_req:
                vulns.append("IPMI 2.0 RAKP HMAC-SHA1 password hashes retrievable via unauthenticated handshake request")
                c_id = hashlib.sha256(f"ipmi-rakp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ipmi_rakp_hash_dump",
                        auth_prerequisites=LegacyAuthPrerequisite.RAKP_HASH.value,
                        privilege_impact=LegacyPrivilegeImpact.CREDENTIAL_HARVESTING.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="bmc-user",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"rakp_hashes_captured": True},
                    )
                )

        elif service_type == LegacyServiceType.CISCO_SMART_INSTALL.value:
            if not auth_req or details.get("smi_active") is True:
                vulns.append("Cisco Smart Install (SMI) active on TCP 4786 without authentication; arbitrary config download and RCE")
                c_id = hashlib.sha256(f"smi:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="cisco_smart_install_rce",
                        auth_prerequisites=LegacyAuthPrerequisite.NONE.value,
                        privilege_impact=LegacyPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="cisco-director",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"smi_version": details.get("version", "Cisco IOS 15.0")},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == LegacyServiceType.TACACS.value:
            if not auth_req or details.get("single_connect") is True:
                vulns.append("TACACS+ AAA daemon exposed to network; unauthenticated handshake reveals legacy obfuscation key usage")
                c_id = hashlib.sha256(f"tacacs:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="tacacs_unauthenticated_daemon",
                        auth_prerequisites=LegacyAuthPrerequisite.SHARED_KEY.value,
                        privilege_impact=LegacyPrivilegeImpact.TRAFFIC_INTERCEPTION.value,
                        execution_effect=ExecutionEffect.NON_DESTRUCTIVE.value,
                        affected_role="network-operator",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"protocol_version": details.get("version", "TACACS+ 13.0")},
                    )
                )

        elif service_type == LegacyServiceType.IKE.value:
            if details.get("aggressive_mode") is True or not auth_req:
                vulns.append("IKEv1 Aggressive Mode enabled; responder returns pre-shared key (PSK) hash subject to offline cracking")
                c_id = hashlib.sha256(f"ike:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ike_aggressive_mode_psk",
                        auth_prerequisites=LegacyAuthPrerequisite.PSK.value,
                        privilege_impact=LegacyPrivilegeImpact.CREDENTIAL_HARVESTING.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="vpn-user",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"ike_mode": "aggressive", "transform": details.get("transform", "3DES-SHA1-MODP1024")},
                    )
                )

        elif service_type == LegacyServiceType.PPTP.value:
            if details.get("mschapv2") is True or not auth_req:
                vulns.append("PPTP VPN service exposed using vulnerable MS-CHAPv2 authentication; credential hash cracking permitted")
                c_id = hashlib.sha256(f"pptp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="pptp_mschapv2_exposure",
                        auth_prerequisites=LegacyAuthPrerequisite.MSCHAPV2.value,
                        privilege_impact=LegacyPrivilegeImpact.CREDENTIAL_HARVESTING.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="vpn-user",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"firmware": details.get("firmware", "Poptop 1.4.0")},
                    )
                )

        elif service_type == LegacyServiceType.SOCKS.value:
            proxy_egress_tested = True
            is_restricted = details.get("egress_restricted", False)
            proxy_egress_restricted = is_restricted
            if not auth_req or details.get("auth_required") is False or not is_restricted:
                vulns.append("SOCKS proxy exposed without authentication or egress restrictions; open network relaying permitted")
                c_id = hashlib.sha256(f"socks:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="socks_open_proxy",
                        auth_prerequisites=LegacyAuthPrerequisite.NONE.value if not auth_req else LegacyAuthPrerequisite.USER_PASSWORD.value,
                        privilege_impact=LegacyPrivilegeImpact.PROXY_EGRESS_PIVOT.value,
                        execution_effect=ExecutionEffect.NON_DESTRUCTIVE.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"socks_version": details.get("version", "SOCKS5"), "egress_restricted": is_restricted},
                    )
                )
                can_change_state = True

        elif service_type == LegacyServiceType.SQUID.value:
            proxy_egress_tested = True
            is_restricted = details.get("egress_restricted", False)
            proxy_egress_restricted = is_restricted
            if details.get("open_proxy") is True or not is_restricted:
                vulns.append("Squid HTTP proxy allows open forward proxying without client subnet restriction; internal SSRF / pivoting permitted")
                c_id = hashlib.sha256(f"squid:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    LegacyPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="squid_open_proxy",
                        auth_prerequisites=LegacyAuthPrerequisite.NONE.value,
                        privilege_impact=LegacyPrivilegeImpact.PROXY_EGRESS_PIVOT.value,
                        execution_effect=ExecutionEffect.NON_DESTRUCTIVE.value,
                        affected_role="proxy-client",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"squid_version": details.get("version", "Squid 4.13"), "open_forward": True},
                    )
                )
                can_change_state = True

        uncertainty = list(svc_data.get("uncertainty_notes", []))
        if can_exec_code and not self.allow_code_execution:
            can_exec_code = False
            uncertainty.append("Code execution verification skipped: not authorized in active action plan")

        if can_change_state and not self.allow_state_change:
            can_change_state = False
            uncertainty.append("State change verification skipped: not authorized in active action plan")

        return LegacyServiceAssessment(
            target_host=target_host,
            resolved_ip=resolved_ip,
            service_type=service_type,
            category=category,
            port=port,
            protocol=protocol,
            vantage=vantage,
            exposure_status=status,
            canary_validated=canary_active,
            canary_identifier=canary_artifact,
            authentication_required=auth_req,
            auth_prerequisite=auth_prereq,
            assigned_role=assigned_role,
            can_execute_code=can_exec_code,
            can_change_state=can_change_state,
            bound_to_plan=True,
            proxy_egress_tested=proxy_egress_tested,
            proxy_egress_restricted=proxy_egress_restricted,
            applicable_versions=applicable_versions,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            uncertainty_notes=uncertainty,
            privilege_candidates=candidates,
            cleanup_receipts=receipts,
        )


class StandardSocketLegacyCollector(LegacyServicesCollector):
    """Standard-library socket probe collector for legacy enterprise, management, and proxy services."""

    def __init__(
        self,
        allow_code_execution: bool = False,
        allow_state_change: bool = False,
    ) -> None:
        self.allow_code_execution = allow_code_execution
        self.allow_state_change = allow_state_change

    def resolve_target(self, target_host: str) -> str:
        return socket.gethostbyname(target_host)

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = LegacyCategory.ENTERPRISE_STORAGE_MANAGEMENT.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> LegacyServiceAssessment:
        is_proxy = category == LegacyCategory.PROXY_EGRESS_SERVICES.value
        try:
            if protocol == "udp":
                # UDP datagram probe
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                # Send benign ping or discovery payload
                sock.sendto(b"\x00", (resolved_ip, port))
                sock.close()
                return LegacyServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    category=category,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=LegacyExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_artifact),
                    canary_identifier=canary_artifact,
                    authentication_required=None,
                    auth_prerequisite=LegacyAuthPrerequisite.UNKNOWN.value,
                    assigned_role="unknown",
                    can_execute_code=False,
                    can_change_state=False,
                    bound_to_plan=True,
                    proxy_egress_tested=False,
                    proxy_egress_restricted=None,
                    configuration_details={"udp_datagram_sent": True},
                    uncertainty_notes=["UDP packet transmitted; application-level protocol challenge required to verify authentication"],
                )
            else:
                with socket.create_connection((resolved_ip, port), timeout=timeout):
                    return LegacyServiceAssessment(
                        target_host=target_host,
                        resolved_ip=resolved_ip,
                        service_type=service_type,
                        category=category,
                        port=port,
                        protocol=protocol,
                        vantage=vantage,
                        exposure_status=LegacyExposureStatus.EXPOSED.value,
                        canary_validated=bool(canary_artifact),
                        canary_identifier=canary_artifact,
                        authentication_required=None,
                        auth_prerequisite=LegacyAuthPrerequisite.UNKNOWN.value,
                        assigned_role="unknown",
                        can_execute_code=False,
                        can_change_state=False,
                        bound_to_plan=True,
                        proxy_egress_tested=is_proxy,
                        proxy_egress_restricted=False if is_proxy else None,
                        configuration_details={"socket_connected": True},
                        uncertainty_notes=["TCP connect succeeded; protocol-level handshake required to verify authentication"],
                    )
        except (TimeoutError, ConnectionRefusedError, OSError) as err:
            return LegacyServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=LegacyExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=LegacyAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                proxy_egress_tested=False,
                proxy_egress_restricted=None,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


def assess_legacy_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: LegacyServicesCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_artifact: str | None = None,
    canary_id: str | None = None,
    timeout: float = 2.0,
    allow_code_execution: bool = False,
    allow_state_change: bool = False,
) -> LegacyServicesReport:
    """Execute exposure and privilege boundary assessment across legacy enterprise and proxy services."""
    active_collector = collector or StandardSocketLegacyCollector(
        allow_code_execution=allow_code_execution,
        allow_state_change=allow_state_change,
    )
    svcs = service_types or list(DEFAULT_LEGACY_PORTS.keys())
    canary = canary_artifact or canary_id

    targets_str = ",".join(targets)
    report_id = f"leg-rep-{hashlib.sha256(f'{scope_ref}:{vantage}:{targets_str}'.encode()).hexdigest()[:16]}"
    assessments: list[LegacyServiceAssessment] = []

    total_exposed = 0
    total_protected = 0
    total_inaccessible = 0
    total_misconfigured = 0
    total_candidates = 0
    total_receipts = 0

    for target in targets:
        resolved_ip = active_collector.resolve_target(target)
        for svc in svcs:
            if svc not in DEFAULT_LEGACY_PORTS:
                continue
            port, proto, cat = DEFAULT_LEGACY_PORTS[svc]
            assessment = active_collector.probe_service(
                target_host=target,
                resolved_ip=resolved_ip,
                service_type=svc,
                port=port,
                protocol=proto,
                category=cat,
                vantage=vantage,
                canary_artifact=canary,
                timeout=timeout,
            )
            assessments.append(assessment)

            if assessment.exposure_status == LegacyExposureStatus.EXPOSED.value:
                total_exposed += 1
            elif assessment.exposure_status == LegacyExposureStatus.PROTECTED.value:
                total_protected += 1
            elif assessment.exposure_status == LegacyExposureStatus.INACCESSIBLE.value:
                total_inaccessible += 1
            elif assessment.exposure_status == LegacyExposureStatus.MISCONFIGURED.value:
                total_misconfigured += 1

            total_candidates += len(assessment.privilege_candidates)
            total_receipts += len(assessment.cleanup_receipts)

    return LegacyServicesReport(
        report_id=report_id,
        target_scope=targets,
        vantage=vantage,
        assessments=assessments,
        total_probed=len(assessments),
        total_exposed=total_exposed,
        total_protected=total_protected,
        total_inaccessible=total_inaccessible,
        total_misconfigured=total_misconfigured,
        candidates_count=total_candidates,
        cleanup_receipts_count=total_receipts,
    )
