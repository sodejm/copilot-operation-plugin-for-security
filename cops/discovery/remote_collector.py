"""Protocol collectors, offline simulator, and assessment engine for remote admin, file sharing, and printing."""

from __future__ import annotations

import hashlib
import re
import socket
from abc import ABC, abstractmethod
from typing import Any

from .remote_models import (
    CleanupReceipt,
    HostPrivilegeCandidate,
    LateralMovementImpact,
    RemoteAuthPrerequisite,
    RemoteExposureStatus,
    RemoteServiceAssessment,
    RemoteServiceCategory,
    RemoteServicesReport,
    RemoteServiceType,
)

DEFAULT_REMOTE_PORTS: dict[str, tuple[int, str, str]] = {
    # Remote Administration
    RemoteServiceType.SSH.value: (22, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    RemoteServiceType.TELNET.value: (23, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    RemoteServiceType.RDP.value: (3389, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    RemoteServiceType.VNC.value: (5900, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    RemoteServiceType.WINRM.value: (5985, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    RemoteServiceType.X11.value: (6000, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value),
    # File Sharing
    RemoteServiceType.SMB.value: (445, "tcp", RemoteServiceCategory.FILE_SHARING.value),
    RemoteServiceType.NFS.value: (2049, "tcp", RemoteServiceCategory.FILE_SHARING.value),
    RemoteServiceType.FTP.value: (21, "tcp", RemoteServiceCategory.FILE_SHARING.value),
    RemoteServiceType.TFTP.value: (69, "udp", RemoteServiceCategory.FILE_SHARING.value),
    RemoteServiceType.RSYNC.value: (873, "tcp", RemoteServiceCategory.FILE_SHARING.value),
    RemoteServiceType.AFP.value: (548, "tcp", RemoteServiceCategory.FILE_SHARING.value),
    # Printing
    RemoteServiceType.LPD.value: (515, "tcp", RemoteServiceCategory.PRINTING.value),
    RemoteServiceType.IPP.value: (631, "tcp", RemoteServiceCategory.PRINTING.value),
    RemoteServiceType.RAW_PRINT.value: (9100, "tcp", RemoteServiceCategory.PRINTING.value),
}


class RemoteServicesCollector(ABC):
    """Abstract interface for remote administration, file sharing, and print service collectors."""

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
        category: str = RemoteServiceCategory.REMOTE_ADMIN.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> RemoteServiceAssessment:
        """Probe a remote administration, file sharing, or print service."""

    def assess_ssh(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.SSH.value, 22, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_telnet(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.TELNET.value, 23, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_rdp(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.RDP.value, 3389, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_vnc(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.VNC.value, 5900, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_winrm(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.WINRM.value, 5985, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_x11(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.X11.value, 6000, "tcp", RemoteServiceCategory.REMOTE_ADMIN.value, vantage, None, timeout)

    def assess_smb(self, target_host: str, canary_artifact: str | None = "canary_share/audit.tmp", vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.SMB.value, 445, "tcp", RemoteServiceCategory.FILE_SHARING.value, vantage, canary_artifact, timeout)

    def assess_nfs(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.NFS.value, 2049, "tcp", RemoteServiceCategory.FILE_SHARING.value, vantage, None, timeout)

    def assess_ftp(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.FTP.value, 21, "tcp", RemoteServiceCategory.FILE_SHARING.value, vantage, None, timeout)

    def assess_tftp(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.TFTP.value, 69, "udp", RemoteServiceCategory.FILE_SHARING.value, vantage, None, timeout)

    def assess_rsync(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.RSYNC.value, 873, "tcp", RemoteServiceCategory.FILE_SHARING.value, vantage, None, timeout)

    def assess_afp(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.AFP.value, 548, "tcp", RemoteServiceCategory.FILE_SHARING.value, vantage, None, timeout)

    def assess_lpd(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.LPD.value, 515, "tcp", RemoteServiceCategory.PRINTING.value, vantage, None, timeout)

    def assess_ipp(self, target_host: str, canary_artifact: str | None = "canary_print_job_probe", vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.IPP.value, 631, "tcp", RemoteServiceCategory.PRINTING.value, vantage, canary_artifact, timeout)

    def assess_raw_print(self, target_host: str, vantage: str = "external", timeout: float = 2.0) -> RemoteServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, RemoteServiceType.RAW_PRINT.value, 9100, "tcp", RemoteServiceCategory.PRINTING.value, vantage, None, timeout)


class OfflineSyntheticRemoteCollector(RemoteServicesCollector):
    """Deterministic offline synthetic collector for remote admin, file sharing, and print tests."""

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
        category: str = RemoteServiceCategory.REMOTE_ADMIN.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> RemoteServiceAssessment:
        self.probes_dispatched.append({
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
            return RemoteServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=RemoteExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=RemoteAuthPrerequisite.UNKNOWN.value,
                uncertainty_notes=[
                    "Service was inaccessible from probe vantage; this cannot be reported as secure or hardened"
                ],
                error_message="Probe connection timed out or network route unreachable",
            )

        details = dict(svc_data.get("details", {}))
        for k, v in svc_data.items():
            if k not in (
                "details", "vulnerabilities", "versions", "status", "protected",
                "inaccessible", "remediated", "state", "auth_prerequisite", "authentication_required",
            ):
                details.setdefault(k, v)

        # 2. Remediated State Check
        if svc_data.get("remediated"):
            return RemoteServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=RemoteExposureStatus.REMEDIATED.value,
                canary_validated=bool(canary_artifact),
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", RemoteAuthPrerequisite.PUBLIC_KEY.value),
                applicable_versions=svc_data.get("versions", [details.get("version", "Remediated")]),
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified remediated against historical misconfiguration or legacy protocol exposure"
                ],
            )

        # 3. Protected Service Check (Properly configured authentication and hardened boundaries)
        is_protected = svc_data.get("protected", False)
        if service_type == RemoteServiceType.SSH.value and details.get("password_auth") is False and details.get("publickey_auth") is True:
            is_protected = True
        elif service_type == RemoteServiceType.RDP.value and details.get("nla_enabled") is True:
            is_protected = True
        elif service_type == RemoteServiceType.SMB.value and details.get("smb_signing_required") is True and details.get("anonymous_access") is False and details.get("smbv1_enabled") is False:
            is_protected = True
        elif service_type == RemoteServiceType.VNC.value and details.get("auth_required") is True:
            is_protected = True
        elif service_type == RemoteServiceType.WINRM.value and details.get("https_enforced") is True and details.get("basic_auth") is False:
            is_protected = True
        elif service_type == RemoteServiceType.NFS.value and details.get("no_root_squash") is False and details.get("world_accessible") is False:
            is_protected = True
        elif service_type == RemoteServiceType.FTP.value and details.get("anonymous_enabled") is False:
            is_protected = True
        elif service_type == RemoteServiceType.RSYNC.value and details.get("auth_users_required") is True:
            is_protected = True
        elif service_type == RemoteServiceType.AFP.value and details.get("guest_access") is False:
            is_protected = True
        elif service_type in (RemoteServiceType.LPD.value, RemoteServiceType.IPP.value) and details.get("auth_required") is True:
            is_protected = True

        canary_active = bool(
            canary_artifact
            or details.get("canary_verified")
            or details.get("canary_file_accessed")
            or details.get("canary_job_dispatched")
        )

        receipts: list[CleanupReceipt] = []
        if canary_active and canary_artifact:
            receipt_id = hashlib.sha256(f"clean:{target_host}:{service_type}:{canary_artifact}".encode()).hexdigest()[:16]
            receipts.append(
                CleanupReceipt(
                    receipt_id=f"rec-{receipt_id}",
                    target_host=target_host,
                    service_type=service_type,
                    artifact_type="canary_file" if category == RemoteServiceCategory.FILE_SHARING.value else "canary_print_job",
                    artifact_identifier=canary_artifact,
                    action_taken="verified_removed",
                    verified_clean=True,
                )
            )

        if is_protected:
            default_auth = RemoteAuthPrerequisite.USER_PASSWORD.value
            if service_type == RemoteServiceType.SSH.value:
                default_auth = RemoteAuthPrerequisite.PUBLIC_KEY.value
            elif service_type == RemoteServiceType.RDP.value:
                default_auth = RemoteAuthPrerequisite.NLA_REQUIRED.value
            elif service_type in (RemoteServiceType.SMB.value, RemoteServiceType.WINRM.value):
                default_auth = RemoteAuthPrerequisite.KERBEROS.value

            return RemoteServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=RemoteExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", default_auth),
                applicable_versions=svc_data.get("versions", [details.get("version", "Hardened")]),
                is_legacy_or_unencrypted=False,
                configuration_details=details,
                cleanup_receipts=receipts,
                uncertainty_notes=[
                    "Service verified protected against unauthenticated access; authenticated attack vectors not evaluated"
                ],
            )

        # 4. Exposed / Misconfigured Assessment & Host Privilege Handoff
        vulns = list(svc_data.get("vulnerabilities", []))
        applicable_versions = list(svc_data.get("versions", []))
        if not applicable_versions and "version" in details:
            applicable_versions.append(str(details["version"]))
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get("auth_prerequisite", RemoteAuthPrerequisite.NONE.value)
        status = svc_data.get("status", RemoteExposureStatus.EXPOSED.value)
        is_legacy = False
        candidates: list[HostPrivilegeCandidate] = []

        # Protocol Evaluations
        if service_type == RemoteServiceType.SMB.value:
            shares = details.get("shares", [])
            has_smbv1 = details.get("smbv1_enabled", False)
            signing_disabled = details.get("smb_signing_disabled", True) or details.get("smb_signing_required") is False

            if has_smbv1:
                is_legacy = True
                vulns.append("Obsolete SMBv1/CIFS protocol enabled")
                c_id = hashlib.sha256(f"smbv1:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="smb_v1_enabled",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"smbv1_dialect": "NT LM 0.12"},
                    )
                )

            if signing_disabled:
                vulns.append("SMB packet signing not required; vulnerable to NTLM relay attacks")
                c_id = hashlib.sha256(f"smbsign:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="smb_signing_disabled",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.CREDENTIAL_HARVESTING.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"signing_required": False},
                    )
                )

            if shares or not auth_req:
                vulns.append(f"Unauthenticated null/guest session permitted with {len(shares)} accessible shares")
                c_id = hashlib.sha256(f"smbshare:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="smb_unauthenticated_share",
                        auth_prerequisites=RemoteAuthPrerequisite.ANONYMOUS.value,
                        lateral_movement_impact=LateralMovementImpact.DATA_EXFILTRATION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"accessible_shares": shares},
                    )
                )

        elif service_type == RemoteServiceType.TELNET.value:
            is_legacy = True
            vulns.append("Unencrypted plaintext Telnet service accessible")
            c_id = hashlib.sha256(f"telnet:{target_host}:{port}".encode()).hexdigest()[:16]
            candidates.append(
                HostPrivilegeCandidate(
                    candidate_id=f"priv-{c_id}",
                    service_type=service_type,
                    category=category,
                    target_host=target_host,
                    port=port,
                    vantage=vantage,
                    finding_type="telnet_plaintext_exposure",
                    auth_prerequisites=RemoteAuthPrerequisite.USER_PASSWORD.value if auth_req else RemoteAuthPrerequisite.NONE.value,
                    lateral_movement_impact=LateralMovementImpact.CREDENTIAL_HARVESTING.value,
                    applicable_versions=applicable_versions,
                    supporting_evidence={"banner": details.get("banner", "Telnet Service")},
                )
            )

        elif service_type == RemoteServiceType.RDP.value:
            nla_disabled = details.get("nla_enabled") is False or details.get("nla_disabled") is True
            if nla_disabled:
                vulns.append("Remote Desktop exposes pre-authentication login screen without NLA enforcement")
                c_id = hashlib.sha256(f"rdpnla:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="rdp_nla_disabled",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"nla_enforced": False, "security_layer": "RDP/SSL"},
                    )
                )

        elif service_type == RemoteServiceType.VNC.value:
            if not auth_req or details.get("auth_type") in ("none", "None", 1):
                vulns.append("VNC RFB service accessible without authentication")
                c_id = hashlib.sha256(f"vnc:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="vnc_no_auth",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"rfb_version": details.get("rfb_version", "003.008")},
                    )
                )

        elif service_type == RemoteServiceType.WINRM.value:
            if port == 5985 or details.get("https_enforced") is False:
                vulns.append("WinRM management endpoint exposed over unencrypted HTTP (5985)")
                c_id = hashlib.sha256(f"winrm:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="winrm_http_unencrypted",
                        auth_prerequisites=auth_prereq,
                        lateral_movement_impact=LateralMovementImpact.CREDENTIAL_HARVESTING.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"http_scheme": "http", "port": port},
                    )
                )

        elif service_type == RemoteServiceType.X11.value:
            if not auth_req or details.get("auth_required") is False:
                vulns.append("X11 display server open to unauthenticated remote client connections")
                c_id = hashlib.sha256(f"x11:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="x11_open_display",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.COMMAND_EXECUTION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"display": ":0", "vendor": details.get("vendor", "X.Org")},
                    )
                )

        elif service_type == RemoteServiceType.NFS.value:
            exports = details.get("exports", [])
            has_no_root_squash = details.get("no_root_squash", False)
            if has_no_root_squash or exports:
                if has_no_root_squash:
                    vulns.append("NFS export configured with 'no_root_squash' permitting root privilege escalation")
                c_id = hashlib.sha256(f"nfs:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="nfs_no_root_squash" if has_no_root_squash else "nfs_world_export",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.PRIVILEGE_ESCALATION.value if has_no_root_squash else LateralMovementImpact.DATA_EXFILTRATION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"exports": exports, "no_root_squash": has_no_root_squash},
                    )
                )

        elif service_type == RemoteServiceType.FTP.value:
            if details.get("anonymous_login") or not auth_req:
                is_legacy = True
                vulns.append("Unauthenticated anonymous FTP access permitted")
                c_id = hashlib.sha256(f"ftp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ftp_anonymous_login",
                        auth_prerequisites=RemoteAuthPrerequisite.ANONYMOUS.value,
                        lateral_movement_impact=LateralMovementImpact.DATA_EXFILTRATION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"banner": details.get("banner", "220 FTP Server")},
                    )
                )

        elif service_type == RemoteServiceType.RSYNC.value:
            modules = details.get("modules", [])
            if not auth_req or modules:
                vulns.append(f"Rsync daemon exposes {len(modules)} modules without mandatory authentication")
                c_id = hashlib.sha256(f"rsync:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="rsync_open_module",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.DATA_EXFILTRATION.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"modules": modules},
                    )
                )

        elif service_type in (RemoteServiceType.LPD.value, RemoteServiceType.IPP.value, RemoteServiceType.RAW_PRINT.value):
            if not auth_req:
                vulns.append(f"Print service ({service_type.upper()}) accepts unauthenticated print job submissions")
                c_id = hashlib.sha256(f"print:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    HostPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="unauthenticated_printer_queue",
                        auth_prerequisites=RemoteAuthPrerequisite.NONE.value,
                        lateral_movement_impact=LateralMovementImpact.UNAUTHORIZED_PRINTING.value,
                        applicable_versions=applicable_versions,
                        supporting_evidence={"printers": details.get("printers", ["default"])},
                    )
                )

        return RemoteServiceAssessment(
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
            applicable_versions=applicable_versions,
            is_legacy_or_unencrypted=is_legacy,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            host_privilege_candidates=candidates,
            cleanup_receipts=receipts,
        )


class StandardSocketRemoteCollector(RemoteServicesCollector):
    """Standard-library socket probe collector for remote, file, and print services."""

    def resolve_target(self, target_host: str) -> str:
        return socket.gethostbyname(target_host)

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = RemoteServiceCategory.REMOTE_ADMIN.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> RemoteServiceAssessment:
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                return RemoteServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    category=category,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=RemoteExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_artifact),
                    canary_identifier=canary_artifact,
                    authentication_required=None,
                    auth_prerequisite=RemoteAuthPrerequisite.UNKNOWN.value,
                    configuration_details={"socket_connected": True},
                    uncertainty_notes=["TCP connect succeeded; protocol credentials required to verify authentication"],
                )
        except (TimeoutError, ConnectionRefusedError, OSError) as err:
            return RemoteServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=RemoteExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=RemoteAuthPrerequisite.UNKNOWN.value,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


def assess_remote_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: RemoteServicesCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_artifact: str | None = None,
    canary_id: str | None = None,
    timeout: float = 2.0,
) -> RemoteServicesReport:
    """Assess remote administration, file sharing, and print services across approved targets."""
    effective_canary = canary_artifact or canary_id
    if collector is None:
        collector = OfflineSyntheticRemoteCollector()

    selected_services = service_types or list(DEFAULT_REMOTE_PORTS.keys())
    assessments: list[RemoteServiceAssessment] = []
    candidates: list[HostPrivilegeCandidate] = []
    receipts: list[CleanupReceipt] = []

    summary = {
        "total_services": 0,
        "exposed": 0,
        "protected": 0,
        "inaccessible": 0,
        "remediated": 0,
        "misconfigured": 0,
        "privilege_candidates": 0,
        "cleanup_receipts": 0,
    }

    report_id = hashlib.sha256(
        f"{scope_ref}:{sorted(targets)}:{sorted(selected_services)}:{vantage}".encode()
    ).hexdigest()[:16]

    for target in targets:
        try:
            resolved_ip = collector.resolve_target(target)
        except Exception:
            resolved_ip = "unresolved"

        for svc in selected_services:
            if svc not in DEFAULT_REMOTE_PORTS:
                continue

            port, proto, cat = DEFAULT_REMOTE_PORTS[svc]
            assessment = collector.probe_service(
                target_host=target,
                resolved_ip=resolved_ip,
                service_type=svc,
                port=port,
                protocol=proto,
                category=cat,
                vantage=vantage,
                canary_artifact=effective_canary,
                timeout=timeout,
            )

            assessments.append(assessment)
            summary["total_services"] += 1
            summary[assessment.exposure_status] = summary.get(assessment.exposure_status, 0) + 1

            for c in assessment.host_privilege_candidates:
                candidates.append(c)
                summary["privilege_candidates"] += 1

            for r in assessment.cleanup_receipts:
                receipts.append(r)
                summary["cleanup_receipts"] += 1

    return RemoteServicesReport(
        report_id=f"remote-{report_id}",
        scope_reference=scope_ref,
        vantage=vantage,
        services_assessed=assessments,
        host_privilege_candidates=candidates,
        cleanup_receipts=receipts,
        summary=summary,
    )
