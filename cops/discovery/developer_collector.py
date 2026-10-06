"""Collectors and evaluators for developer and runtime interfaces."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from abc import ABC, abstractmethod
from typing import Any

from .developer_models import (
    CleanupReceipt,
    DeveloperAuthPrerequisite,
    DeveloperCategory,
    DeveloperExposureStatus,
    DeveloperPrivilegeCandidate,
    DeveloperPrivilegeImpact,
    DeveloperServiceAssessment,
    DeveloperServicesReport,
    DeveloperServiceType,
    ExecutionEffect,
)

DEFAULT_DEVELOPER_PORTS: dict[str, tuple[int, str, str]] = {
    # Container & Orchestration Runtimes
    DeveloperServiceType.DOCKER.value: (2375, "tcp", DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value),
    DeveloperServiceType.DOCKER_REGISTRY.value: (5000, "tcp", DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value),

    # Language & Debugging Runtimes
    DeveloperServiceType.RMI.value: (1099, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value),
    DeveloperServiceType.JDWP.value: (8000, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value),
    DeveloperServiceType.ERLANG_EPMD.value: (4369, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value),
    DeveloperServiceType.ADB.value: (5555, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value),

    # Distributed Build & SCM
    DeveloperServiceType.DISTCC.value: (3632, "tcp", DeveloperCategory.DISTRIBUTED_BUILD_SCM.value),
    DeveloperServiceType.SVN.value: (3690, "tcp", DeveloperCategory.DISTRIBUTED_BUILD_SCM.value),

    # Application Server & Gateway Interfaces
    DeveloperServiceType.AJP.value: (8009, "tcp", DeveloperCategory.APPLICATION_SERVER_GATEWAY.value),
    DeveloperServiceType.FASTCGI.value: (9000, "tcp", DeveloperCategory.APPLICATION_SERVER_GATEWAY.value),
}


class DeveloperServicesCollector(ABC):
    """Abstract interface for developer and runtime interface exposure assessment."""

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
        category: str = DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> DeveloperServiceAssessment:
        """Probe and evaluate discrete developer service exposure."""

    def assess_docker(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 2375) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.DOCKER.value, port, "tcp", DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_docker_registry(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 5000) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.DOCKER_REGISTRY.value, port, "tcp", DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_rmi(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 1099) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.RMI.value, port, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_jdwp(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 8000) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.JDWP.value, port, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_erlang_epmd(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 4369) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.ERLANG_EPMD.value, port, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_adb(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 5555) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.ADB.value, port, "tcp", DeveloperCategory.LANGUAGE_DEBUG_RUNTIME.value, vantage, canary_artifact, timeout)

    def assess_distcc(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 3632) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.DISTCC.value, port, "tcp", DeveloperCategory.DISTRIBUTED_BUILD_SCM.value, vantage, canary_artifact, timeout)

    def assess_svn(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 3690) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.SVN.value, port, "tcp", DeveloperCategory.DISTRIBUTED_BUILD_SCM.value, vantage, canary_artifact, timeout)

    def assess_ajp(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 8009) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.AJP.value, port, "tcp", DeveloperCategory.APPLICATION_SERVER_GATEWAY.value, vantage, canary_artifact, timeout)

    def assess_fastcgi(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0, port: int = 9000) -> DeveloperServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DeveloperServiceType.FASTCGI.value, port, "tcp", DeveloperCategory.APPLICATION_SERVER_GATEWAY.value, vantage, canary_artifact, timeout)


class OfflineSyntheticDeveloperCollector(DeveloperServicesCollector):
    """Deterministic simulation collector for developer and runtime interfaces."""

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
            return t_data.get("resolved_ip", "198.51.100.170")

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> DeveloperServiceAssessment:
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
            return DeveloperServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DeveloperExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=DeveloperAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
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
                "can_change_state", "bound_to_plan",
            ):
                details.setdefault(k, v)

        # 2. Remediated State Check
        if svc_data.get("remediated"):
            return DeveloperServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DeveloperExposureStatus.REMEDIATED.value,
                canary_validated=bool(canary_artifact),
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", DeveloperAuthPrerequisite.USER_PASSWORD.value),
                assigned_role=svc_data.get("role", "authenticated_developer"),
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                applicable_versions=svc_data.get("versions", [details.get("version", "Remediated")]),
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified remediated against historical unauthenticated exposure"
                ],
            )

        # 3. Protected Service Check (Properly authenticated & hardened)
        is_protected = svc_data.get("protected", False)
        auth_req = svc_data.get("authentication_required", True)

        if service_type == DeveloperServiceType.DOCKER.value and details.get("tls_verify") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.DOCKER_REGISTRY.value and details.get("auth_required") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.RMI.value and details.get("ssl_enabled") is True and details.get("auth_required") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.JDWP.value and (details.get("bind_localhost") is True or details.get("disabled") is True):
            is_protected = True
        elif service_type == DeveloperServiceType.ERLANG_EPMD.value and details.get("cookie_required") is True and details.get("firewalled") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.ADB.value and details.get("rsa_key_enforced") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.DISTCC.value and details.get("allow_cidr_enforced") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.SVN.value and details.get("anon_access_none") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.AJP.value and details.get("secret_required") is True and details.get("secret_configured") is True:
            is_protected = True
        elif service_type == DeveloperServiceType.FASTCGI.value and details.get("bind_localhost") is True:
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
                    artifact_type="canary_developer_artifact",
                    artifact_identifier=canary_artifact,
                    action_taken="verified_removed",
                    verified_clean=True,
                )
            )

        if is_protected:
            default_auth = svc_data.get("auth_prerequisite", DeveloperAuthPrerequisite.USER_PASSWORD.value)
            role = svc_data.get("role", "authenticated_developer")
            return DeveloperServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DeveloperExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=default_auth,
                assigned_role=role,
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                applicable_versions=svc_data.get("versions", [details.get("version", "Current")]),
                configuration_details=details,
                cleanup_receipts=receipts,
            )

        # 4. Exposed or Misconfigured State
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get(
            "auth_prerequisite",
            DeveloperAuthPrerequisite.NONE.value if not auth_req else DeveloperAuthPrerequisite.DEFAULT_CREDENTIALS.value
        )
        assigned_role = svc_data.get("role", "anonymous" if not auth_req else "developer")
        status = svc_data.get("status", DeveloperExposureStatus.EXPOSED.value)
        applicable_versions = svc_data.get("versions", [details.get("version", "Observed")])
        vulns = list(svc_data.get("vulnerabilities", []))
        candidates: list[DeveloperPrivilegeCandidate] = []

        can_exec_code = False
        can_change_state = False

        # Protocol-specific candidate evaluation
        if service_type == DeveloperServiceType.DOCKER.value:
            if not auth_req or details.get("tls_verify") is False:
                vulns.append("Docker daemon TCP socket exposed without mutual TLS; root container breakout / RCE permitted")
                c_id = hashlib.sha256(f"docker:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="docker_socket_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.CONTAINER_ESCAPE.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="root",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"api_version": details.get("api_version", "1.41"), "tls_verify": False},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.DOCKER_REGISTRY.value:
            if not auth_req or details.get("auth_required") is False:
                vulns.append("Docker Registry HTTP API exposed without authentication; container image and secret leakage permitted")
                c_id = hashlib.sha256(f"registry:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="docker_registry_leak",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.SOURCE_CODE_LEAKAGE.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"repositories": details.get("repositories", ["internal/app"])},
                    )
                )
                can_change_state = False

        elif service_type == DeveloperServiceType.RMI.value:
            if not auth_req or details.get("ssl_enabled") is False:
                vulns.append("Java Remote Method Invocation (RMI) registry exposed without authentication; remote class loading / RCE possible")
                c_id = hashlib.sha256(f"rmi:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="rmi_code_execution",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"bound_names": details.get("bound_names", ["jmxrmi"])},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.JDWP.value:
            if details.get("bind_localhost") is False or not auth_req:
                vulns.append("Java Debug Wire Protocol (JDWP) port exposed to network; arbitrary JVM bytecode execution permitted")
                c_id = hashlib.sha256(f"jdwp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="jdwp_code_execution",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="debugger",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"handshake": "JDWP-Handshake"},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.ERLANG_EPMD.value:
            if not auth_req or details.get("cookie_required") is False:
                vulns.append("Erlang Port Mapper Daemon (EPMD) exposed; unauthenticated node discovery and arbitrary command execution")
                c_id = hashlib.sha256(f"epmd:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="erlang_epmd_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"nodes": details.get("nodes", ["rabbit@localhost"])},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.ADB.value:
            if not auth_req or details.get("rsa_key_enforced") is False:
                vulns.append("Android Debug Bridge (ADB) daemon exposed without RSA authorization; arbitrary shell access and app installation permitted")
                c_id = hashlib.sha256(f"adb:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="adb_shell_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="shell",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"device_model": details.get("device_model", "Android Device")},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.DISTCC.value:
            if not auth_req or details.get("allow_cidr_enforced") is False:
                vulns.append("distcc distributed compiler daemon exposed without host filtering; arbitrary command execution (CVE-2004-2687)")
                c_id = hashlib.sha256(f"distcc:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="distcc_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="compiler",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"version": details.get("version", "distcc 3.1")},
                    )
                )
                can_exec_code = True
                can_change_state = True

        elif service_type == DeveloperServiceType.SVN.value:
            if details.get("anon_access_none") is False or not auth_req:
                vulns.append("Subversion repository daemon (svnserve) allows anonymous read access; source code repository exposure")
                c_id = hashlib.sha256(f"svn:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="svn_anonymous_checkout",
                        auth_prerequisites=DeveloperAuthPrerequisite.ANONYMOUS.value,
                        privilege_impact=DeveloperPrivilegeImpact.SOURCE_CODE_LEAKAGE.value,
                        execution_effect=ExecutionEffect.READ_ONLY.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"repositories": details.get("repositories", ["repo1"])},
                    )
                )
                can_change_state = False

        elif service_type == DeveloperServiceType.AJP.value:
            if details.get("secret_required") is False or not details.get("secret_configured"):
                vulns.append("Apache JServ Protocol (AJP13) exposed without secret; Ghostcat arbitrary file read / RCE (CVE-2020-1938)")
                c_id = hashlib.sha256(f"ajp:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="ajp_ghostcat_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.FILE_INCLUSION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="tomcat",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"version": details.get("version", "Tomcat 8.5.50")},
                    )
                )
                can_exec_code = True

        elif service_type == DeveloperServiceType.FASTCGI.value:
            if details.get("bind_localhost") is False or not auth_req:
                vulns.append("FastCGI (php-fpm) port exposed to external network; arbitrary PHP code execution / file inclusion")
                c_id = hashlib.sha256(f"fastcgi:{target_host}:{port}".encode()).hexdigest()[:16]
                candidates.append(
                    DeveloperPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="fastcgi_rce",
                        auth_prerequisites=DeveloperAuthPrerequisite.NONE.value,
                        privilege_impact=DeveloperPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        execution_effect=ExecutionEffect.CODE_EXECUTION.value,
                        affected_role="www-data",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"php_version": details.get("php_version", "7.4.3")},
                    )
                )
                can_exec_code = True
                can_change_state = True
        uncertainty = list(svc_data.get("uncertainty_notes", []))
        if can_exec_code and not self.allow_code_execution:
            can_exec_code = False
            uncertainty.append("Code execution verification skipped: not authorized in active action plan")

        if can_change_state and not self.allow_state_change:
            can_change_state = False
            uncertainty.append("State change verification skipped: not authorized in active action plan")

        return DeveloperServiceAssessment(
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
            applicable_versions=applicable_versions,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            uncertainty_notes=uncertainty,
            privilege_candidates=candidates,
            cleanup_receipts=receipts,
        )


class StandardSocketDeveloperCollector(DeveloperServicesCollector):
    """Standard-library socket probe collector for developer and runtime interfaces."""

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
        category: str = DeveloperCategory.CONTAINER_ORCHESTRATION_RUNTIME.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        timeout: float = 2.0,
    ) -> DeveloperServiceAssessment:
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                return DeveloperServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    category=category,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=DeveloperExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_artifact),
                    canary_identifier=canary_artifact,
                    authentication_required=None,
                    auth_prerequisite=DeveloperAuthPrerequisite.UNKNOWN.value,
                    assigned_role="unknown",
                    can_execute_code=False,
                    can_change_state=False,
                    bound_to_plan=True,
                    configuration_details={"socket_connected": True},
                    uncertainty_notes=["TCP connect succeeded; protocol-level handshake required to verify authentication"],
                )
        except (TimeoutError, ConnectionRefusedError, OSError) as err:
            return DeveloperServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DeveloperExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=DeveloperAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                can_execute_code=False,
                can_change_state=False,
                bound_to_plan=True,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


def assess_developer_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: DeveloperServicesCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_artifact: str | None = None,
    canary_id: str | None = None,
    timeout: float = 2.0,
    allow_code_execution: bool = False,
    allow_state_change: bool = False,
) -> DeveloperServicesReport:
    """Execute exposure and privilege boundary assessment across developer and runtime interfaces."""
    active_collector = collector or StandardSocketDeveloperCollector(
        allow_code_execution=allow_code_execution,
        allow_state_change=allow_state_change,
    )
    svcs = service_types or list(DEFAULT_DEVELOPER_PORTS.keys())
    canary = canary_artifact or canary_id

    targets_str = ",".join(targets)
    report_id = f"dev-rep-{hashlib.sha256(f'{scope_ref}:{vantage}:{targets_str}'.encode()).hexdigest()[:16]}"
    assessments: list[DeveloperServiceAssessment] = []

    total_exposed = 0
    total_protected = 0
    total_inaccessible = 0
    total_misconfigured = 0
    total_candidates = 0
    total_receipts = 0

    for target in targets:
        resolved_ip = active_collector.resolve_target(target)
        for svc in svcs:
            if svc not in DEFAULT_DEVELOPER_PORTS:
                continue
            port, proto, cat = DEFAULT_DEVELOPER_PORTS[svc]
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

            if assessment.exposure_status == DeveloperExposureStatus.EXPOSED.value:
                total_exposed += 1
            elif assessment.exposure_status == DeveloperExposureStatus.PROTECTED.value:
                total_protected += 1
            elif assessment.exposure_status == DeveloperExposureStatus.INACCESSIBLE.value:
                total_inaccessible += 1
            elif assessment.exposure_status == DeveloperExposureStatus.MISCONFIGURED.value:
                total_misconfigured += 1

            total_candidates += len(assessment.privilege_candidates)
            total_receipts += len(assessment.cleanup_receipts)

    return DeveloperServicesReport(
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
