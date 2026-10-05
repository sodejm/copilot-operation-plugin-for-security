"""Collectors and evaluators for database, cache, and search/analytics services."""

from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
from typing import Any

from cops.evidence.canonical import canonical, utc_now
from .data_models import (
    CleanupReceipt,
    DataAuthPrerequisite,
    DataExposureStatus,
    DataPrivilegeCandidate,
    DataPrivilegeImpact,
    DataServiceAssessment,
    DataServiceCategory,
    DataServicesReport,
    DataServiceType,
)


DEFAULT_DATA_PORTS: dict[str, tuple[int, str, str]] = {
    # Relational Databases
    DataServiceType.MYSQL.value: (3306, "tcp", DataServiceCategory.RELATIONAL_DB.value),
    DataServiceType.POSTGRES.value: (5432, "tcp", DataServiceCategory.RELATIONAL_DB.value),
    DataServiceType.MSSQL.value: (1433, "tcp", DataServiceCategory.RELATIONAL_DB.value),
    DataServiceType.ORACLE.value: (1521, "tcp", DataServiceCategory.RELATIONAL_DB.value),

    # NoSQL & Document Stores
    DataServiceType.MONGODB.value: (27017, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value),
    DataServiceType.COUCHDB.value: (5984, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value),
    DataServiceType.CASSANDRA.value: (9042, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value),

    # In-Memory & Caches
    DataServiceType.REDIS.value: (6379, "tcp", DataServiceCategory.CACHE_INMEMORY.value),
    DataServiceType.MEMCACHED.value: (11211, "tcp", DataServiceCategory.CACHE_INMEMORY.value),

    # Search & Analytics Engines
    DataServiceType.ELASTICSEARCH.value: (9200, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value),
    DataServiceType.INFLUXDB.value: (8086, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value),
    DataServiceType.KIBANA.value: (5601, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value),
    DataServiceType.SPLUNK.value: (8089, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value),
}


class DataServicesCollector(ABC):
    """Abstract interface for database, cache, and search service exposure assessment."""

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
        category: str = DataServiceCategory.RELATIONAL_DB.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        query_budget_rows: int = 5,
        timeout: float = 2.0,
    ) -> DataServiceAssessment:
        """Probe and evaluate discrete data service exposure."""

    def assess_mysql(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.MYSQL.value, 3306, "tcp", DataServiceCategory.RELATIONAL_DB.value, vantage, canary_artifact, 5, timeout)

    def assess_postgres(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.POSTGRES.value, 5432, "tcp", DataServiceCategory.RELATIONAL_DB.value, vantage, canary_artifact, 5, timeout)

    def assess_mssql(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.MSSQL.value, 1433, "tcp", DataServiceCategory.RELATIONAL_DB.value, vantage, canary_artifact, 5, timeout)

    def assess_oracle(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.ORACLE.value, 1521, "tcp", DataServiceCategory.RELATIONAL_DB.value, vantage, canary_artifact, 5, timeout)

    def assess_mongodb(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.MONGODB.value, 27017, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value, vantage, canary_artifact, 5, timeout)

    def assess_couchdb(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.COUCHDB.value, 5984, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value, vantage, canary_artifact, 5, timeout)

    def assess_cassandra(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.CASSANDRA.value, 9042, "tcp", DataServiceCategory.NOSQL_DOCUMENT.value, vantage, canary_artifact, 5, timeout)

    def assess_redis(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.REDIS.value, 6379, "tcp", DataServiceCategory.CACHE_INMEMORY.value, vantage, canary_artifact, 5, timeout)

    def assess_memcached(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.MEMCACHED.value, 11211, "tcp", DataServiceCategory.CACHE_INMEMORY.value, vantage, canary_artifact, 5, timeout)

    def assess_elasticsearch(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.ELASTICSEARCH.value, 9200, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value, vantage, canary_artifact, 5, timeout)

    def assess_influxdb(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.INFLUXDB.value, 8086, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value, vantage, canary_artifact, 5, timeout)

    def assess_kibana(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.KIBANA.value, 5601, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value, vantage, canary_artifact, 5, timeout)

    def assess_splunk(self, target_host: str, canary_artifact: str | None = None, vantage: str = "external", timeout: float = 2.0) -> DataServiceAssessment:
        ip = self.resolve_target(target_host)
        return self.probe_service(target_host, ip, DataServiceType.SPLUNK.value, 8089, "tcp", DataServiceCategory.SEARCH_ANALYTICS.value, vantage, canary_artifact, 5, timeout)



class OfflineSyntheticDataCollector(DataServicesCollector):
    """Deterministic offline collector for database, cache, and search services."""

    def __init__(self, targets: dict[str, Any] | None = None) -> None:
        self.targets: dict[str, Any] = targets or {}
        self.probes_recorded: list[dict[str, Any]] = []

    def resolve_target(self, target_host: str) -> str:
        try:
            ipaddress.ip_address(target_host)
            return target_host
        except ValueError:
            t_data = self.targets.get(target_host, {})
            return t_data.get("resolved_ip", "198.51.100.150")

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = DataServiceCategory.RELATIONAL_DB.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        query_budget_rows: int = 5,
        timeout: float = 2.0,
    ) -> DataServiceAssessment:
        self.probes_recorded.append({
            "target_host": target_host,
            "resolved_ip": resolved_ip,
            "service_type": service_type,
            "category": category,
            "port": port,
            "protocol": protocol,
            "vantage": vantage,
            "canary_artifact": canary_artifact,
            "query_budget_rows": query_budget_rows,
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
            return DataServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DataExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=DataAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                query_budget_rows=query_budget_rows,
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
                "authentication_required", "role", "role_assigned",
            ):
                details.setdefault(k, v)

        # 2. Remediated State Check
        if svc_data.get("remediated"):
            return DataServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DataExposureStatus.REMEDIATED.value,
                canary_validated=bool(canary_artifact),
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=svc_data.get("auth_prerequisite", DataAuthPrerequisite.USER_PASSWORD.value),
                assigned_role=svc_data.get("role", "read_only"),
                query_budget_rows=query_budget_rows,
                applicable_versions=svc_data.get("versions", [details.get("version", "Remediated")]),
                configuration_details=details,
                uncertainty_notes=[
                    "Service verified remediated against historical unauthenticated exposure"
                ],
            )

        # 3. Protected Service Check (Properly authenticated & hardened)
        is_protected = svc_data.get("protected", False)
        auth_req = svc_data.get("authentication_required", True)

        if service_type == DataServiceType.REDIS.value and details.get("requirepass") is True:
            is_protected = True
        elif service_type == DataServiceType.POSTGRES.value and details.get("auth_method") in ("scram-sha-256", "md5", "cert"):
            is_protected = True
        elif service_type == DataServiceType.MYSQL.value and details.get("password_required") is True:
            is_protected = True
        elif service_type == DataServiceType.MSSQL.value and details.get("sa_disabled") is True and details.get("windows_auth_only") is True:
            is_protected = True
        elif service_type == DataServiceType.MONGODB.value and details.get("auth_enabled") is True:
            is_protected = True
        elif service_type == DataServiceType.ELASTICSEARCH.value and details.get("security_enabled") is True:
            is_protected = True
        elif service_type == DataServiceType.MEMCACHED.value and details.get("sasl_enabled") is True:
            is_protected = True
        elif service_type == DataServiceType.COUCHDB.value and details.get("admin_party") is False:
            is_protected = True
        elif service_type == DataServiceType.CASSANDRA.value and details.get("password_authenticator") is True:
            is_protected = True
        elif service_type == DataServiceType.INFLUXDB.value and details.get("auth_enabled") is True:
            is_protected = True
        elif service_type == DataServiceType.KIBANA.value and details.get("auth_enabled") is True:
            is_protected = True
        elif service_type == DataServiceType.SPLUNK.value and details.get("default_creds") is False:
            is_protected = True

        canary_active = bool(
            canary_artifact
            or details.get("canary_verified")
            or details.get("canary_query_executed")
        )

        receipts: list[CleanupReceipt] = []
        if canary_active and canary_artifact:
            receipt_id = hashlib.sha256(f"clean:{target_host}:{service_type}:{canary_artifact}".encode("utf-8")).hexdigest()[:16]
            receipts.append(
                CleanupReceipt(
                    receipt_id=f"rec-{receipt_id}",
                    target_host=target_host,
                    service_type=service_type,
                    artifact_type="canary_record",
                    artifact_identifier=canary_artifact,
                    action_taken="verified_removed",
                    verified_clean=True,
                )
            )

        if is_protected:
            default_auth = svc_data.get("auth_prerequisite", DataAuthPrerequisite.USER_PASSWORD.value)
            role = svc_data.get("role", "authenticated_user")
            return DataServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DataExposureStatus.PROTECTED.value,
                canary_validated=canary_active,
                canary_identifier=canary_artifact,
                authentication_required=True,
                auth_prerequisite=default_auth,
                assigned_role=role,
                query_budget_rows=query_budget_rows,
                applicable_versions=svc_data.get("versions", [details.get("version", "Current")]),
                configuration_details=details,
                cleanup_receipts=receipts,
            )

        # 4. Exposed or Misconfigured State
        auth_req = svc_data.get("authentication_required", False)
        auth_prereq = svc_data.get(
            "auth_prerequisite",
            DataAuthPrerequisite.NONE.value if not auth_req else DataAuthPrerequisite.DEFAULT_CREDENTIALS.value
        )
        assigned_role = svc_data.get("role", "admin" if not auth_req else "anonymous")
        status = svc_data.get("status", DataExposureStatus.EXPOSED.value)
        applicable_versions = svc_data.get("versions", [details.get("version", "Observed")])
        vulns = list(svc_data.get("vulnerabilities", []))
        candidates: list[DataPrivilegeCandidate] = []

        # Protocol-specific candidate evaluation
        if service_type == DataServiceType.REDIS.value:
            if not auth_req or details.get("requirepass") is False:
                vulns.append("Redis instance accepts unauthenticated TCP commands")
                c_id = hashlib.sha256(f"redis:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="redis_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.CACHE_POISONING.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"requirepass": False, "version": details.get("version", "Redis 6.0")},
                    )
                )
            if details.get("config_set_enabled", True) and not auth_req:
                vulns.append("Redis CONFIG command accessible; potential arbitrary file write / code execution")
                c_id = hashlib.sha256(f"redis_config:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="redis_config_set",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"command": "CONFIG SET"},
                    )
                )

        elif service_type == DataServiceType.ELASTICSEARCH.value:
            if not auth_req or details.get("security_enabled") is False:
                vulns.append("Elasticsearch REST endpoint open without authentication")
                c_id = hashlib.sha256(f"es:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="elasticsearch_open_cluster",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATA_EXFILTRATION.value,
                        affected_role="superuser",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"cluster_name": details.get("cluster_name", "elasticsearch"), "indices": details.get("indices", [])},
                    )
                )

        elif service_type == DataServiceType.MONGODB.value:
            if not auth_req or details.get("auth_enabled") is False:
                vulns.append("MongoDB instance running without authentication (--auth)")
                c_id = hashlib.sha256(f"mongo:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="mongodb_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="root",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"databases": details.get("databases", ["admin", "local"])},
                    )
                )

        elif service_type == DataServiceType.MEMCACHED.value:
            if not auth_req or details.get("sasl_enabled") is False:
                vulns.append("Memcached daemon accepts unauthenticated slab dump requests")
                c_id = hashlib.sha256(f"memcached:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="memcached_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATA_EXFILTRATION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"version": details.get("version", "1.6.9")},
                    )
                )

        elif service_type == DataServiceType.MYSQL.value:
            if details.get("password_required") is False or not auth_req:
                vulns.append("MySQL server accessible with blank/unauthenticated root credentials")
                c_id = hashlib.sha256(f"mysql:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="mysql_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="root",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"user": "root"},
                    )
                )

        elif service_type == DataServiceType.POSTGRES.value:
            if details.get("auth_method") == "trust" or not auth_req:
                vulns.append("PostgreSQL pg_hba.conf configured with 'trust' authentication")
                c_id = hashlib.sha256(f"postgres:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="postgres_trust_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="postgres",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"auth_method": "trust"},
                    )
                )

        elif service_type == DataServiceType.MSSQL.value:
            if details.get("blank_sa") is True or details.get("blank_sa_password") is True or not auth_req:
                vulns.append("Microsoft SQL Server configured with blank sa password or xp_cmdshell enabled")
                c_id = hashlib.sha256(f"mssql:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="mssql_blank_sa",
                        auth_prerequisites=DataAuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        privilege_impact=DataPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        affected_role="sa",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"sa_account": True, "xp_cmdshell": details.get("xp_cmdshell", True)},
                    )
                )

        elif service_type == DataServiceType.ORACLE.value:
            if details.get("default_credentials") is True or not auth_req:
                vulns.append("Oracle database accessible with default administrative credentials (SYS/SYSTEM)")
                c_id = hashlib.sha256(f"oracle:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="oracle_default_credentials",
                        auth_prerequisites=DataAuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="SYS",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"sid": details.get("sid", "ORCL"), "user": details.get("user", "SYS")},
                    )
                )

        elif service_type == DataServiceType.COUCHDB.value:
            if details.get("admin_party") is True or not auth_req:
                vulns.append("CouchDB running in unauthenticated Admin Party mode")
                c_id = hashlib.sha256(f"couchdb:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="couchdb_admin_party",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"admin_party": True},
                    )
                )

        elif service_type == DataServiceType.CASSANDRA.value:
            if details.get("default_creds") is True or not auth_req:
                vulns.append("Cassandra cluster accessible using default superuser credentials (cassandra/cassandra)")
                c_id = hashlib.sha256(f"cassandra:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="cassandra_default_superuser",
                        auth_prerequisites=DataAuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        privilege_impact=DataPrivilegeImpact.DATABASE_TAKEOVER.value,
                        affected_role="cassandra",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"superuser": "cassandra"},
                    )
                )

        elif service_type == DataServiceType.INFLUXDB.value:
            if not auth_req or details.get("auth_enabled") is False:
                vulns.append("InfluxDB HTTP API open without mandatory authentication")
                c_id = hashlib.sha256(f"influx:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="influxdb_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.ANALYTICS_TAMPERING.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"databases": details.get("databases", ["_internal"])},
                    )
                )

        elif service_type == DataServiceType.KIBANA.value:
            if not auth_req or details.get("auth_enabled") is False:
                vulns.append("Kibana analytics dashboard exposed without user authentication")
                c_id = hashlib.sha256(f"kibana:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="kibana_no_auth",
                        auth_prerequisites=DataAuthPrerequisite.NONE.value,
                        privilege_impact=DataPrivilegeImpact.DATA_EXFILTRATION.value,
                        affected_role="anonymous",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"spaces": details.get("spaces", ["default"])},
                    )
                )

        elif service_type == DataServiceType.SPLUNK.value:
            if details.get("default_creds") is True:
                vulns.append("Splunk management daemon accessible with default credentials (admin/changeme)")
                c_id = hashlib.sha256(f"splunk:{target_host}:{port}".encode("utf-8")).hexdigest()[:16]
                candidates.append(
                    DataPrivilegeCandidate(
                        candidate_id=f"priv-{c_id}",
                        service_type=service_type,
                        category=category,
                        target_host=target_host,
                        port=port,
                        vantage=vantage,
                        finding_type="splunk_default_creds",
                        auth_prerequisites=DataAuthPrerequisite.DEFAULT_CREDENTIALS.value,
                        privilege_impact=DataPrivilegeImpact.REMOTE_CODE_EXECUTION.value,
                        affected_role="admin",
                        applicable_versions=applicable_versions,
                        supporting_evidence={"user": "admin", "port": port},
                    )
                )

        return DataServiceAssessment(
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
            query_budget_rows=query_budget_rows,
            applicable_versions=applicable_versions,
            configuration_details=details,
            observed_vulnerabilities=vulns,
            privilege_candidates=candidates,
            cleanup_receipts=receipts,
        )


class StandardSocketDataCollector(DataServicesCollector):
    """Standard-library socket probe collector for databases, caches, and search services."""

    def resolve_target(self, target_host: str) -> str:
        return socket.gethostbyname(target_host)

    def probe_service(
        self,
        target_host: str,
        resolved_ip: str,
        service_type: str,
        port: int,
        protocol: str = "tcp",
        category: str = DataServiceCategory.RELATIONAL_DB.value,
        vantage: str = "external",
        canary_artifact: str | None = None,
        query_budget_rows: int = 5,
        timeout: float = 2.0,
    ) -> DataServiceAssessment:
        try:
            with socket.create_connection((resolved_ip, port), timeout=timeout):
                return DataServiceAssessment(
                    target_host=target_host,
                    resolved_ip=resolved_ip,
                    service_type=service_type,
                    category=category,
                    port=port,
                    protocol=protocol,
                    vantage=vantage,
                    exposure_status=DataExposureStatus.EXPOSED.value,
                    canary_validated=bool(canary_artifact),
                    canary_identifier=canary_artifact,
                    authentication_required=None,
                    auth_prerequisite=DataAuthPrerequisite.UNKNOWN.value,
                    assigned_role="unknown",
                    query_budget_rows=query_budget_rows,
                    configuration_details={"socket_connected": True},
                    uncertainty_notes=["TCP connect succeeded; protocol credentials required to verify authentication"],
                )
        except (socket.timeout, ConnectionRefusedError, OSError) as err:
            return DataServiceAssessment(
                target_host=target_host,
                resolved_ip=resolved_ip,
                service_type=service_type,
                category=category,
                port=port,
                protocol=protocol,
                vantage=vantage,
                exposure_status=DataExposureStatus.INACCESSIBLE.value,
                canary_validated=False,
                canary_identifier=canary_artifact,
                authentication_required=None,
                auth_prerequisite=DataAuthPrerequisite.UNKNOWN.value,
                assigned_role="unknown",
                query_budget_rows=query_budget_rows,
                error_message=str(err),
                uncertainty_notes=["Service was inaccessible from probe vantage; this cannot be reported as secure"],
            )


def assess_data_services(
    targets: list[str],
    service_types: list[str] | None = None,
    collector: DataServicesCollector | None = None,
    vantage: str = "external",
    scope_ref: str = "authorized-scope",
    canary_artifact: str | None = None,
    canary_id: str | None = None,
    query_budget_rows: int = 5,
    timeout: float = 2.0,
) -> DataServicesReport:
    """Assess database, cache, and search/analytics services across approved targets."""
    effective_canary = canary_artifact or canary_id
    if collector is None:
        collector = OfflineSyntheticDataCollector()

    selected_services = service_types or list(DEFAULT_DATA_PORTS.keys())
    assessments: list[DataServiceAssessment] = []
    candidates: list[DataPrivilegeCandidate] = []
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
        f"{scope_ref}:{sorted(targets)}:{sorted(selected_services)}:{vantage}".encode("utf-8")
    ).hexdigest()[:16]

    for target in targets:
        try:
            resolved_ip = collector.resolve_target(target)
        except Exception:
            resolved_ip = "unresolved"

        for svc in selected_services:
            if svc not in DEFAULT_DATA_PORTS:
                continue

            port, proto, cat = DEFAULT_DATA_PORTS[svc]
            assessment = collector.probe_service(
                target_host=target,
                resolved_ip=resolved_ip,
                service_type=svc,
                port=port,
                protocol=proto,
                category=cat,
                vantage=vantage,
                canary_artifact=effective_canary,
                query_budget_rows=query_budget_rows,
                timeout=timeout,
            )

            assessments.append(assessment)
            summary["total_services"] += 1
            summary[assessment.exposure_status] = summary.get(assessment.exposure_status, 0) + 1

            for c in assessment.privilege_candidates:
                candidates.append(c)
                summary["privilege_candidates"] += 1

            for r in assessment.cleanup_receipts:
                receipts.append(r)
                summary["cleanup_receipts"] += 1

    return DataServicesReport(
        report_id=f"data-{report_id}",
        scope_reference=scope_ref,
        vantage=vantage,
        services_assessed=assessments,
        privilege_candidates=candidates,
        cleanup_receipts=receipts,
        summary=summary,
    )
