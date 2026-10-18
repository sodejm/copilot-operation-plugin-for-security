"""Content-safe, bounded analyzers for heterogeneous security artifacts.

The analyzers in this module inspect caller-supplied bytes and structured data.
They never execute artifacts, resolve network resources, or claim live-system
coverage. Reports contain hashes and stable artifact identifiers, not artifact
content or credential values.
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import json
import re
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cops.assessments.cloud_inputs import cloud_input
from cops.assessments.network_inputs import KINDS as NETWORK_KINDS
from cops.assessments.network_inputs import inspect_network
from cops.assessments.supply_inputs import github_actions, npm_lock, package_name, requirements_lock
from cops.contracts.models import Finding
from cops.evidence.canonical import EvidenceError, canonical, timestamp

REPORT_SCHEMA = "cops.artifact-assessment/v1"
DEFAULT_LIMITATION = (
    "Offline artifact inspection cannot establish live provider, production, "
    "runtime enforcement, or deployment readiness."
)
CAPABILITIES = frozenset(
    {
        "application_security",
        "foundry_security",
        "compliance_evidence",
        "forensic_evidence",
        "malware_static",
        "cloud_configuration",
        "supply_chain",
        "credential_history",
        "network_segmentation",
        "transport_identity",
    }
)
_ID = re.compile(r"[a-zA-Z0-9_.:-]{1,96}\Z")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
_SECRET_KEYS = frozenset({"secret", "password", "private_key", "access_token", "api_key", "credential_value"})
_MAX_SCANNER_RECORDS = 1000


class ArtifactAssessmentError(ValueError):
    """Content-free validation error suitable for untrusted inputs."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject_secret_fields(value: Any) -> None:
    """Reject explicit credential-value fields without retaining their values."""
    pending = [value]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 10_000:
            raise ArtifactAssessmentError("artifact_structure_limit")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if isinstance(key, str) and key.lower() in _SECRET_KEYS:
                    raise ArtifactAssessmentError("credential_value_forbidden")
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)


@dataclass(frozen=True)
class _Artifact:
    artifact_id: str
    kind: str
    content: Any
    raw: bytes
    sha256: str
    metadata: dict[str, Any]

    @property
    def evidence_ref(self) -> str:
        return f"artifact:{self.artifact_id}:sha256:{self.sha256}"


@dataclass(frozen=True)
class _Issue:
    code: str
    title: str
    severity: str
    claim: str
    remediation: str
    refs: tuple[str, ...]
    classification: str = "assessment"
    verification: str = "partially-verified"
    confidence: str = "limited"
    uncertainty: str = "The conclusion is limited to the supplied offline artifact."


def _safe_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "source_ref",
        "collected_at",
        "sha256",
        "collection_authorized",
        "custody",
        "framework",
        "framework_version",
    }
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in _SECRET_KEYS:
            raise ArtifactAssessmentError("credential_value_forbidden")
        if key not in allowed:
            continue
        if key == "custody":
            if not isinstance(item, list) or len(item) > 128:
                raise ArtifactAssessmentError("invalid_custody")
            result[key] = item
        elif isinstance(item, (str, bool)) or item is None:
            result[key] = item
        else:
            raise ArtifactAssessmentError("invalid_metadata")
    return result


def _prepare_artifacts(
    artifacts: Sequence[Mapping[str, object]], *, max_artifacts: int, max_artifact_bytes: int, max_total_bytes: int
) -> list[_Artifact]:
    if isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, Sequence):
        raise ArtifactAssessmentError("invalid_artifacts")
    if not all(type(limit) is int and limit > 0 for limit in (max_artifacts, max_artifact_bytes, max_total_bytes)):
        raise ArtifactAssessmentError("invalid_limit")
    if len(artifacts) > max_artifacts:
        raise ArtifactAssessmentError("artifact_count_limit")
    prepared: list[_Artifact] = []
    total = 0
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, Mapping):
            raise ArtifactAssessmentError("invalid_artifact")
        artifact_id, kind = item.get("artifact_id"), item.get("kind")
        if not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id):
            raise ArtifactAssessmentError("invalid_artifact_id")
        if artifact_id in seen:
            raise ArtifactAssessmentError("duplicate_artifact_id")
        if not isinstance(kind, str) or not _ID.fullmatch(kind):
            raise ArtifactAssessmentError("invalid_artifact_kind")
        _reject_secret_fields(item)
        content = item.get("content")
        if isinstance(content, bytes):
            raw = content
        elif isinstance(content, str):
            try:
                raw = content.encode("utf-8")
            except UnicodeError:
                raise ArtifactAssessmentError("invalid_text") from None
        elif type(content) in (dict, list):
            try:
                raw = canonical(content, max_bytes=max_artifact_bytes)
            except EvidenceError as exc:
                raise ArtifactAssessmentError(exc.code) from None
        else:
            raise ArtifactAssessmentError("invalid_artifact_content")
        if len(raw) > max_artifact_bytes:
            raise ArtifactAssessmentError("artifact_size_limit")
        total += len(raw)
        if total > max_total_bytes:
            raise ArtifactAssessmentError("total_size_limit")
        metadata = _safe_metadata(item)
        prepared.append(_Artifact(artifact_id, kind, content, raw, hashlib.sha256(raw).hexdigest(), metadata))
        seen.add(artifact_id)
    return prepared


def _issue(
    artifact: _Artifact, code: str, title: str, severity: str, claim: str, remediation: str, **kwargs: Any
) -> _Issue:
    return _Issue(code, title, severity, claim, remediation, (artifact.evidence_ref,), **kwargs)


def _finding(
    issue: _Issue,
    *,
    capability: str,
    engagement_id: str,
    result_id: str,
    scenario_id: str,
    created_at: str,
    occurrence: int | None = None,
) -> dict[str, Any]:
    identity = capability + issue.code + "|".join(issue.refs)
    if occurrence is not None:
        identity += f"|occurrence:{occurrence}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:24]
    data = Finding(
        schema_version="cops.finding/v1",
        finding_id=f"find-{suffix}",
        engagement_id=engagement_id,
        result_id=result_id,
        scenario_id=scenario_id,
        title=issue.title,
        severity=issue.severity,
        classification=issue.classification,
        verification=issue.verification,
        confidence=issue.confidence,
        claim=issue.claim,
        evidence_references=list(issue.refs),
        mitre_attack=[],
        remediation=issue.remediation,
        uncertainty=issue.uncertainty,
        created_at=created_at,
    ).to_dict()
    return Finding.from_dict(data).to_dict()


def _text(artifact: _Artifact) -> str | None:
    return artifact.content if isinstance(artifact.content, str) else None


def _structured(artifact: _Artifact) -> dict[str, Any] | list[Any] | None:
    return artifact.content if type(artifact.content) in (dict, list) else None


def _unresolved(artifact: _Artifact, subject: str) -> _Issue:
    return _issue(
        artifact,
        f"{subject}_insufficient_evidence",
        f"Insufficient evidence for {subject.replace('_', ' ')}",
        "informational",
        "Required fields or a supported representation are absent, so the security state is unknown.",
        "Provide the documented, versioned artifact fields and collection metadata.",
        classification="unresolved",
        verification="unverified",
        confidence="unknown",
        uncertainty="The supplied evidence cannot support either a passing or failing conclusion.",
    )


def _application_security(
    items: list[_Artifact], _as_of: datetime
) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    limitations: list[str] = []
    analyzed: set[str] = set()
    for artifact in items:
        text = _text(artifact)
        if artifact.kind == "python_source" and text is not None:
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                issues.append(_unresolved(artifact, "python_source"))
                continue
            analyzed.add(artifact.artifact_id)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = (
                        node.func.id
                        if isinstance(node.func, ast.Name)
                        else node.func.attr
                        if isinstance(node.func, ast.Attribute)
                        else ""
                    )
                    if name in {"eval", "exec"}:
                        issues.append(
                            _issue(
                                artifact,
                                "dynamic_code_execution",
                                "Dynamic code execution accepts runtime input",
                                "high",
                                "The Python syntax tree contains a dynamic code execution call.",
                                "Replace dynamic execution with an allowlisted parser or dispatcher.",
                            )
                        )
                    if name in {"run", "Popen", "call", "check_output"} and any(
                        k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                        for k in node.keywords
                    ):
                        issues.append(
                            _issue(
                                artifact,
                                "subprocess_shell",
                                "Shell-enabled subprocess call",
                                "high",
                                "The Python syntax tree enables shell interpretation for a subprocess.",
                                "Pass an argument vector with shell disabled and validate each argument.",
                            )
                        )
                    if (
                        name in {"execute", "executemany"}
                        and node.args
                        and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp))
                    ):
                        issues.append(
                            _issue(
                                artifact,
                                "sql_interpolation",
                                "Interpolated SQL statement",
                                "high",
                                "A database call receives a constructed SQL expression.",
                                "Use driver parameter binding for all untrusted values.",
                            )
                        )
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    decorators = {ast.unparse(d) for d in node.decorator_list}
                    route = any(".route" in d or ".get" in d or ".post" in d for d in decorators)
                    authorized = any(re.search(r"authoriz|permission|require_role", d, re.I) for d in decorators)
                    if route and not authorized:
                        issues.append(
                            _issue(
                                artifact,
                                "route_authorization",
                                "Route lacks visible authorization enforcement",
                                "medium",
                                "A routed Python handler has no recognized authorization decorator in the supplied source.",
                                "Apply an explicit authorization policy to the route and test denied identities.",
                            )
                        )
        elif artifact.kind in {"javascript_source", "typescript_source", "unified_diff"} and text is not None:
            analyzed.add(artifact.artifact_id)
            source = (
                "\n".join(line[1:] for line in text.splitlines() if line.startswith("+") and not line.startswith("+++"))
                if artifact.kind == "unified_diff"
                else text
            )
            if re.search(r"(?:child_process\.)?exec\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$])", source):
                issues.append(
                    _issue(
                        artifact,
                        "js_command_injection",
                        "Constructed command reaches process execution",
                        "high",
                        "Added or supplied JavaScript constructs a command passed to exec.",
                        "Use an argv-based process API and allowlist arguments.",
                    )
                )
            if re.search(r"\.query\s*\(\s*`[^`]*\$\{", source):
                issues.append(
                    _issue(
                        artifact,
                        "js_sql_interpolation",
                        "Template expression reaches database query",
                        "high",
                        "A JavaScript database query contains template interpolation.",
                        "Use parameter placeholders and bound values.",
                    )
                )
            for match in re.finditer(r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\((.*?)\)\s*;?", source, re.S):
                if not re.search(r"authoriz|permission|requireRole|require_role", match.group(1), re.I):
                    issues.append(
                        _issue(
                            artifact,
                            "js_route_authorization",
                            "Route lacks visible authorization middleware",
                            "medium",
                            "A JavaScript route has no recognized authorization middleware in the supplied source.",
                            "Add explicit authorization middleware and denied-identity tests.",
                        )
                    )
        elif artifact.kind == "scanner_json" and type(artifact.content) in (dict, list):
            records = artifact.content.get("findings", []) if isinstance(artifact.content, dict) else artifact.content
            if not isinstance(records, list):
                analyzed.add(artifact.artifact_id)
                issues.append(_unresolved(artifact, "scanner_output"))
            elif len(records) > _MAX_SCANNER_RECORDS:
                raise ArtifactAssessmentError("scanner_record_limit")
            else:
                analyzed.add(artifact.artifact_id)
                for record in records:
                    if (
                        isinstance(record, dict)
                        and record.get("status", "open") == "open"
                        and isinstance(record.get("rule_id"), str)
                    ):
                        severity = str(record.get("severity", "medium")).lower()
                        if severity not in {"critical", "high", "medium", "low", "informational"}:
                            severity = "medium"
                        issues.append(
                            _issue(
                                artifact,
                                "scanner_open_finding",
                                "Scanner reports an open source finding",
                                severity,
                                "A supplied scanner record is open; its message is intentionally not copied into this report.",
                                "Review the referenced scanner record and verify a code-level correction.",
                            )
                        )
        else:
            limitations.append(f"Unsupported application security artifact kind: {artifact.kind}.")
    return issues, limitations, ["registered-adapter:application-source-parser@1"], analyzed


def _foundry_security(items: list[_Artifact], _as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    markers = re.compile(
        r"ignore (?:all )?(?:previous|prior)|system prompt|call (?:the )?tool|override instructions", re.I
    )
    for artifact in items:
        if artifact.kind != "foundry_test" or not isinstance(artifact.content, dict):
            limitations.append(f"Unsupported Foundry artifact kind: {artifact.kind}.")
            continue
        data = artifact.content
        required = {
            "prompt_origin",
            "untrusted_content",
            "expected_decision",
            "decision",
            "allowed_tools",
            "observed_calls",
        }

        def identifiers(value: Any) -> bool:
            return isinstance(value, list) and all(isinstance(item, str) and _ID.fullmatch(item) for item in value)

        resource_fields = {"allowed_resources", "observed_resources"} & data.keys()
        if (
            not required <= data.keys()
            or data.get("prompt_origin") not in ("direct", "indirect")
            or not isinstance(data.get("untrusted_content"), str)
            or data.get("expected_decision") not in ("allow", "deny")
            or data.get("decision") not in ("allow", "deny")
            or not identifiers(data.get("allowed_tools"))
            or not identifiers(data.get("observed_calls"))
            or (
                resource_fields
                and (
                    len(resource_fields) != 2
                    or not identifiers(data.get("allowed_resources"))
                    or not identifiers(data.get("observed_resources"))
                )
            )
        ):
            issues.append(_unresolved(artifact, "foundry_security_test"))
            continue
        analyzed.add(artifact.artifact_id)
        allowed = set(data["allowed_tools"])
        observed = set(data["observed_calls"])
        if observed - allowed:
            issues.append(
                _issue(
                    artifact,
                    "foundry_tool_scope",
                    "Foundry test observes an out-of-scope tool call",
                    "high",
                    "Observed tool identifiers are not a subset of the test allowlist.",
                    "Deny the call before dispatch and bind tool grants to the approved test scope.",
                )
            )
        if resource_fields and set(data["observed_resources"]) - set(data["allowed_resources"]):
            issues.append(
                _issue(
                    artifact,
                    "foundry_resource_scope",
                    "Foundry test observes an out-of-scope resource",
                    "high",
                    "Observed resource identifiers are not a subset of the approved resource allowlist.",
                    "Bind tool calls to the approved resource scope before dispatch.",
                )
            )
        if (
            markers.search(data["untrusted_content"])
            and data.get("expected_decision") == "deny"
            and data.get("decision") != "deny"
        ):
            issues.append(
                _issue(
                    artifact,
                    "foundry_prompt_injection",
                    "Prompt-injection test was not denied",
                    "high",
                    "Direct or indirect untrusted instructions were accepted despite a deny expectation.",
                    "Treat retrieved and user content as data, enforce instruction provenance, and deny unauthorized tool requests.",
                )
            )
    return issues, limitations, ["registered-adapter:foundry-live-evaluator@1"], analyzed


def _parse_time(value: Any) -> datetime | None:
    try:
        return timestamp(value)
    except EvidenceError:
        return None


def _compliance(items: list[_Artifact], as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    frameworks = {"SOC2", "CIS", "NIST"}
    for artifact in items:
        if artifact.kind != "control_evidence":
            limitations.append(f"Unsupported compliance artifact kind: {artifact.kind}.")
            continue
        records = artifact.content.get("controls") if isinstance(artifact.content, dict) else None
        if not isinstance(records, list) or not records:
            issues.append(_unresolved(artifact, "control_evidence"))
            continue
        analyzed.add(artifact.artifact_id)
        for record in records[:1000]:
            if (
                not isinstance(record, dict)
                or record.get("framework") not in tuple(frameworks)
                or any(
                    not isinstance(record.get(field), str) or not _ID.fullmatch(record[field])
                    for field in ("framework_version", "control_id")
                )
            ):
                issues.append(_unresolved(artifact, "versioned_control"))
                continue
            collected = _parse_time(record.get("collected_at"))
            refs = record.get("evidence_refs")
            status = record.get("status")
            if (
                collected is None
                or collected > as_of
                or not isinstance(refs, list)
                or not refs
                or any(not isinstance(ref, str) or not _ID.fullmatch(ref) for ref in refs)
                or status not in ("effective", "ineffective", "not_tested")
            ):
                issues.append(_unresolved(artifact, "control_evidence"))
            elif as_of - collected > timedelta(days=90):
                issues.append(
                    _issue(
                        artifact,
                        "stale_control_evidence",
                        "Control evidence is stale",
                        "informational",
                        "Versioned control evidence is older than the 90-day offline assessment window.",
                        "Collect fresh evidence under the same framework version.",
                        classification="unresolved",
                        verification="unverified",
                        confidence="unknown",
                    )
                )
            elif status == "ineffective":
                issues.append(
                    _issue(
                        artifact,
                        "ineffective_control",
                        "Control evidence records an ineffective control",
                        "medium",
                        "A versioned control record is marked ineffective.",
                        "Remediate the control and collect new evidence.",
                    )
                )
            elif status == "not_tested":
                issues.append(_unresolved(artifact, "untested_control"))
    return issues, limitations, ["registered-adapter:compliance-evidence-export@1"], analyzed


def _forensics(items: list[_Artifact], as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    for artifact in items:
        if artifact.kind not in {"disk_image", "memory_image"} or not isinstance(artifact.content, bytes):
            limitations.append(f"Unsupported forensic artifact kind: {artifact.kind}.")
            continue
        analyzed.add(artifact.artifact_id)
        source = artifact.metadata.get("source_ref")
        if not isinstance(source, str) or not _ID.fullmatch(source):
            issues.append(_unresolved(artifact, "forensic_source"))
        collected = _parse_time(artifact.metadata.get("collected_at"))
        if collected is None or collected > as_of:
            issues.append(_unresolved(artifact, "forensic_collection_time"))
        expected = artifact.metadata.get("sha256")
        if not isinstance(expected, str) or not _HEX64.fullmatch(expected):
            issues.append(_unresolved(artifact, "forensic_hash"))
        elif expected.lower() != artifact.sha256:
            issues.append(
                _issue(
                    artifact,
                    "forensic_hash_mismatch",
                    "Forensic evidence hash mismatch",
                    "high",
                    "The supplied expected SHA-256 does not match the original bytes.",
                    "Stop analysis and reconcile acquisition and custody records before reuse.",
                )
            )
        if artifact.metadata.get("collection_authorized") is not True:
            issues.append(
                _issue(
                    artifact,
                    "forensic_collection_permission",
                    "Forensic collection permission is absent",
                    "high",
                    "The artifact metadata does not affirm collection authorization.",
                    "Record explicit collection authority and scope before processing.",
                    classification="unresolved",
                    verification="unverified",
                    confidence="unknown",
                )
            )
        custody = artifact.metadata.get("custody")
        if not isinstance(custody, list) or not custody:
            issues.append(_unresolved(artifact, "chain_of_custody"))
        else:
            times = [_parse_time(event.get("at")) for event in custody if isinstance(event, dict)]
            if (
                len(times) != len(custody)
                or any(
                    value is None or value > as_of or (collected is not None and value < collected) for value in times
                )
                or times != sorted(times)
                or any(
                    not isinstance(event.get("actor_ref"), str) or not _ID.fullmatch(event["actor_ref"])
                    for event in custody
                    if isinstance(event, dict)
                )
            ):
                issues.append(
                    _issue(
                        artifact,
                        "custody_order",
                        "Chain-of-custody records are invalid",
                        "medium",
                        "Custody events are missing valid actor references or timestamps, precede collection, occur in the future, or are out of order.",
                        "Provide ordered UTC custody events with opaque actor references.",
                        classification="unresolved",
                        verification="unverified",
                        confidence="unknown",
                    )
                )
        limitations.append(
            "Disk and memory bytes were hashed but not mounted, executed, or parsed as a filesystem or memory image."
        )
    return issues, limitations, ["registered-adapter:forensic-image-parser@1"], analyzed


_SUSPICIOUS = re.compile(
    rb"(?:powershell(?:\.exe)?\s+-e(?:ncodedcommand)?|invoke-expression|downloadstring|frombase64string)", re.I
)


def _malware(items: list[_Artifact], _as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    for artifact in items:
        raw: bytes | None = None
        if artifact.kind == "binary" and isinstance(artifact.content, bytes):
            raw = artifact.content
        elif artifact.kind == "powershell_encoded" and isinstance(artifact.content, str):
            try:
                raw = base64.b64decode(artifact.content, validate=True)
            except (binascii.Error, ValueError):
                issues.append(_unresolved(artifact, "powershell_encoding"))
                continue
            if len(raw) > 262_144:
                issues.append(_unresolved(artifact, "powershell_decoded_size"))
                continue
        else:
            limitations.append(f"Unsupported malware artifact kind: {artifact.kind}.")
            continue
        analyzed.add(artifact.artifact_id)
        scan = raw.replace(b"\x00", b"")
        if _SUSPICIOUS.search(scan):
            issues.append(
                _issue(
                    artifact,
                    "static_execution_indicator",
                    "Static artifact contains a high-risk execution indicator",
                    "high",
                    "Bounded byte inspection found a PowerShell execution or download indicator; no content was executed.",
                    "Quarantine the artifact and investigate in an authorized isolated laboratory.",
                )
            )
        limitations.append(
            "Static byte inspection does not establish runtime behavior, unpacked payload behavior, or malware attribution."
        )
    return issues, limitations, ["registered-adapter:malware-emulator@1"], analyzed


def _walk_dicts(value: Any, *, max_nodes: int = 10_000) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    pending = [value]
    nodes = 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            break
        if isinstance(item, dict):
            result.append(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return result


def _cloud(items: list[_Artifact], _as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    supported = {
        "terraform_plan",
        "kubernetes_rendered",
        "helm_rendered_json",
        "aws_export",
        "azure_export",
        "gcp_export",
    }
    for artifact in items:
        data = _structured(artifact)
        if artifact.kind == "helm_chart_yaml":
            limitations.append(
                "Raw Helm templates require a pinned renderer; supply rendered JSON for deterministic offline checks."
            )
            continue
        if artifact.kind not in supported or data is None:
            limitations.append(f"Unsupported cloud artifact kind: {artifact.kind}.")
            continue
        analyzed.add(artifact.artifact_id)
        parsed = cloud_input(artifact.kind, data)
        messages = {
            "workload_privilege": (
                "Rendered workload permits elevated execution",
                "A workload enables privileged or host execution, or explicitly permits root execution.",
                "Set restrictive pod and container security contexts.",
            ),
            "iam_wildcard": (
                "IAM or RBAC policy contains a broad grant",
                "A typed Allow policy or RBAC rule grants wildcard action or global resource scope.",
                "Replace broad grants with required actions and resources.",
            ),
            "public_storage": (
                "Cloud storage export indicates public access",
                "A typed storage ACL, resource policy, or provider setting permits public access.",
                "Disable public access and use explicit principals.",
            ),
            "internet_ingress": (
                "Network rule permits unrestricted ingress",
                "An enabled inbound Allow rule permits an all-address source range.",
                "Restrict ingress to documented source networks and ports.",
            ),
        }
        for code in sorted(parsed.codes):
            title, claim, remediation = messages[code]
            issues.append(
                _issue(artifact, code, title, "medium" if code == "internet_ingress" else "high", claim, remediation)
            )
        if parsed.incomplete:
            issues.append(_unresolved(artifact, "cloud_configuration"))
            limitations.append(
                "Unrecognized resources, malformed fields, unsupported plan versions, or unknown values leave cloud coverage partial."
            )
        limitations.append(
            "Typed cloud observations do not solve effective permissions, rule priority, condition expressions, or deployed reachability."
        )
    return (
        issues,
        limitations,
        ["registered-adapter:helm-renderer@1", "registered-adapter:cloud-live-export@1"],
        analyzed,
    )


def _supply_chain(items: list[_Artifact], _as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    components: dict[tuple[str, str, str], _Artifact] = {}
    advisories: list[dict[str, Any]] = []
    messages = {
        "npm_registry_resolution": (
            "npm lock resolves outside the expected registry",
            "A locked npm package does not resolve to the expected HTTPS registry identity.",
            "Pin the approved registry and regenerate the lockfile under trusted configuration.",
        ),
        "npm_integrity_missing": (
            "npm lock entry lacks integrity metadata",
            "A registry package entry has no integrity value.",
            "Regenerate the lockfile with integrity metadata and verify the registry source.",
        ),
        "python_dependency_unhashed": (
            "Python dependency is not fully hash-pinned",
            "A requirements entry lacks an exact version and valid SHA-256 hashes.",
            "Generate a locked requirements file with exact versions and hashes.",
        ),
        "action_container_unpinned": (
            "Workflow container action is not digest-pinned",
            "A workflow container reference lacks a complete SHA-256 digest.",
            "Pin the container image by digest.",
        ),
        "action_unpinned": (
            "GitHub Action is not commit-pinned",
            "A remote workflow action reference is not pinned to a 40-character commit SHA.",
            "Pin the action to a reviewed commit SHA and retain update provenance.",
        ),
        "workflow_write_permissions": (
            "Workflow grants token write permissions",
            "A workflow or job requests write permissions for its GitHub token.",
            "Use read permissions by default and scope necessary writes to reviewed jobs.",
        ),
        "workflow_untrusted_head": (
            "Privileged workflow checks out an untrusted pull-request head",
            "A pull_request_target workflow explicitly checks out pull-request head code.",
            "Keep privileged workflows on trusted base code and isolate untrusted pull-request execution.",
        ),
    }
    parsers = {
        "package_lock": (dict, npm_lock, "npm_lock"),
        "requirements_lock": (str, requirements_lock, "python_lock"),
        "github_actions": (str, github_actions, "github_actions"),
    }
    for artifact in items:
        if (
            artifact.kind == "advisory_fixture"
            and isinstance(artifact.content, dict)
            and isinstance(artifact.content.get("advisories"), list)
        ):
            analyzed.add(artifact.artifact_id)
            records = artifact.content["advisories"]
            if len(records) > 5000 or any(not isinstance(record, dict) for record in records):
                issues.append(_unresolved(artifact, "advisory_fixture"))
            advisories.extend(record for record in records[:5000] if isinstance(record, dict))
        elif artifact.kind in parsers and isinstance(artifact.content, parsers[artifact.kind][0]):
            analyzed.add(artifact.artifact_id)
            parsed = parsers[artifact.kind][1](artifact.content)
            components.update({identity: artifact for identity in parsed.components})
            if parsed.incomplete:
                issues.append(_unresolved(artifact, parsers[artifact.kind][2]))
            for code in sorted(parsed.codes):
                title, claim, remediation = messages[code]
                issues.append(
                    _issue(
                        artifact,
                        code,
                        title,
                        "high" if code == "workflow_untrusted_head" else "medium",
                        claim,
                        remediation,
                    )
                )
        elif artifact.kind in {"cyclonedx", "spdx", "container_sbom"} and isinstance(artifact.content, dict):
            analyzed.add(artifact.artifact_id)
            records = artifact.content.get("components", artifact.content.get("packages", []))
            if not isinstance(records, list):
                issues.append(_unresolved(artifact, "sbom"))
                continue
            if not records or len(records) > 5000:
                issues.append(_unresolved(artifact, "sbom"))
            for record in records[:5000]:
                if not isinstance(record, dict):
                    issues.append(_unresolved(artifact, "versioned_sbom_component"))
                    continue
                name = record.get("name", record.get("PackageName"))
                version = record.get("version", record.get("versionInfo"))
                if not isinstance(name, str) or not isinstance(version, str):
                    issues.append(_unresolved(artifact, "versioned_sbom_component"))
                else:
                    purl = record.get("purl", "")
                    ecosystem = (
                        "npm"
                        if isinstance(purl, str) and purl.startswith("pkg:npm/")
                        else "pypi"
                        if isinstance(purl, str) and purl.startswith("pkg:pypi/")
                        else ""
                    )
                    components[(ecosystem, package_name(name, ecosystem), version)] = artifact
        else:
            limitations.append(f"Unsupported supply-chain artifact kind: {artifact.kind}.")
    for advisory in advisories[:5000]:
        name, version = advisory.get("package"), advisory.get("version")
        ecosystem = str(advisory.get("ecosystem", "")).lower()
        if ecosystem == "python":
            ecosystem = "pypi"
        if isinstance(name, str) and isinstance(version, str):
            for (component_ecosystem, component_name, component_version), artifact in components.items():
                if (
                    (not ecosystem or ecosystem == component_ecosystem)
                    and package_name(name, component_ecosystem) == component_name
                    and version == component_version
                ):
                    issues.append(
                        _issue(
                            artifact,
                            "pinned_advisory_match",
                            "Pinned advisory fixture matches a component",
                            "high",
                            "A package ecosystem, name, and version match the supplied pinned advisory fixture; legacy fixtures may omit the ecosystem.",
                            "Upgrade to the fixture's fixed version after independently verifying the advisory source.",
                        )
                    )
    limitations.append("Offline fixtures do not establish current vulnerability status or registry availability.")
    limitations.append(
        "Lockfile includes, substitutions, general YAML features, advisory version ranges, and dynamic action expressions are outside the bounded parser subsets."
    )
    return (
        issues,
        limitations,
        ["registered-adapter:advisory-snapshot@1", "registered-adapter:registry-resolution@1"],
        analyzed,
    )


def _credential_history(
    items: list[_Artifact], _as_of: datetime
) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    for artifact in items:
        if artifact.kind != "git_history" or not isinstance(artifact.content, dict):
            limitations.append(f"Unsupported credential-history artifact kind: {artifact.kind}.")
            continue
        records = artifact.content.get("occurrences")
        if not isinstance(records, list):
            issues.append(_unresolved(artifact, "credential_history"))
            continue
        analyzed.add(artifact.artifact_id)
        coverage = artifact.content.get("coverage")
        scanner_output = "scanner_version" in artifact.content
        if (
            len(records) > 5000
            or (
                scanner_output
                and (
                    not isinstance(coverage, dict)
                    or coverage.get("complete_within_configured_bounds") is not True
                    or type(coverage.get("commits_examined")) is not int
                    or coverage.get("commits_examined", 0) < 1
                    or artifact.content.get("assessment_status") == "insufficient_evidence"
                )
            )
            or (
                not records
                and not (
                    scanner_output
                    and isinstance(coverage, dict)
                    and coverage.get("complete_within_configured_bounds") is True
                    and artifact.content.get("assessment_status")
                    in ("no_synthetic_match_observed", "no_supported_match_observed")
                )
            )
        ):
            issues.append(_unresolved(artifact, "credential_history_coverage"))
        by_fingerprint: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records[:5000]:
            if not isinstance(record, dict):
                issues.append(_unresolved(artifact, "credential_occurrence"))
                continue
            if any(record.get(key) not in (None, "", False) for key in _SECRET_KEYS):
                raise ArtifactAssessmentError("credential_value_forbidden")
            fingerprint = record.get("fingerprint")
            if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{16,64}", fingerprint):
                by_fingerprint[fingerprint].append(record)
            else:
                issues.append(_unresolved(artifact, "credential_fingerprint"))
        for records_for_secret in by_fingerprint.values():
            exposed = any(record.get("exposed") is True for record in records_for_secret)
            redacted = all(record.get("redacted") is True for record in records_for_secret)
            rotated = any(record.get("rotated") is True for record in records_for_secret)
            if exposed and (not redacted or not rotated):
                issues.append(
                    _issue(
                        artifact,
                        "credential_not_contained",
                        "Potential credential exposure requires containment evidence",
                        "high",
                        "A fingerprint-correlated potential credential exposure lacks redaction or recorded rotation. Pattern matching does not establish credential validity.",
                        "Review the exposure, revoke or rotate valid credentials, remove reachable values, and preserve only opaque fingerprint evidence.",
                    )
                )
            identities = {
                record.get("author_id") for record in records_for_secret if isinstance(record.get("author_id"), str)
            }
            if exposed and not identities:
                issues.append(_unresolved(artifact, "exposure_identity_correlation"))
    limitations.append(
        "History inspection cannot prove provider-side revocation or absence from unreachable Git objects."
    )
    return (
        issues,
        limitations,
        ["registered-adapter:git-object-enumerator@1", "registered-adapter:provider-revocation-check@1"],
        analyzed,
    )


def _network(items: list[_Artifact], as_of: datetime) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    for artifact in items:
        if artifact.kind in NETWORK_KINDS:
            analyzed.add(artifact.artifact_id)
            result = inspect_network(artifact.kind, _structured(artifact), as_of)
            for code in sorted(result.codes):
                issues.append(
                    _issue(
                        artifact,
                        code,
                        "Imported network evidence conflicts with expectation",
                        "high" if code == "segmentation_mismatch" else "medium",
                        "A bounded policy prediction or supplied observation disagrees with an expected path or address set.",
                        "Correct the scoped policy or DNS configuration and collect fresh connectivity evidence.",
                    )
                )
            if result.incomplete:
                issues.append(_unresolved(artifact, "network_policy_evidence"))
            continue
        if artifact.kind == "pcap":
            limitations.append(
                "Packet capture parsing requires a pinned registered adapter; structured flows are supported."
            )
            continue
        if artifact.kind != "segmentation_model" or not isinstance(artifact.content, dict):
            limitations.append(f"Unsupported segmentation artifact kind: {artifact.kind}.")
            continue
        rules, expectations = artifact.content.get("rules"), artifact.content.get("expected_reachability")
        if (
            not isinstance(rules, list)
            or len(rules) > 5000
            or not isinstance(expectations, list)
            or not 0 < len(expectations) <= 256
            or any(
                not isinstance(r, dict)
                or r.get("action", "allow") not in ("allow", "deny")
                or not isinstance(r.get("from"), str)
                or not r["from"]
                or not isinstance(r.get("to"), str)
                or not r["to"]
                for r in rules
            )
        ):
            issues.append(_unresolved(artifact, "segmentation_model"))
            continue
        analyzed.add(artifact.artifact_id)
        graph: dict[str, set[str]] = defaultdict(set)
        for rule in rules:
            if rule.get("action", "allow") == "allow":
                graph[rule["from"]].add(rule["to"])

        def reachable(graph: dict[str, set[str]], start: str, end: str) -> bool:
            pending, seen = deque([start]), {start}
            while pending:
                node = pending.popleft()
                if node == end:
                    return True
                for neighbor in graph.get(node, set()):
                    if neighbor not in seen:
                        seen.add(neighbor)
                        pending.append(neighbor)
            return False

        for expectation in expectations:
            if (
                not isinstance(expectation, dict)
                or not isinstance(expectation.get("from"), str)
                or not isinstance(expectation.get("to"), str)
                or type(expectation.get("allowed")) is not bool
            ):
                issues.append(_unresolved(artifact, "reachability_expectation"))
                continue
            actual = reachable(graph, expectation["from"], expectation["to"])
            if actual != expectation["allowed"]:
                issues.append(
                    _issue(
                        artifact,
                        "segmentation_mismatch",
                        "Computed reachability conflicts with expectation",
                        "high" if actual else "medium",
                        "A bounded graph traversal of allow rules disagrees with an expected reachability assertion.",
                        "Correct the firewall or NetworkPolicy rule set and repeat the expected-path test.",
                    )
                )
        dns = artifact.content.get("dns")
        if dns is not None and (
            not isinstance(dns, dict) or any(not isinstance(value, (str, list)) for value in dns.values())
        ):
            issues.append(_unresolved(artifact, "dns_mapping"))
    limitations.append("Static policy and flow evidence cannot prove runtime enforcement or unobserved paths.")
    limitations.append(
        "Kubernetes predictions cover complete Pod/Namespace inventories and TCP/UDP NetworkPolicy rules; CNI, NAT, Services, host networking, SCTP and administrative policies require separate evidence. Supplied flows expire after 15 minutes and DNS records at their TTL."
    )
    return (
        issues,
        limitations,
        ["registered-adapter:pcap-flow-extractor@1", "registered-adapter:live-segmentation-probe@1"],
        analyzed,
    )


def _b64url_json(value: str) -> dict[str, Any] | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        result = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def _transport(
    items: list[_Artifact], as_of: datetime, *, verification_results: list[dict[str, Any]] | None = None
) -> tuple[list[_Issue], list[str], list[str], set[str]]:
    from cops.assessments.crypto_inputs import KINDS, verify_artifact

    issues: list[_Issue] = []
    analyzed: set[str] = set()
    limitations: list[str] = []
    jwks: dict[str, dict[str, Any]] = {}
    for artifact in items:
        if (
            artifact.kind == "jwks"
            and isinstance(artifact.content, dict)
            and isinstance(artifact.content.get("keys"), list)
        ):
            analyzed.add(artifact.artifact_id)
            for key in artifact.content["keys"][:1000]:
                if isinstance(key, dict) and isinstance(key.get("kid"), str):
                    jwks[key["kid"]] = key
    for artifact in items:
        if artifact.kind in KINDS:
            result = verify_artifact(artifact.kind, artifact.content, as_of=as_of)
            if verification_results is not None:
                verification_results.append(
                    {"artifact_id": artifact.artifact_id, "evidence_ref": artifact.evidence_ref, **result.to_dict()}
                )
            if result.status == "unknown":
                issues.append(_unresolved(artifact, result.code))
            else:
                analyzed.add(artifact.artifact_id)
                if result.status == "rejected":
                    issues.append(
                        _issue(
                            artifact,
                            result.code,
                            "Local cryptographic verification rejected supplied evidence",
                            "informational",
                            "The bounded verifier rejected the certificate or token under the supplied trust and authorization policy.",
                            "Review the expected identity, trust anchors, validity, algorithm, signature and authorization policy; then repeat verification.",
                            classification="observation",
                            verification="verified",
                            confidence="high",
                            uncertainty="This proves local rejection only; remote service acceptance and deployment security remain unverified.",
                        )
                    )
        elif artifact.kind == "tls_config" and isinstance(artifact.content, dict):
            chain = artifact.content.get("chain")
            hostname = artifact.content.get("hostname")
            if not isinstance(chain, list) or not chain or not isinstance(hostname, str):
                issues.append(_unresolved(artifact, "tls_configuration"))
                continue
            analyzed.add(artifact.artifact_id)
            for index, cert in enumerate(chain):
                if not isinstance(cert, dict):
                    issues.append(_unresolved(artifact, "certificate_metadata"))
                    continue
                not_before, not_after = _parse_time(cert.get("not_before")), _parse_time(cert.get("not_after"))
                if not_before is None or not_after is None:
                    issues.append(_unresolved(artifact, "certificate_time"))
                elif not_before > as_of or not_after < as_of:
                    issues.append(
                        _issue(
                            artifact,
                            "certificate_time_invalid",
                            "Certificate is outside its declared validity interval",
                            "high",
                            "Certificate metadata is not valid at the assessment time.",
                            "Replace or correct the certificate chain and repeat cryptographic validation.",
                        )
                    )
                if (
                    index + 1 < len(chain)
                    and isinstance(chain[index + 1], dict)
                    and cert.get("issuer") != chain[index + 1].get("subject")
                ):
                    issues.append(
                        _issue(
                            artifact,
                            "certificate_chain_link",
                            "Certificate chain metadata is discontinuous",
                            "high",
                            "A certificate issuer does not match the next certificate subject.",
                            "Supply and cryptographically validate a complete ordered chain.",
                        )
                    )
            leaf = chain[0] if isinstance(chain[0], dict) else {}
            sans = leaf.get("san", [])
            if not isinstance(sans, list) or hostname not in sans:
                issues.append(
                    _issue(
                        artifact,
                        "certificate_hostname",
                        "Certificate metadata does not cover the expected hostname",
                        "high",
                        "The expected hostname is absent from the supplied leaf SAN list.",
                        "Issue a certificate whose SAN covers the expected hostname.",
                    )
                )
            if (
                artifact.content.get("expected_mtls") is True
                and artifact.content.get("require_client_certificate") is not True
            ):
                issues.append(
                    _issue(
                        artifact,
                        "mtls_not_required",
                        "Expected mTLS configuration does not require a client certificate",
                        "high",
                        "The structured TLS configuration expects mTLS but does not require client certificates.",
                        "Require and validate client certificates against the intended trust store.",
                    )
                )
        elif artifact.kind == "jwt" and isinstance(artifact.content, str):
            parts = artifact.content.split(".")
            if len(parts) != 3:
                issues.append(_unresolved(artifact, "jwt_structure"))
                continue
            header, payload = _b64url_json(parts[0]), _b64url_json(parts[1])
            if header is None or payload is None:
                issues.append(_unresolved(artifact, "jwt_encoding"))
                continue
            analyzed.add(artifact.artifact_id)
            if str(header.get("alg", "")).lower() == "none":
                issues.append(
                    _issue(
                        artifact,
                        "jwt_alg_none",
                        "JWT declares the none algorithm",
                        "high",
                        "The JWT header disables cryptographic signing.",
                        "Reject unsigned tokens and allowlist an appropriate asymmetric algorithm.",
                    )
                )
            if not all(key in payload for key in ("exp", "aud", "iss")):
                issues.append(_unresolved(artifact, "jwt_claims"))
            kid = header.get("kid")
            if not isinstance(kid, str) or kid not in jwks:
                issues.append(_unresolved(artifact, "jwks_key_match"))
            elif isinstance(jwks[kid].get("alg"), str) and jwks[kid]["alg"] != header.get("alg"):
                issues.append(
                    _issue(
                        artifact,
                        "jwks_algorithm_mismatch",
                        "JWT algorithm conflicts with matching JWKS metadata",
                        "high",
                        "The token header algorithm does not match the same-key JWKS metadata.",
                        "Reject the token and align the issuer key and algorithm policy.",
                    )
                )
        elif artifact.kind != "jwks":
            limitations.append(f"Unsupported transport-identity artifact kind: {artifact.kind}.")
    limitations.append(
        "Typed certificate_chain and jwt_verification artifacts verify supplied signatures and local trust only. Legacy metadata artifacts do not verify signatures. Revocation, remote TLS negotiation and service token acceptance require separate evidence."
    )
    return (
        issues,
        limitations,
        [
            "registered-adapter:cryptographic-verification/v1 (cryptography==50.0.2)",
            "revocation evidence and live service validation",
        ],
        analyzed,
    )


_ANALYZERS: dict[str, Callable[[list[_Artifact], datetime], tuple[list[_Issue], list[str], list[str], set[str]]]] = {
    "application_security": _application_security,
    "foundry_security": _foundry_security,
    "compliance_evidence": _compliance,
    "forensic_evidence": _forensics,
    "malware_static": _malware,
    "cloud_configuration": _cloud,
    "supply_chain": _supply_chain,
    "credential_history": _credential_history,
    "network_segmentation": _network,
    "transport_identity": _transport,
}


def assess(
    capability: str,
    artifacts: Sequence[Mapping[str, object]],
    *,
    as_of: str,
    engagement_id: str = "eng-offline-artifact",
    result_id: str = "res-offline-artifact",
    scenario_id: str = "COPS-OFFLINE-ARTIFACT",
    max_artifacts: int = 64,
    max_artifact_bytes: int = 1_048_576,
    max_total_bytes: int = 4_194_304,
) -> dict[str, Any]:
    """Assess bounded supplied artifacts without execution or network access."""
    if capability not in CAPABILITIES:
        raise ArtifactAssessmentError("unsupported_capability")
    try:
        assessed_at = timestamp(as_of)
    except EvidenceError:
        raise ArtifactAssessmentError("invalid_as_of") from None
    prepared = _prepare_artifacts(
        artifacts,
        max_artifacts=max_artifacts,
        max_artifact_bytes=max_artifact_bytes,
        max_total_bytes=max_total_bytes,
    )
    verification_results: list[dict[str, Any]] = []
    if capability == "transport_identity":
        issues, specific_limits, prerequisites, analyzed = _transport(
            prepared, assessed_at, verification_results=verification_results
        )
    else:
        issues, specific_limits, prerequisites, analyzed = _ANALYZERS[capability](prepared, assessed_at)
    if not prepared or not analyzed:
        readiness = "insufficient_evidence"
    elif specific_limits:
        readiness = "limited"
    else:
        readiness = "supported"
    evidence = [
        {"artifact_id": item.artifact_id, "kind": item.kind, "sha256": item.sha256, "bytes": len(item.raw)}
        for item in prepared
    ]
    issue_keys = [(issue.code, issue.refs) for issue in issues]
    issue_counts = Counter(issue_keys)
    seen_issues: defaultdict[tuple[str, tuple[str, ...]], int] = defaultdict(int)
    findings = []
    for issue, issue_key in zip(issues, issue_keys, strict=True):
        seen_issues[issue_key] += 1
        findings.append(
            _finding(
                issue,
                capability=capability,
                engagement_id=engagement_id,
                result_id=result_id,
                scenario_id=scenario_id,
                created_at=as_of,
                occurrence=seen_issues[issue_key] if issue_counts[issue_key] > 1 else None,
            )
        )
    return {
        "schema_version": REPORT_SCHEMA,
        "capability": capability,
        "assessment_mode": "offline",
        "generated_at": as_of,
        "readiness": readiness,
        **({"verification_results": verification_results} if capability == "transport_identity" else {}),
        "findings": findings,
        "finding_codes": {finding["finding_id"]: issue.code for finding, issue in zip(findings, issues, strict=True)},
        "evidence": evidence,
        "coverage": {
            "artifact_count": len(prepared),
            "analyzed_artifact_count": len(analyzed),
            "kinds": sorted({item.kind for item in prepared}),
        },
        "limitations": sorted(set([DEFAULT_LIMITATION, *specific_limits])),
        "prerequisites": sorted(set(prerequisites)),
    }
