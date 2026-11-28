"""MITRE ATT&CK coverage mapping, Attack Flow export, and gap analysis engine for COPS."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
MAPPING_ID_PATTERN = re.compile(r"^COPS-COV-[A-Za-z0-9_-]+$")

# Deterministic UUID namespace for reproducible Attack Flow exports
ATTACK_FLOW_NAMESPACE = uuid.UUID("3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f")

VALID_COVERAGE_ROLES = {"detection", "investigation", "prevention", "response"}
VALID_COVERAGE_MATURITIES = {"production", "preview", "hypothesis", "experimental"}
VALID_VALIDATION_STATES = {"validated", "unverified"}
VALID_COMPONENT_TYPES = {"hunt", "rule", "skill", "command", "graph_rule", "workflow", "intake"}
VALID_ONBOARDING_STATUSES = {"onboarded", "available_not_onboarded", "missing_data_source"}

VALID_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}


class CoverageError(ValueError):
    """Raised when coverage data, schema validation, or Attack Flow generation fails."""


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique in the pinned reference catalog."""

    id: str
    name: str
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    data_components: tuple[str, ...]
    revoked: bool
    deprecated: bool
    version: str
    url: str
    revoked_by: str | None = None


@dataclass(frozen=True)
class AttackReference:
    """The pinned MITRE ATT&CK reference bundle."""

    schema_version: str
    attck_version: str
    source: str
    license: str
    copyright: str
    attribution: str
    techniques: dict[str, Technique]


@dataclass(frozen=True)
class CapabilityRef:
    """A reference to an existing COPS plugin capability or analytic."""

    plugin_id: str
    component_type: str
    component_id: str
    query_or_analytic: str


@dataclass(frozen=True)
class EvidenceSourceRequirement:
    """A telemetry requirement defining product, table, fields, and onboarding status."""

    product: str
    table_or_log: str
    required_fields: tuple[str, ...]
    onboarding_status: str


@dataclass(frozen=True)
class CoverageMapping:
    """A single mapping between a COPS capability and a MITRE ATT&CK technique."""

    mapping_id: str
    technique_id: str
    technique_name: str
    tactic: str
    platforms: tuple[str, ...]
    data_component: str
    capability: CapabilityRef
    evidence_sources: tuple[EvidenceSourceRequirement, ...]
    coverage_role: str
    coverage_maturity: str
    validation_state: str
    validation_fixture: str | None
    time_window: str | None
    assumptions: tuple[str, ...]
    known_limitations: tuple[str, ...]
    last_reviewed: str
    attck_version: str


def deterministic_uuid(name: str) -> str:
    """Generate a reproducible UUID5 string for Attack Flow STIX objects."""
    return str(uuid.uuid5(ATTACK_FLOW_NAMESPACE, name))


def load_attack_reference(path: Path | None = None, root: Path = ROOT) -> AttackReference:
    """Load and validate the pinned MITRE ATT&CK reference catalog."""
    if path is None:
        path = root / "catalog" / "attack_reference.json"

    if not path.is_file():
        raise CoverageError(f"ATT&CK reference file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CoverageError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise CoverageError(f"Root of {path} must be a JSON object")

    schema_version = str(data.get("schema_version", ""))
    if schema_version != "cops.attack-reference/v1":
        raise CoverageError(f"Unsupported ATT&CK reference schema version: {schema_version}")

    attck_version = str(data.get("attck_version", ""))
    source = str(data.get("source", ""))
    license_str = str(data.get("license", ""))
    copyright_str = str(data.get("copyright", ""))
    attribution = str(data.get("attribution", ""))

    raw_techniques = data.get("techniques", [])
    if not isinstance(raw_techniques, list) or not raw_techniques:
        raise CoverageError("ATT&CK reference must contain a non-empty 'techniques' array")

    techniques: dict[str, Technique] = {}
    for idx, item in enumerate(raw_techniques):
        if not isinstance(item, dict):
            raise CoverageError(f"Technique at index {idx} must be an object")
        tech_id = str(item.get("id", ""))
        if not TECHNIQUE_ID_PATTERN.match(tech_id):
            raise CoverageError(f"Technique at index {idx} has invalid ID: {tech_id}")

        techniques[tech_id] = Technique(
            id=tech_id,
            name=str(item.get("name", "")),
            tactics=tuple(str(t) for t in item.get("tactics", [])),
            platforms=tuple(str(p) for p in item.get("platforms", [])),
            data_components=tuple(str(d) for d in item.get("data_components", [])),
            revoked=bool(item.get("revoked", False)),
            deprecated=bool(item.get("deprecated", False)),
            version=str(item.get("version", attck_version)),
            url=str(item.get("url", "")),
            revoked_by=str(item["revoked_by"]) if item.get("revoked_by") else None,
        )

    return AttackReference(
        schema_version=schema_version,
        attck_version=attck_version,
        source=source,
        license=license_str,
        copyright=copyright_str,
        attribution=attribution,
        techniques=techniques,
    )


def validate_coverage_catalog(
    catalog_data: dict[str, Any],
    reference: AttackReference,
    *,
    root: Path = ROOT,
    strict_reviews: bool = True,
) -> list[str]:
    """Validate coverage catalog data against schema rules and pinned reference data."""
    errors: list[str] = []

    if catalog_data.get("schema_version") != "cops.attack-coverage/v1":
        errors.append(f"Invalid schema_version: {catalog_data.get('schema_version')}")

    attck_version = str(catalog_data.get("attck_version", ""))
    if attck_version != reference.attck_version:
        errors.append(
            f"Coverage catalog ATT&CK version '{attck_version}' does not match "
            f"pinned reference version '{reference.attck_version}'"
        )

    mappings = catalog_data.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        errors.append("Coverage catalog must contain a non-empty 'mappings' list")
        return errors

    seen_mapping_ids: set[str] = set()
    seen_capability_techniques: set[tuple[str, str, str]] = set()

    for idx, item in enumerate(mappings):
        context = f"mappings[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{context} must be an object")
            continue

        mapping_id = str(item.get("mapping_id", ""))
        if not MAPPING_ID_PATTERN.match(mapping_id):
            errors.append(f"{context} has invalid mapping_id '{mapping_id}'")
        elif mapping_id in seen_mapping_ids:
            errors.append(f"{context} has duplicate mapping_id '{mapping_id}'")
        else:
            seen_mapping_ids.add(mapping_id)

        technique_id = str(item.get("technique_id", ""))
        if not TECHNIQUE_ID_PATTERN.match(technique_id):
            errors.append(f"{context} has invalid technique_id '{technique_id}'")
        elif technique_id not in reference.techniques:
            errors.append(f"{context} references unknown technique '{technique_id}'")
        else:
            ref_tech = reference.techniques[technique_id]
            if ref_tech.revoked:
                msg = f"{context} references revoked technique '{technique_id}'"
                if ref_tech.revoked_by:
                    msg += f" (revoked by {ref_tech.revoked_by})"
                errors.append(msg)
            elif ref_tech.deprecated and strict_reviews:
                errors.append(f"{context} references deprecated technique '{technique_id}'")

        item_attck_version = str(item.get("attck_version", ""))
        if item_attck_version != reference.attck_version:
            errors.append(
                f"{context} attck_version '{item_attck_version}' does not match "
                f"catalog version '{reference.attck_version}'"
            )

        tactic = str(item.get("tactic", ""))
        if tactic not in VALID_TACTICS:
            errors.append(f"{context} has invalid tactic '{tactic}'")

        platforms = item.get("platforms")
        if not isinstance(platforms, list) or not platforms:
            errors.append(f"{context} must provide non-empty platforms list")

        data_component = str(item.get("data_component", ""))
        if not data_component:
            errors.append(f"{context} data_component cannot be empty")

        cap = item.get("capability")
        if not isinstance(cap, dict):
            errors.append(f"{context} capability must be an object")
        else:
            plugin_id = str(cap.get("plugin_id", ""))
            component_type = str(cap.get("component_type", ""))
            component_id = str(cap.get("component_id", ""))
            query_or_analytic = str(cap.get("query_or_analytic", ""))

            if not plugin_id or not component_id or not query_or_analytic:
                errors.append(f"{context}.capability has empty required fields")
            if component_type not in VALID_COMPONENT_TYPES:
                errors.append(f"{context}.capability has invalid component_type '{component_type}'")

            cap_tech_key = (plugin_id, component_id, technique_id)
            if cap_tech_key in seen_capability_techniques:
                errors.append(
                    f"{context} duplicates mapping for capability "
                    f"'{plugin_id}:{component_id}' and technique '{technique_id}'"
                )
            seen_capability_techniques.add(cap_tech_key)

        sources = item.get("evidence_sources")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{context} evidence_sources must be a non-empty list")
        else:
            for s_idx, src in enumerate(sources):
                s_context = f"{context}.evidence_sources[{s_idx}]"
                if not isinstance(src, dict):
                    errors.append(f"{s_context} must be an object")
                    continue
                product = str(src.get("product", ""))
                table = str(src.get("table_or_log", ""))
                req_fields = src.get("required_fields")
                onboarding = str(src.get("onboarding_status", ""))

                if not product or not table:
                    errors.append(f"{s_context} product and table_or_log must be non-empty")
                if not isinstance(req_fields, list) or not req_fields:
                    errors.append(f"{s_context} required_fields must be a non-empty list")
                if onboarding not in VALID_ONBOARDING_STATUSES:
                    errors.append(f"{s_context} invalid onboarding_status '{onboarding}'")

        coverage_role = str(item.get("coverage_role", ""))
        if coverage_role not in VALID_COVERAGE_ROLES:
            errors.append(f"{context} invalid coverage_role '{coverage_role}'")

        coverage_maturity = str(item.get("coverage_maturity", ""))
        if coverage_maturity not in VALID_COVERAGE_MATURITIES:
            errors.append(f"{context} invalid coverage_maturity '{coverage_maturity}'")

        validation_state = str(item.get("validation_state", ""))
        if validation_state not in VALID_VALIDATION_STATES:
            errors.append(f"{context} invalid validation_state '{validation_state}'")

        fixture = item.get("validation_fixture")
        if validation_state == "validated":
            if not fixture or not isinstance(fixture, str):
                errors.append(
                    f"{context} marked as 'validated' but lacks required 'validation_fixture'"
                )
            elif root:
                fixture_path = root / fixture
                if not fixture_path.exists():
                    errors.append(
                        f"{context} validation_fixture path does not exist: {fixture}"
                    )

        limitations = item.get("known_limitations")
        if not isinstance(limitations, list) or not limitations:
            errors.append(f"{context} known_limitations must be a non-empty list")

    return errors


def load_attack_coverage(
    path: Path | None = None,
    reference: AttackReference | None = None,
    *,
    root: Path = ROOT,
    strict: bool = True,
) -> list[CoverageMapping]:
    """Load, validate, and parse coverage mappings into typed records."""
    if reference is None:
        reference = load_attack_reference(root=root)
    if path is None:
        path = root / "catalog" / "attack_coverage.json"

    if not path.is_file():
        raise CoverageError(f"Coverage file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CoverageError(f"Invalid JSON in {path}: {exc}") from exc

    errors = validate_coverage_catalog(data, reference, root=root, strict_reviews=strict)
    if errors:
        raise CoverageError(f"Coverage validation failed in {path}:\n - " + "\n - ".join(errors))

    records: list[CoverageMapping] = []
    for item in data["mappings"]:
        cap_dict = item["capability"]
        capability = CapabilityRef(
            plugin_id=str(cap_dict["plugin_id"]),
            component_type=str(cap_dict["component_type"]),
            component_id=str(cap_dict["component_id"]),
            query_or_analytic=str(cap_dict["query_or_analytic"]),
        )

        sources = tuple(
            EvidenceSourceRequirement(
                product=str(src["product"]),
                table_or_log=str(src["table_or_log"]),
                required_fields=tuple(str(f) for f in src["required_fields"]),
                onboarding_status=str(src["onboarding_status"]),
            )
            for src in item["evidence_sources"]
        )

        records.append(
            CoverageMapping(
                mapping_id=str(item["mapping_id"]),
                technique_id=str(item["technique_id"]),
                technique_name=str(item["technique_name"]),
                tactic=str(item["tactic"]),
                platforms=tuple(str(p) for p in item["platforms"]),
                data_component=str(item["data_component"]),
                capability=capability,
                evidence_sources=sources,
                coverage_role=str(item["coverage_role"]),
                coverage_maturity=str(item["coverage_maturity"]),
                validation_state=str(item["validation_state"]),
                validation_fixture=str(item["validation_fixture"]) if item.get("validation_fixture") else None,
                time_window=str(item["time_window"]) if item.get("time_window") else None,
                assumptions=tuple(str(a) for a in item.get("assumptions", [])),
                known_limitations=tuple(str(limitation) for limitation in item["known_limitations"]),
                last_reviewed=str(item["last_reviewed"]),
                attck_version=str(item["attck_version"]),
            )
        )

    return records


def generate_coverage_matrix(
    mappings: Sequence[CoverageMapping],
    reference: AttackReference | None = None,
) -> str:
    """Generate a clean, human-readable Markdown coverage matrix."""
    lines: list[str] = [
        "# COPS MITRE ATT&CK Coverage Matrix",
        "",
        "> [!IMPORTANT]",
        "> ATT&CK mappings represent **planning evidence and investigative structure**, not proof of control",
        "> effectiveness. Coverage claims distinguish between verified analytics and unverified proposals.",
        "> Match criteria retain uncertainty, and reports never assume absence of alerts indicates absence of adversary activity.",
        "",
    ]

    total_mappings = len(mappings)
    unique_techniques = len({m.technique_id for m in mappings})
    validated_count = sum(1 for m in mappings if m.validation_state == "validated")
    unverified_count = sum(1 for m in mappings if m.validation_state == "unverified")

    role_counts: dict[str, int] = {}
    for m in mappings:
        role_counts[m.coverage_role] = role_counts.get(m.coverage_role, 0) + 1

    lines.extend([
        "## Summary Metrics",
        "",
        "| Metric | Count | Description |",
        "| :--- | :--- | :--- |",
        f"| **Total Mappings** | {total_mappings} | Total capability-to-technique associations |",
        f"| **Distinct Techniques** | {unique_techniques} | Unique ATT&CK techniques and sub-techniques |",
        f"| **Validated Analytics** | {validated_count} | Backed by automated deterministic offline test fixtures |",
        f"| **Unverified / Experimental** | {unverified_count} | Draft analytics without automated test verification |",
        f"| **Detective Coverage** | {role_counts.get('detection', 0)} | Threat hunting and detection engineering queries |",
        f"| **Investigative Coverage** | {role_counts.get('investigation', 0)} | Deep-dive triage, entity tracing, and path analysis |",
        f"| **Preventive Coverage** | {role_counts.get('prevention', 0)} | Telemetry posture and configuration recommendations |",
        f"| **Response Coverage** | {role_counts.get('response', 0)} | Incident timeline and case handoff workflows |",
        "",
        "## Capabilities and Techniques",
        "",
        "| Technique ID | Technique Name | Tactic | Capability | Evidence Source | Role | Validation | Key Limitations |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for m in sorted(mappings, key=lambda x: (x.tactic, x.technique_id, x.capability.component_id)):
        sources_str = "<br>".join(f"{s.product}: `{s.table_or_log}`" for s in m.evidence_sources)
        cap_str = f"`{m.capability.plugin_id}`<br>({m.capability.component_id})"
        val_badge = "**Validated**" if m.validation_state == "validated" else "*Unverified (Draft)*"
        limitations_summary = m.known_limitations[0] if m.known_limitations else "None specified"
        if len(limitations_summary) > 75:
            limitations_summary = limitations_summary[:72] + "..."

        row = (
            f"| [`{m.technique_id}`](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}/) "
            f"| {m.technique_name} "
            f"| `{m.tactic}` "
            f"| {cap_str} "
            f"| {sources_str} "
            f"| `{m.coverage_role}` "
            f"| {val_badge} "
            f"| {limitations_summary} |"
        )
        lines.append(row)

    lines.extend([
        "",
        "## Review Workflow & Maintenance",
        "",
        "1. **Updating Mappings**: Modify `catalog/attack_coverage.json` and validate with `python3 -m cops coverage --check`.",
        "2. **Evidence Boundaries**: Do not promote an analytic from `unverified` to `validated` without specifying a reproducible test fixture in `validation_fixture`.",
        "3. **Version Synchronization**: Mappings target the pinned ATT&CK version (Enterprise v18.0). Deprecated or revoked objects are rejected by the validation gate.",
        "",
    ])

    return "\n".join(lines)


def evaluate_coverage_gaps(
    mappings: Sequence[CoverageMapping],
    reference: AttackReference,
    environment_profile: dict[str, Any] | None = None,
    target_techniques: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Evaluate coverage gaps, separating missing telemetry from missing analytics.

    Categorization:
      - no_data_source: Required telemetry is not supported by any product in the stack.
      - data_source_not_onboarded: Product supports telemetry, but log source is not onboarded.
      - required_fields_missing: Data source is onboarded, but required fields are absent.
      - analytic_absent: Telemetry is onboarded, but no COPS analytic covers this technique.
      - analytic_present_unvalidated: Analytic exists, but lacks deterministic test validation.
      - validated_coverage: Telemetry is onboarded and analytic is validated by tests.
    """
    if environment_profile is None:
        # Default baseline environment for illustration:
        # Sentinel + Entra + Defender onboarded with core tables
        environment_profile = {
            "available_products": [
                "Sentinel",
                "Entra ID",
                "Defender for Endpoint",
                "Microsoft 365",
            ],
            "onboarded_sources": {
                "Sentinel:SigninLogs": [
                    "TimeGenerated",
                    "UserPrincipalName",
                    "IPAddress",
                    "ResultType",
                    "AppDisplayName",
                    "Location",
                    "RiskLevelDuringSignIn",
                ],
                "Sentinel:AuditLogs": [
                    "TimeGenerated",
                    "OperationName",
                    "InitiatedBy",
                    "TargetResources",
                ],
                "Defender for Endpoint:DeviceProcessEvents": [
                    "TimeGenerated",
                    "DeviceName",
                    "FileName",
                    "ProcessCommandLine",
                    "AccountName",
                ],
                "Microsoft 365:OfficeActivity": [
                    "TimeGenerated",
                    "UserId",
                    "Operation",
                    "Parameters",
                    "SourceFileName",
                    "SiteUrl",
                ],
            },
        }

    available_products = set(environment_profile.get("available_products", []))
    onboarded_sources = environment_profile.get("onboarded_sources", {})

    if target_techniques is None:
        target_techniques = sorted(reference.techniques.keys())

    telemetry_gaps: list[dict[str, Any]] = []
    analytics_gaps: list[dict[str, Any]] = []
    validated_coverage: list[dict[str, Any]] = []

    # Map techniques to available mappings
    tech_to_mappings: dict[str, list[CoverageMapping]] = {}
    for m in mappings:
        tech_to_mappings.setdefault(m.technique_id, []).append(m)

    for tech_id in target_techniques:
        tech = reference.techniques.get(tech_id)
        if tech is None or tech.revoked:
            continue

        relevant_mappings = tech_to_mappings.get(tech_id, [])

        if not relevant_mappings:
            # No analytic exists in COPS for this technique
            analytics_gaps.append({
                "technique_id": tech_id,
                "technique_name": tech.name,
                "tactics": tech.tactics,
                "category": "analytic_absent",
                "details": f"No COPS hunting, logging, or investigation analytic covers {tech_id}",
            })
            continue

        for m in relevant_mappings:
            # Check telemetry satisfaction for each mapping
            is_telemetry_satisfied = True
            telemetry_failure_category = ""
            telemetry_failure_details = ""

            for src in m.evidence_sources:
                key = f"{src.product}:{src.table_or_log}"
                if src.product not in available_products:
                    is_telemetry_satisfied = False
                    telemetry_failure_category = "no_data_source"
                    telemetry_failure_details = f"Product '{src.product}' is not part of environment telemetry stack"
                    break
                elif key not in onboarded_sources:
                    is_telemetry_satisfied = False
                    telemetry_failure_category = "data_source_not_onboarded"
                    telemetry_failure_details = f"Source '{key}' is available in product stack but not onboarded"
                    break
                else:
                    present_fields = set(onboarded_sources[key])
                    missing_fields = set(src.required_fields) - present_fields
                    if missing_fields:
                        is_telemetry_satisfied = False
                        telemetry_failure_category = "required_fields_missing"
                        telemetry_failure_details = (
                            f"Source '{key}' is onboarded but missing required fields: "
                            f"{', '.join(sorted(missing_fields))}"
                        )
                        break

            if not is_telemetry_satisfied:
                telemetry_gaps.append({
                    "technique_id": tech_id,
                    "technique_name": tech.name,
                    "mapping_id": m.mapping_id,
                    "capability": f"{m.capability.plugin_id}:{m.capability.component_id}",
                    "category": telemetry_failure_category,
                    "details": telemetry_failure_details,
                })
            else:
                # Telemetry is satisfied, evaluate analytic maturity
                if m.validation_state == "validated":
                    validated_coverage.append({
                        "technique_id": tech_id,
                        "technique_name": tech.name,
                        "mapping_id": m.mapping_id,
                        "capability": f"{m.capability.plugin_id}:{m.capability.component_id}",
                        "coverage_role": m.coverage_role,
                        "validation_fixture": m.validation_fixture,
                        "category": "validated_coverage",
                    })
                else:
                    analytics_gaps.append({
                        "technique_id": tech_id,
                        "technique_name": tech.name,
                        "mapping_id": m.mapping_id,
                        "capability": f"{m.capability.plugin_id}:{m.capability.component_id}",
                        "category": "analytic_present_unvalidated",
                        "details": f"Analytic {m.capability.component_id} is present but unvalidated (untested against fixtures)",
                    })

    return {
        "summary": {
            "total_evaluated": len(target_techniques),
            "validated_coverage_count": len(validated_coverage),
            "telemetry_gap_count": len(telemetry_gaps),
            "analytics_gap_count": len(analytics_gaps),
        },
        "telemetry_gaps": telemetry_gaps,
        "analytics_gaps": analytics_gaps,
        "validated_coverage": validated_coverage,
    }


def render_gap_report_markdown(gap_data: dict[str, Any]) -> str:
    """Render a gap analysis report in structured Markdown."""
    summary = gap_data["summary"]
    lines = [
        "# COPS ATT&CK Gap Analysis Report",
        "",
        "## Summary",
        "",
        f"- **Evaluated Techniques**: {summary['total_evaluated']}",
        f"- **Validated Coverage**: {summary['validated_coverage_count']}",
        f"- **Telemetry Gaps (Missing / Non-onboarded / Schema Mismatch)**: {summary['telemetry_gap_count']}",
        f"- **Analytics Gaps (Missing Analytics / Unvalidated Drafts)**: {summary['analytics_gap_count']}",
        "",
        "---",
        "",
        "## Telemetry Gaps",
        "",
        "Telemetry gaps represent situations where detection or investigation logic cannot function "
        "because logs are absent, unconfigured, or lack required fields.",
        "",
    ]

    if not gap_data["telemetry_gaps"]:
        lines.append("No telemetry gaps identified in current scope.\n")
    else:
        lines.extend([
            "| Technique | Mapping | Capability | Gap Category | Details |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for g in gap_data["telemetry_gaps"]:
            lines.append(
                f"| `{g['technique_id']}` ({g['technique_name']}) | `{g['mapping_id']}` | "
                f"`{g['capability']}` | `{g['category']}` | {g['details']} |"
            )
        lines.append("")

    lines.extend([
        "## Analytics Gaps",
        "",
        "Analytics gaps represent situations where required telemetry may exist, but detection/hunting "
        "rules are absent or have not been validated against deterministic test fixtures.",
        "",
    ])

    if not gap_data["analytics_gaps"]:
        lines.append("No analytics gaps identified in current scope.\n")
    else:
        lines.extend([
            "| Technique | Gap Category | Details |",
            "| :--- | :--- | :--- |",
        ])
        for a in gap_data["analytics_gaps"]:
            tech_label = f"`{a['technique_id']}` ({a['technique_name']})"
            lines.append(f"| {tech_label} | `{a['category']}` | {a['details']} |")
        lines.append("")

    lines.extend([
        "## Validated Coverage",
        "",
        "Techniques with satisfied telemetry dependencies and automated test verification.",
        "",
    ])

    if not gap_data["validated_coverage"]:
        lines.append("No validated coverage in current scope.\n")
    else:
        lines.extend([
            "| Technique | Mapping | Capability | Role | Fixture |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for v in gap_data["validated_coverage"]:
            lines.append(
                f"| `{v['technique_id']}` ({v['technique_name']}) | `{v['mapping_id']}` | "
                f"`{v['capability']}` | `{v['coverage_role']}` | `{v['validation_fixture']}` |"
            )
        lines.append("")

    return "\n".join(lines)


def generate_attack_flow(
    scenario_name: str,
    mappings: Sequence[CoverageMapping] | None = None,
    reference: AttackReference | None = None,
) -> dict[str, Any]:
    """Generate a MITRE Attack Flow STIX 2.1 bundle for representative threat scenarios.

    Supported scenarios:
      - 'azure-identity': Azure/Entra ID Identity Compromise to Role Assignment & Storage Exfiltration
      - 'm365-compromise': Microsoft 365 Phishing to Mailbox Forwarding & SharePoint Harvesting
    """
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    if scenario_name == "azure-identity":
        flow_id = deterministic_uuid("attack-flow-azure-identity")
        action_spray_id = deterministic_uuid("action-password-spray")
        cond_spray_compromise_id = deterministic_uuid("condition-credentials-obtained")
        action_signin_id = deterministic_uuid("action-cloud-signin")
        cond_active_session_id = deterministic_uuid("condition-active-session")
        action_role_assign_id = deterministic_uuid("action-role-assignment")
        cond_priv_escalation_id = deterministic_uuid("condition-privilege-escalation")
        # Branch 1: App Credential Addition (Persistence)
        action_app_cred_id = deterministic_uuid("action-app-credential-addition")
        cond_persistent_api_id = deterministic_uuid("condition-persistent-api")
        # Branch 2: Cloud Storage Access (Collection)
        action_blob_access_id = deterministic_uuid("action-cloud-blob-access")
        cond_data_exfil_id = deterministic_uuid("condition-data-exfiltrated")

        objects: list[dict[str, Any]] = [
            {
                "type": "attack-flow",
                "id": f"attack-flow--{flow_id}",
                "spec_version": "2.1",
                "name": "Azure / Entra ID Identity Compromise and Cloud Exfiltration",
                "description": "Representative end-to-end Attack Flow illustrating password spray, privileged cloud role assignment, API persistence, and cloud storage collection.",
                "created": now_iso,
                "modified": now_iso,
                "start_refs": [f"attack-action--{action_spray_id}"],
                "scope": "enterprise",
            },
            # Step 1: Password Spray
            {
                "type": "attack-action",
                "id": f"attack-action--{action_spray_id}",
                "spec_version": "2.1",
                "name": "Password Spray against Entra ID",
                "technique_id": "T1110.003",
                "technique_name": "Password Spraying",
                "tactic": "credential-access",
                "execution_order": 1,
                "evidence_refs": ["ev-intake-signins-01"],
                "capability_refs": ["sentinel-hunt-workbench:H01", "soc-investigation-workbench:intake"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_spray_compromise_id}",
                "spec_version": "2.1",
                "description": "Valid credentials obtained for user principal",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-spray-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_spray_id}",
                "target_ref": f"attack-condition--{cond_spray_compromise_id}",
            },
            # Step 2: Cloud Sign-In
            {
                "type": "attack-action",
                "id": f"attack-action--{action_signin_id}",
                "spec_version": "2.1",
                "name": "Sign-in to Azure Portal with Cloud Account",
                "technique_id": "T1078.004",
                "technique_name": "Cloud Accounts",
                "tactic": "initial-access",
                "execution_order": 2,
                "prerequisite_refs": [f"attack-condition--{cond_spray_compromise_id}"],
                "evidence_refs": ["ev-intake-signins-02"],
                "capability_refs": ["sentinel-hunt-workbench:H02"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_active_session_id}",
                "spec_version": "2.1",
                "description": "Active interactive session established on Azure Portal",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-signin-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_signin_id}",
                "target_ref": f"attack-condition--{cond_active_session_id}",
            },
            # Step 3: Privilege Escalation
            {
                "type": "attack-action",
                "id": f"attack-action--{action_role_assign_id}",
                "spec_version": "2.1",
                "name": "Assign Privileged Role to Target Identity",
                "technique_id": "T1098.003",
                "technique_name": "Additional Cloud Roles",
                "tactic": "privilege-escalation",
                "execution_order": 3,
                "prerequisite_refs": [f"attack-condition--{cond_active_session_id}"],
                "evidence_refs": ["ev-auditlogs-roleassign-01"],
                "capability_refs": ["sentinel-hunt-workbench:H10", "attack-path-workbench:attackpath"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_priv_escalation_id}",
                "spec_version": "2.1",
                "description": "Global Administrator or Contributor role assigned",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-role-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_role_assign_id}",
                "target_ref": f"attack-condition--{cond_priv_escalation_id}",
            },
            # Branch A: Service Principal Secret Addition
            {
                "type": "attack-action",
                "id": f"attack-action--{action_app_cred_id}",
                "spec_version": "2.1",
                "name": "Add Password / Certificate Credential to Service Principal",
                "technique_id": "T1098",
                "technique_name": "Account Manipulation",
                "tactic": "persistence",
                "execution_order": 4,
                "prerequisite_refs": [f"attack-condition--{cond_priv_escalation_id}"],
                "evidence_refs": ["ev-auditlogs-appcred-01"],
                "capability_refs": ["sentinel-hunt-workbench:H12"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_persistent_api_id}",
                "spec_version": "2.1",
                "description": "Persistent API access established via service principal",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-appcred-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_app_cred_id}",
                "target_ref": f"attack-condition--{cond_persistent_api_id}",
            },
            # Branch B: Cloud Storage Access
            {
                "type": "attack-action",
                "id": f"attack-action--{action_blob_access_id}",
                "spec_version": "2.1",
                "name": "Read Sensitive Data from Azure Blob Storage",
                "technique_id": "T1530",
                "technique_name": "Data from Cloud Storage",
                "tactic": "collection",
                "execution_order": 4,
                "prerequisite_refs": [f"attack-condition--{cond_priv_escalation_id}"],
                "evidence_refs": ["ev-storage-blob-01"],
                "capability_refs": ["sentinel-hunt-workbench:H-PREVIEW-STORAGE"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_data_exfil_id}",
                "spec_version": "2.1",
                "description": "Confidential cloud data extracted",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-blob-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_blob_access_id}",
                "target_ref": f"attack-condition--{cond_data_exfil_id}",
            },
        ]

        bundle_id = deterministic_uuid("bundle-azure-identity")
        return {
            "type": "bundle",
            "id": f"bundle--{bundle_id}",
            "spec_version": "2.1",
            "objects": objects,
        }

    elif scenario_name == "m365-compromise":
        flow_id = deterministic_uuid("attack-flow-m365-compromise")
        action_phish_id = deterministic_uuid("action-spearphish-link")
        cond_clicked_id = deterministic_uuid("condition-link-clicked")
        action_login_id = deterministic_uuid("action-m365-valid-account")
        cond_mailbox_access_id = deterministic_uuid("condition-mailbox-accessed")
        # Branch 1: Forwarding Rule
        action_forward_id = deterministic_uuid("action-email-forwarding-rule")
        cond_forward_active_id = deterministic_uuid("condition-forwarding-active")
        # Branch 2: SharePoint bulk harvest
        action_sp_harvest_id = deterministic_uuid("action-sharepoint-harvest")
        cond_sp_downloaded_id = deterministic_uuid("condition-sp-downloaded")

        objects = [
            {
                "type": "attack-flow",
                "id": f"attack-flow--{flow_id}",
                "spec_version": "2.1",
                "name": "Microsoft 365 Phishing to Email Forwarding and SharePoint Exfiltration",
                "description": "Representative end-to-end Attack Flow illustrating spearphishing, mailbox compromise, email forwarding rule creation, and bulk SharePoint exfiltration.",
                "created": now_iso,
                "modified": now_iso,
                "start_refs": [f"attack-action--{action_phish_id}"],
                "scope": "enterprise",
            },
            # Step 1: Spearphishing Link
            {
                "type": "attack-action",
                "id": f"attack-action--{action_phish_id}",
                "spec_version": "2.1",
                "name": "Spearphishing Link Click in Mailbox",
                "technique_id": "T1566.002",
                "technique_name": "Spearphishing Link",
                "tactic": "initial-access",
                "execution_order": 1,
                "evidence_refs": ["ev-urlclick-01"],
                "capability_refs": ["sentinel-hunt-workbench:H09"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_clicked_id}",
                "spec_version": "2.1",
                "description": "User credential entered into spoofed consent page",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-phish-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_phish_id}",
                "target_ref": f"attack-condition--{cond_clicked_id}",
            },
            # Step 2: Valid Account Sign-In
            {
                "type": "attack-action",
                "id": f"attack-action--{action_login_id}",
                "spec_version": "2.1",
                "name": "Authenticate to Exchange Online via Compromised Account",
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "initial-access",
                "execution_order": 2,
                "prerequisite_refs": [f"attack-condition--{cond_clicked_id}"],
                "evidence_refs": ["ev-intake-signins-03"],
                "capability_refs": ["sentinel-hunt-workbench:H01"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_mailbox_access_id}",
                "spec_version": "2.1",
                "description": "Attacker interactive access to Exchange Online and OneDrive",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-login-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_login_id}",
                "target_ref": f"attack-condition--{cond_mailbox_access_id}",
            },
            # Branch A: Email Forwarding Rule
            {
                "type": "attack-action",
                "id": f"attack-action--{action_forward_id}",
                "spec_version": "2.1",
                "name": "Create Malicious Inbox Forwarding Rule",
                "technique_id": "T1114.003",
                "technique_name": "Email Forwarding Rule",
                "tactic": "collection",
                "execution_order": 3,
                "prerequisite_refs": [f"attack-condition--{cond_mailbox_access_id}"],
                "evidence_refs": ["ev-officeactivity-inboxrule-01"],
                "capability_refs": ["sentinel-hunt-workbench:H07"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_forward_active_id}",
                "spec_version": "2.1",
                "description": "Incoming messages forwarded to external actor mailbox",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-forward-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_forward_id}",
                "target_ref": f"attack-condition--{cond_forward_active_id}",
            },
            # Branch B: SharePoint Bulk Download
            {
                "type": "attack-action",
                "id": f"attack-action--{action_sp_harvest_id}",
                "spec_version": "2.1",
                "name": "Bulk Download Confidential Documents from SharePoint",
                "technique_id": "T1213.002",
                "technique_name": "SharePoint",
                "tactic": "collection",
                "execution_order": 3,
                "prerequisite_refs": [f"attack-condition--{cond_mailbox_access_id}"],
                "evidence_refs": ["ev-officeactivity-spdownload-01"],
                "capability_refs": ["sentinel-hunt-workbench:H08"],
            },
            {
                "type": "attack-condition",
                "id": f"attack-condition--{cond_sp_downloaded_id}",
                "spec_version": "2.1",
                "description": "Bulk corporate document archive staged for exfiltration",
            },
            {
                "type": "relationship",
                "id": f"relationship--{deterministic_uuid('rel-sp-to-cond')}",
                "spec_version": "2.1",
                "relationship_type": "causes",
                "source_ref": f"attack-action--{action_sp_harvest_id}",
                "target_ref": f"attack-condition--{cond_sp_downloaded_id}",
            },
        ]

        bundle_id = deterministic_uuid("bundle-m365-compromise")
        return {
            "type": "bundle",
            "id": f"bundle--{bundle_id}",
            "spec_version": "2.1",
            "objects": objects,
        }

    else:
        raise CoverageError(
            f"Unknown scenario '{scenario_name}'. Supported scenarios: 'azure-identity', 'm365-compromise'"
        )


def review_coverage_freshness(
    mappings: Sequence[CoverageMapping],
    reference: AttackReference,
) -> dict[str, Any]:
    """Inspect mappings for deprecated/revoked ATT&CK techniques or version drift."""
    revoked_findings: list[dict[str, Any]] = []
    deprecated_findings: list[dict[str, Any]] = []
    version_drift_findings: list[dict[str, Any]] = []

    for m in mappings:
        tech = reference.techniques.get(m.technique_id)
        if tech is None:
            continue
        if tech.revoked:
            revoked_findings.append({
                "mapping_id": m.mapping_id,
                "technique_id": m.technique_id,
                "revoked_by": tech.revoked_by,
                "capability": f"{m.capability.plugin_id}:{m.capability.component_id}",
            })
        if tech.deprecated:
            deprecated_findings.append({
                "mapping_id": m.mapping_id,
                "technique_id": m.technique_id,
                "capability": f"{m.capability.plugin_id}:{m.capability.component_id}",
            })
        if m.attck_version != reference.attck_version:
            version_drift_findings.append({
                "mapping_id": m.mapping_id,
                "mapping_version": m.attck_version,
                "reference_version": reference.attck_version,
            })

    is_fresh = not (revoked_findings or deprecated_findings or version_drift_findings)
    return {
        "status": "fresh" if is_fresh else "needs_review",
        "revoked_count": len(revoked_findings),
        "deprecated_count": len(deprecated_findings),
        "version_drift_count": len(version_drift_findings),
        "revoked_findings": revoked_findings,
        "deprecated_findings": deprecated_findings,
        "version_drift_findings": version_drift_findings,
    }
