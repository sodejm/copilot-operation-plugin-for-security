"""Action plan compilation from authorized engagements and scenarios."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import uuid

from cops.catalog import ROOT
from cops.contracts.models import ActionPlan, Engagement, Scenario
from cops.scenarios import get_scenario
from .errors import (
    EngagementIntakeError,
    IncompleteLiveRequestError,
    ScopeAmbiguityError,
)
from .intake import validate_engagement_intake


def build_action_plan(
    *,
    engagement: Engagement | dict[str, Any],
    scenario: Scenario | dict[str, Any] | str,
    target: str,
    specialist_id: str = "cops-pentest-specialist",
    mode: str | None = None,
    plan_id: str | None = None,
    created_at: str | None = None,
    root: Path | None = None,
) -> ActionPlan:
    """Compile an immutable, reviewable ActionPlan from an engagement and scenario.

    Enforces platform prerequisites, expected evidence, side effects, and cleanup obligations.
    Refuses incomplete live requests and distinguishes planning, import, laboratory, and live execution modes.
    """
    # 1. Normalize and validate engagement
    if isinstance(engagement, Engagement):
        eng_data = engagement.to_dict()
    elif isinstance(engagement, dict):
        eng_data = dict(engagement)
    else:
        raise EngagementIntakeError(f"Unsupported engagement input type: {type(engagement)}")

    validated_eng = validate_engagement_intake(eng_data)
    eng_id = validated_eng["engagement_id"]

    # 2. Scope verification for target
    included = [str(t).strip().lower() for t in validated_eng["scope"]["included_targets"]]
    excluded = [str(t).strip().lower() for t in validated_eng["scope"].get("excluded_targets", [])]
    target_clean = target.strip()
    target_lower = target_clean.lower()

    if target_lower not in included:
        raise ScopeAmbiguityError(
            f"Target '{target_clean}' is not present in engagement included_targets: {validated_eng['scope']['included_targets']}"
        )
    if target_lower in excluded:
        raise ScopeAmbiguityError(
            f"Target '{target_clean}' is explicitly listed in engagement excluded_targets"
        )

    # 3. Mode determination and live request guard
    resolved_mode = mode or validated_eng.get("mode", "planning")
    if resolved_mode not in ("planning", "import", "laboratory", "live"):
        raise EngagementIntakeError(f"Unsupported execution mode '{resolved_mode}'")

    if resolved_mode == "live":
        # Ensure intake passed live checks
        if validated_eng.get("mode") != "live":
            # If engagement wasn't marked live, re-validate with live mode
            temp_eng = dict(validated_eng)
            temp_eng["mode"] = "live"
            validate_engagement_intake(temp_eng)

    # 4. Resolve scenario
    if isinstance(scenario, str):
        scen_data = get_scenario(scenario_id=scenario, root=root or ROOT)
    elif isinstance(scenario, Scenario):
        scen_data = scenario.to_dict()
    elif isinstance(scenario, dict):
        scen_data = scenario
    else:
        raise EngagementIntakeError(f"Unsupported scenario input type: {type(scenario)}")

    scen_id = scen_data.get("scenario_id", "unknown-scenario")
    env = scen_data.get("environment", {})
    safety = scen_data.get("safety_profile", {})
    mitre = scen_data.get("mitre_attack", {})

    # 5. Compile platform prerequisites
    platform_prerequisites: list[str] = []
    os_list = env.get("os", ["linux"])
    platform_prerequisites.append(f"Operating System: {', '.join(os_list)}")
    if env.get("isolated_worker_required", True):
        platform_prerequisites.append("Isolated execution worker: mandatory container boundary")
    tools = env.get("required_tools", ["python3", "cops"])
    platform_prerequisites.append(f"Required execution tools: {', '.join(tools)}")
    for prereq in scen_data.get("prerequisites", []):
        if prereq not in platform_prerequisites:
            platform_prerequisites.append(prereq)

    # 6. Compile operations with expected evidence, side effects, and cleanup
    budget = validated_eng.get("budget", {})
    max_duration = budget.get("max_duration_seconds", 3600)
    max_output = budget.get("max_output_bytes", 10485760)

    operation_tool = tools[0] if tools else "cops"
    tactics = mitre.get("tactics", ["discovery"])
    action_name = tactics[0] if tactics else "discovery"

    operations: list[dict[str, Any]] = [
        {
            "step_id": "step-01-execute",
            "tool": operation_tool,
            "action": action_name,
            "arguments": {
                "target": target_clean,
                "execution_mode": resolved_mode,
                "intensity": validated_eng["rules_of_engagement"].get("max_intensity", "low"),
                "safe_mode": validated_eng["rules_of_engagement"].get("safe_mode", True),
            },
            "timeout_seconds": min(max_duration, 600),
            "expected_evidence": [
                f"{scen_id}_evidence_receipt",
                "execution_trace_log",
            ],
            "side_effects": [
                f"{resolved_mode}_telemetry_probes",
                "temporary_working_cache",
            ],
            "cleanup": {
                "action": "cleanup_temporary_artifacts",
                "target": target_clean,
            },
            "idempotent": safety.get("reversible", True),
        }
    ]

    # 7. Compile limits
    limits: dict[str, Any] = {
        "max_duration_seconds": max_duration,
        "max_output_bytes": max_output,
        "egress_allowed": True if resolved_mode == "live" else False,
    }

    # 8. Compile credential references
    cred_refs = validated_eng.get("credential_references", [])

    # 9. Build ActionPlan
    if plan_id is None:
        import hashlib
        seed = f"{eng_id}:{scen_id}:{target_clean}"
        digest_hex = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
        plan_id = f"plan-cops-{digest_hex}"

    if created_at is None:
        created_at = validated_eng.get("created_at") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return ActionPlan.create(
        plan_id=plan_id,
        engagement_id=eng_id,
        scenario_id=scen_id,
        target=target_clean,
        specialist_id=specialist_id,
        operations=operations,
        limits=limits,
        credential_references=cred_refs,
        created_at=created_at,
        status="draft",
        platform_prerequisites=platform_prerequisites,
    )
