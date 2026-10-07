"""Core logic for COPS Offensive Engagement Workbench."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from cops.engagement import build_action_plan, validate_engagement_intake


def run_engagement_plan_workflow(
    engagement_manifest: Path | dict[str, Any],
    *,
    tool_versions: Mapping[str, str],
    target: str = "10.100.0.10",
    scenario_id: str = "COPS-E03.01-S01",
    root: Path | None = None,
) -> dict[str, Any]:
    """Execute offline deterministic validation and plan compilation workflow."""
    if isinstance(engagement_manifest, Path):
        raw_doc = json.loads(engagement_manifest.read_text(encoding="utf-8"))
    else:
        raw_doc = engagement_manifest

    # Validate intake
    validated_eng = validate_engagement_intake(raw_doc)

    # Build reviewable action plan
    plan = build_action_plan(
        engagement=validated_eng,
        scenario=scenario_id,
        target=target,
        tool_versions=tool_versions,
        specialist_id="cops-pentest-specialist",
        mode=validated_eng.get("mode", "planning"),
        root=root,
    )

    return {
        "status": "passed",
        "engagement_id": validated_eng["engagement_id"],
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "target": target,
        "mode": validated_eng.get("mode", "planning"),
        "operations_count": len(plan.operations),
        "platform_prerequisites": plan.platform_prerequisites,
        "network_requests": 0,
    }
