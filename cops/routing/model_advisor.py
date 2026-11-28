"""Offline model advice from explicit, time-bounded host capability evidence.

Catalog records are operator assertions, not verified entitlements. This module
never discovers providers, changes a model, executes catalog data, or authorizes
security operations. Model family names have no policy significance.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

TASK_KINDS = ("auto", "routine", "coding", "security-review", "adversarial-research")
COMPLEXITIES = ("auto", "simple", "standard", "complex")
EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
TIERS = ("efficient", "balanced", "flagship")
CAPABILITIES = ("general", "coding", "security", "advanced-security")
MAX_CATALOG_BYTES = 1024 * 1024
MAX_CATALOG_AGE = timedelta(hours=24)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")


class ModelCatalogError(ValueError):
    """A catalog cannot safely be used for model advice."""


def _fields(value: Any, required: set[str], location: str) -> None:
    if not isinstance(value, dict) or set(value) != required:
        raise ModelCatalogError(f"{location} must contain exactly the documented fields")


def _label(value: Any, maximum: int = 160) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and value.isprintable() and bool(value.strip())


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ModelCatalogError("observed_at must be an ISO 8601 timestamp with a timezone")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ModelCatalogError("observed_at must be an ISO 8601 timestamp with a timezone") from exc
    if result.tzinfo is None:
        raise ModelCatalogError("observed_at requires a timezone")
    try:
        return result.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ModelCatalogError("observed_at is outside the supported timestamp range") from exc


def _choices(value: Any, allowed: tuple[str, ...], location: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or item not in allowed for item in value)
        or len(set(value)) != len(value)
    ):
        raise ModelCatalogError(f"{location} must be a nonempty list of distinct supported values")


def parse_catalog(value: Any) -> dict[str, Any]:
    """Validate the strict v1 contract without inferring any missing evidence."""
    _fields(value, {"schema_version", "source", "observed_at", "models"}, "catalog")
    if value["schema_version"] != "cops.model-catalog/v1":
        raise ModelCatalogError("unsupported model catalog schema_version")
    if not _label(value["source"]):
        raise ModelCatalogError("catalog source must be a short printable evidence description")
    _timestamp(value["observed_at"])
    models = value["models"]
    if not isinstance(models, list) or len(models) > 256:
        raise ModelCatalogError("models must be a list of at most 256 records")
    identifiers: set[str] = set()
    for model in models:
        _fields(
            model, {"id", "family", "tier", "capabilities", "available", "access", "efforts", "preference"}, "model"
        )
        if not isinstance(model["id"], str) or not _ID.fullmatch(model["id"]):
            raise ModelCatalogError("model id must be a safe exact host identifier of at most 128 characters")
        if model["id"] in identifiers:
            raise ModelCatalogError("duplicate model id")
        identifiers.add(model["id"])
        if not _label(model["family"], 80):
            raise ModelCatalogError("model family must be a short printable label")
        if model["tier"] not in TIERS:
            raise ModelCatalogError("model tier must be efficient, balanced, or flagship")
        _choices(model["capabilities"], CAPABILITIES, "capabilities")
        if type(model["available"]) is not bool:
            raise ModelCatalogError("model available must be a boolean")
        if model["access"] not in ("granted", "denied", "unknown"):
            raise ModelCatalogError("model access must be granted, denied, or unknown")
        _choices(model["efforts"], EFFORTS, "efforts")
        if type(model["preference"]) is not int or not 0 <= model["preference"] <= 10000:
            raise ModelCatalogError("model preference must be an integer from 0 through 10000")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelCatalogError("duplicate JSON field")
        result[key] = value
    return result


def load_catalog(path: Path) -> dict[str, Any]:
    """Read bounded JSON; errors omit potentially sensitive paths and contents."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
    except OSError as exc:
        raise ModelCatalogError("cannot read model catalog") from exc
    if len(raw) > MAX_CATALOG_BYTES:
        raise ModelCatalogError("model catalog exceeds 1 MiB")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ModelCatalogError):
            raise
        raise ModelCatalogError("model catalog must be valid UTF-8 JSON") from exc
    return parse_catalog(value)


def assess_task(query: str, *, task_kind: str = "auto", complexity: str = "auto") -> dict[str, str]:
    """Explainable heuristics; explicit scope overrides resolve ambiguous prose."""
    if task_kind not in TASK_KINDS or complexity not in COMPLEXITIES:
        raise ValueError("unsupported task kind or complexity")
    text = query.casefold()
    if task_kind == "auto":
        # Documentation about a security topic does not itself need cyber access.
        docs = re.search(r"\b(documentation|readme|typo|wording|guide|comment)\b", text)
        behavior = re.search(
            r"\b(implement|debug|exploit|bypass|vulnerability|vulnerabilities|patch|code|review)\b", text
        )
        if docs and not behavior:
            task_kind = "routine"
        elif re.search(
            r"exploit (development|chain)|binary (analysis|exploitation)|reverse engineer|vulnerability research|adversarial research|penetration test|pentest|red.team",
            text,
        ):
            task_kind = "adversarial-research"
        elif re.search(
            r"secur(?:ity|e)|trust.boundar|authoriz|authenticat|credential|threat|untrusted|sandbox|cryptograph|bypass|vulnerabil|penetration|pentest",
            text,
        ):
            task_kind = "security-review"
        else:
            task_kind = "coding"
    if complexity == "auto":
        complexity = "simple" if task_kind == "routine" else "standard"
        if re.search(r"cross.system|multi.system|distributed|rearchitect|complex|migration", text):
            complexity = "complex"
    capability, tier, effort = {
        "routine": ("general", "efficient", "low"),
        "coding": ("coding", "balanced", "medium"),
        "security-review": ("security", "flagship", "high"),
        "adversarial-research": ("advanced-security", "flagship", "high"),
    }[task_kind]
    if complexity == "complex":
        tier, effort = "flagship", "high"
    elif task_kind == "coding" and complexity == "simple":
        tier, effort = "efficient", "low"
    return {
        "kind": task_kind,
        "complexity": complexity,
        "capability": capability,
        "minimum_tier": tier,
        "minimum_effort": effort,
        "reason": f"{task_kind} at {complexity} complexity requires {capability} capability, {tier} tier, and {effort} effort.",
    }


def _exclusions(model: dict[str, Any], task: dict[str, str]) -> list[str]:
    reasons = []
    if not model["available"]:
        reasons.append("unavailable")
    if model["access"] != "granted":
        reasons.append(f"access_{model['access']}")
    if task["capability"] not in model["capabilities"]:
        reasons.append("capability_missing")
    if TIERS.index(model["tier"]) < TIERS.index(task["minimum_tier"]):
        reasons.append("tier_insufficient")
    return reasons


def advise_models(
    query: str,
    *,
    catalog: dict[str, Any] | None = None,
    task_kind: str = "auto",
    complexity: str = "auto",
    current_model: str | None = None,
    current_effort: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Suggest eligible exact model/effort pairs without changing execution."""
    if current_effort is not None and current_effort not in EFFORTS:
        raise ValueError("unsupported current effort")
    task = assess_task(query, task_kind=task_kind, complexity=complexity)
    current: dict[str, Any] = {
        "status": "unverified",
        "model_id": current_model,
        "effort": current_effort,
        "reasons": ["current_settings_or_fresh_catalog_missing"],
    }
    result: dict[str, Any] = {
        "schema_version": "cops.model-advice/v1",
        "advisory_only": True,
        "status": "catalog_required",
        "task": task,
        "catalog": None,
        "recommendation": None,
        "alternatives": [],
        "excluded": {},
        "current": current,
        "next_action": "Discover the host's exact models, access, capabilities, and supported efforts; supply a fresh catalog.",
    }
    if catalog is None:
        return result
    catalog = parse_catalog(catalog)
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("now requires a timezone")
    observed = _timestamp(catalog["observed_at"])
    result["catalog"] = {
        "source": catalog["source"],
        "observed_at": catalog["observed_at"],
        "evidence": "operator_supplied",
    }
    if observed > now or now - observed > MAX_CATALOG_AGE:
        result["status"] = "catalog_future" if observed > now else "catalog_stale"
        result["next_action"] = (
            "Refresh host discovery; catalog evidence must be at most 24 hours old and not future dated."
        )
        return result

    candidates = []
    minimum = EFFORTS.index(task["minimum_effort"])
    for model in catalog["models"]:
        reasons = _exclusions(model, task)
        efforts = [effort for effort in EFFORTS[:3] if effort in model["efforts"] and EFFORTS.index(effort) >= minimum]
        if not efforts:
            reasons.append("automatic_effort_unsupported")
        if reasons:
            result["excluded"][model["id"]] = reasons
        else:
            candidates.append((model, efforts[0]))
        if model["id"] == current_model and current_effort is not None:
            current_reasons = _exclusions(model, task)
            if current_effort not in model["efforts"]:
                current_reasons.append("current_effort_unsupported")
            elif EFFORTS.index(current_effort) < minimum:
                current_reasons.append("current_effort_insufficient")
            current["status"] = "change_recommended" if current_reasons else "adequate"
            current["reasons"] = current_reasons
    if current_model and all(model["id"] != current_model for model in catalog["models"]):
        current["reasons"] = ["current_model_not_in_catalog"]

    candidates.sort(key=lambda pair: (TIERS.index(pair[0]["tier"]), pair[0]["preference"], pair[0]["id"]))
    suggestions = [
        {
            "model_id": model["id"],
            "family": model["family"],
            "tier": model["tier"],
            "effort": effort,
            "reason": "Available with granted access and sufficient catalog capabilities; ranked by tier, operator preference, then exact ID.",
        }
        for model, effort in candidates
    ]
    if suggestions:
        result["status"] = "suggested"
        result["recommendation"] = suggestions[0]
        result["alternatives"] = suggestions[1:]
        result["next_action"] = (
            "Current settings are adequate; retain them or review the suggested pair."
            if current["status"] == "adequate"
            else "Review the suggested pair and select it through the host before implementation; verify current settings if unknown."
        )
    else:
        result["status"] = "no_eligible_model"
        result["next_action"] = (
            "Review exclusions and obtain appropriate host access or narrow the task; do not silently downgrade."
        )
    return result
