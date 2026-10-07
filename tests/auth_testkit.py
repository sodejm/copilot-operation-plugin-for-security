"""Explicit test-only authorization and worker compatibility fixtures."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from cops.contracts import ActionPlan, Engagement
from cops.execution.authorization import (
    AuthorizationSigner,
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
)
from cops.execution.worker import WorkerCapabilityInventory, WorkerConfig

_TEST_KEY_ID = "cops-tests-hmac-v1"
_TEST_SECRET_TEXT = "cops-test-only-authorization-secret-v1"
_TEST_SECRET = _TEST_SECRET_TEXT.encode("utf-8")
_TEST_SECRET_ENV = "COPS_TEST_AUTHORIZATION_SECRET"


def make_test_authorization_context(
    plan: ActionPlan,
) -> tuple[AuthorizationSigner, AuthorizationTrustStore, Engagement]:
    """Build a matching explicit signer, trust store, and engagement for ``plan``."""

    engagement = Engagement.from_dict(
        {
            "schema_version": "cops.engagement/v1",
            "engagement_id": plan.engagement_id,
            "name": "Authenticated execution test",
            "status": "active",
            "scope": {
                "included_targets": [plan.target],
                "excluded_targets": [],
            },
            "window": {
                "started_at": "2026-01-01T00:00:00Z",
                "authorized_until_utc": "2029-12-31T23:59:59Z",
            },
            "operator": "secops-lead",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": sorted(
                    {str(operation["action"]) for operation in plan.operations}
                ),
                "emergency_contact": "soc@example.test",
                "safe_mode": True,
            },
            "created_at": "2026-01-01T00:00:00Z",
            "mode": "laboratory",
        }
    )
    signer = AuthorizationSigner(
        key_id=_TEST_KEY_ID,
        operator=engagement.operator,
        secret=_TEST_SECRET,
    )
    trust_store = AuthorizationTrustStore(
        [
            TrustedAuthorizationKey(
                key_id=_TEST_KEY_ID,
                operator=engagement.operator,
                secret=_TEST_SECRET,
            )
        ]
    )
    return signer, trust_store, engagement


def authorize_test_plan(
    plan: ActionPlan,
    *,
    worker_identity: str,
    valid_hours: int = 1,
):
    """Authorize ``plan`` with explicit test-only trust and return its context."""

    signer, trust_store, engagement = make_test_authorization_context(plan)
    authorization = create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity=worker_identity,
        valid_hours=valid_hours,
    )
    return authorization, trust_store, engagement


def write_test_authorization_trust_store(path: str | Path) -> Path:
    """Write verifier-owned test trust metadata without embedding the secret."""

    output_path = Path(path)
    output_path.write_text(
        json.dumps(
            {
                "schema_version": "cops.authorization-trust-store/v1",
                "keys": [
                    {
                        "key_id": _TEST_KEY_ID,
                        "operator_identity": "secops-lead",
                        "algorithm": "hmac-sha256",
                        "secret_env": _TEST_SECRET_ENV,
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return output_path


def authorization_secret_environment() -> dict[str, str]:
    """Return the explicit environment input used by trust-store loading tests."""

    return {_TEST_SECRET_ENV: _TEST_SECRET_TEXT}


def worker_config_for_plan(
    plan: ActionPlan,
    *,
    worker_id: str,
    allowed_tools: Iterable[str] | None = None,
) -> WorkerConfig:
    """Build a worker configuration that exactly satisfies the plan contract."""

    versions, plan_tools = _worker_requirements_for_plan(plan)

    return WorkerConfig(
        worker_id=worker_id,
        allowed_tools=tuple(plan_tools if allowed_tools is None else allowed_tools),
        tool_versions=versions,
        platform_capabilities=tuple(plan.platform_prerequisites),
    )


def worker_inventory_for_plan(
    plan: ActionPlan,
    *,
    worker_identity: str,
) -> WorkerCapabilityInventory:
    """Build deterministic owner-provisioned capability evidence for ``plan``."""

    versions, _ = _worker_requirements_for_plan(plan)
    return WorkerCapabilityInventory(
        schema_version=WorkerCapabilityInventory.SCHEMA_VERSION,
        worker_identity=worker_identity,
        measured_at="2026-01-01T00:00:00Z",
        measurement_source="test-provisioner",
        tool_versions=versions,
        platform_capabilities=tuple(plan.platform_prerequisites),
    )


def write_test_worker_inventory(
    path: str | Path,
    inventory: WorkerCapabilityInventory,
) -> Path:
    """Write owner-only deterministic capability evidence for CLI tests."""

    output_path = Path(path)
    output_path.write_text(json.dumps(inventory.to_dict()), encoding="utf-8")
    output_path.chmod(0o600)
    return output_path


def _worker_requirements_for_plan(plan: ActionPlan) -> tuple[dict[str, str], list[str]]:
    """Return the plan's exact tool versions and stable tool order."""

    versions: dict[str, str] = {}
    plan_tools: list[str] = []
    for operation in plan.operations:
        tool = str(operation["tool"])
        version = str(operation["tool_version"])
        existing = versions.get(tool)
        if existing is not None and existing != version:
            raise ValueError(f"plan requires conflicting versions for tool {tool!r}")
        versions[tool] = version
        if tool not in plan_tools:
            plan_tools.append(tool)
    return versions, plan_tools
