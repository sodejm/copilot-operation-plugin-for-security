"""Explicit test-only authorization and worker compatibility fixtures."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from cops.contracts import ActionPlan, Engagement
from cops.evidence.canonical import digest
from cops.execution.authorization import (
    AuthorizationSigner,
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
    verify_execution_authorization,
)
from cops.execution.control import (
    ApprovalConsumptionReceipt,
    ApprovalControlError,
)
from cops.execution.process import BoundedProcessResult
from cops.execution.store import ApprovalStore
from cops.execution.worker import WorkerCapabilityInventory

_TEST_KEY_ID = "cops-tests-hmac-v1"
_TEST_SECRET_TEXT = "cops-test-only-authorization-secret-v1"
_TEST_SECRET = _TEST_SECRET_TEXT.encode("utf-8")
_TRUST_ENVIRONMENT_NAME = "COPS_TEST_AUTHORIZATION_SECRET"


class TestApprovalControl:
    """In-process approval authority used only by worker unit tests.

    The fake deliberately exposes the same consume-only surface as the
    production client. It still verifies and atomically consumes the persisted
    authorization so fail-before-consume assertions exercise the real store
    transition rather than a call counter alone.
    """

    __test__ = False

    def __init__(
        self,
        store: ApprovalStore,
        trust_store: AuthorizationTrustStore,
        engagement: Engagement,
        *,
        readiness_error: Exception | None = None,
    ) -> None:
        self.store = store
        self.trust_store = trust_store
        self.engagement = engagement
        self.readiness_error = readiness_error
        self.ready_workers: list[str] = []
        self.consume_calls: list[tuple[str, str, str]] = []
        self._issued_receipts: dict[int, ApprovalConsumptionReceipt] = {}

    def assert_ready(self, worker_identity: str) -> None:
        self.ready_workers.append(worker_identity)
        if self.readiness_error is not None:
            raise self.readiness_error

    def consume_authorization(
        self,
        authorization_id: str,
        action_plan: ActionPlan,
        worker_identity: str,
    ) -> ApprovalConsumptionReceipt:
        self.consume_calls.append((authorization_id, action_plan.plan_id, worker_identity))
        stored = self.store.get_authorization(authorization_id)
        verified = verify_execution_authorization(
            stored,
            action_plan,
            trust_store=self.trust_store,
            engagement=self.engagement,
            worker_identity=worker_identity,
        )
        consumed = self.store.atomically_consume(
            authorization_id,
            expected_authorization=verified,
            worker_identity=worker_identity,
        )
        receipt = ApprovalConsumptionReceipt(
            authorization_id=consumed.authorization_id,
            authorization_digest=digest(consumed.to_dict()),
            action_plan_id=consumed.action_plan_id,
            plan_digest=consumed.plan_digest,
            engagement_id=consumed.engagement_id,
            worker_identity=worker_identity,
            target=action_plan.target,
        )
        self._issued_receipts[id(receipt)] = receipt
        return receipt

    def validate_receipt_provenance(self, receipt: ApprovalConsumptionReceipt) -> ApprovalConsumptionReceipt:
        if self._issued_receipts.get(id(receipt)) is not receipt:
            raise ApprovalControlError("approval receipt was not issued by this control client")
        return receipt


class TestExecutionSandbox:
    """Deterministic execution sandbox double with explicit readiness state."""

    __test__ = False

    def __init__(
        self,
        *,
        readiness_error: Exception | None = None,
        result: BoundedProcessResult | None = None,
        run_callback: Callable[..., BoundedProcessResult] | None = None,
    ) -> None:
        self.readiness_error = readiness_error
        self.result = result or BoundedProcessResult(
            stdout=b"",
            stderr=b"",
            returncode=0,
            timed_out=False,
            output_limit_exceeded=False,
        )
        self.run_callback = run_callback
        self.ready_calls: list[tuple[str, Path]] = []
        self.run_calls: list[dict[str, Any]] = []

    def assert_ready(self, worker_identity: str, *, cwd: Path) -> None:
        self.ready_calls.append((worker_identity, cwd))
        if self.readiness_error is not None:
            raise self.readiness_error

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: float,
        max_output_bytes: int,
        executable_fd: int | None = None,
        pass_fds: tuple[int, ...] = (),
        operation_env: Mapping[str, str] | None = None,
        capability_fds: tuple[int, ...] = (),
    ) -> BoundedProcessResult:
        call = {
            "command": tuple(command),
            "cwd": cwd,
            "env": dict(env),
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "executable_fd": executable_fd,
            "pass_fds": pass_fds,
            "operation_env": dict(operation_env or {}),
            "capability_fds": capability_fds,
        }
        self.run_calls.append(call)
        if self.run_callback is not None:
            return self.run_callback(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                executable_fd=executable_fd,
                pass_fds=pass_fds,
                operation_env=operation_env,
                capability_fds=capability_fds,
            )
        return self.result


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
                "allowed_actions": sorted({str(operation["action"]) for operation in plan.operations}),
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
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2030-01-01T00:00:00Z",
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
                        "secret_env": _TRUST_ENVIRONMENT_NAME,
                        "valid_from_utc": "2026-01-01T00:00:00Z",
                        "valid_until_utc": "2030-01-01T00:00:00Z",
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_path.chmod(0o600)
    return output_path


def authorization_secret_environment() -> dict[str, str]:
    """Return the explicit environment input used by trust-store loading tests."""

    return {_TRUST_ENVIRONMENT_NAME: _TEST_SECRET_TEXT}


def worker_inventory_for_plan(
    plan: ActionPlan,
    *,
    worker_identity: str,
    allowed_tools: Iterable[str] | None = None,
) -> WorkerCapabilityInventory:
    """Build deterministic owner-provisioned capability evidence for ``plan``."""

    versions, _ = _worker_requirements_for_plan(plan)
    if allowed_tools is not None:
        versions = {tool: versions.get(tool, "1.0.0") for tool in allowed_tools}
    document = {
        "schema_version": WorkerCapabilityInventory.SCHEMA_VERSION,
        "worker_identity": worker_identity,
        "measured_at": "2026-01-01T00:00:00Z",
        "measurement_source": "test-provisioner",
        "tool_versions": versions,
        "platform_capabilities": list(plan.platform_prerequisites),
    }
    with tempfile.TemporaryDirectory(prefix="cops-test-inventory-") as temporary_directory:
        path = Path(temporary_directory) / "inventory.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return WorkerCapabilityInventory.from_file(
            path,
            expected_worker_identity=worker_identity,
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
