"""Security regressions for authenticated, immutable execution plans."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from cops.contracts.models import ActionPlan, Engagement, ExecutionAuthorization
from cops.execution.authorization import (
    AuthorizationError,
    AuthorizationSigner,
    AuthorizationTrustStore,
    TrustedAuthorizationKey,
    create_execution_authorization,
    verify_execution_authorization,
)
from cops.execution.store import ApprovalStore, ApprovalStoreConflictError
from cops.execution.worker import (
    IsolatedWorker,
    WorkerCapabilityInventory,
    WorkerConfig,
    WorkerExecutionError,
    WorkerIsolationError,
)

SECRET = b"issue-184-test-key-material-32-bytes-minimum"
ISSUED = "2026-10-02T10:00:00Z"
EXPIRES = "2026-10-02T12:00:00Z"


@pytest.fixture
def engagement() -> Engagement:
    return Engagement.from_dict(
        {
            "schema_version": "cops.engagement/v1",
            "engagement_id": "eng-auth-plan-test",
            "name": "Authenticated plan test",
            "status": "active",
            "scope": {"included_targets": ["10.0.0.5"], "excluded_targets": []},
            "window": {
                "started_at": "2026-10-02T09:00:00Z",
                "authorized_until_utc": "2026-10-02T13:00:00Z",
            },
            "operator": "operator@example.test",
            "rules_of_engagement": {
                "max_intensity": "low",
                "allowed_actions": ["port_scan"],
                "emergency_contact": "soc@example.test",
                "safe_mode": True,
            },
            "created_at": "2026-10-02T09:00:00Z",
        }
    )


@pytest.fixture
def plan() -> ActionPlan:
    return ActionPlan.create(
        plan_id="plan-auth-test",
        engagement_id="eng-auth-plan-test",
        scenario_id="COPS-E01.03-S01",
        target="10.0.0.5",
        specialist_id="cops-network-specialist",
        operations=[
            {
                "step_id": "step-1",
                "tool": "nmap",
                "tool_version": "7.94",
                "action": "port_scan",
                "arguments": {"ports": [80, 443], "options": {"timing": 3}},
                "timeout_seconds": 60,
                "side_effects": ["network_connections"],
                "cleanup": {"strategy": "none", "resources": []},
            }
        ],
        limits={
            "max_duration_seconds": 300,
            "max_output_bytes": 65536,
            "egress_allowed": False,
        },
        credential_references=["corp_service_account_ref"],
        created_at=ISSUED,
        platform_prerequisites=["linux"],
        batch={"mode": "sequential", "max_operations": 1, "fail_fast": True},
    )


@pytest.fixture
def signer() -> AuthorizationSigner:
    return AuthorizationSigner(
        key_id="operator-key-2026q4",
        operator="operator@example.test",
        secret=SECRET,
        valid_from="2026-10-02T09:00:00Z",
        valid_until="2026-10-02T13:00:00Z",
    )


@pytest.fixture
def trust_store() -> AuthorizationTrustStore:
    return AuthorizationTrustStore(
        [
            TrustedAuthorizationKey(
                key_id="operator-key-2026q4",
                operator="operator@example.test",
                secret=SECRET,
                valid_from="2026-10-02T09:00:00Z",
                valid_until="2026-10-02T13:00:00Z",
            )
        ]
    )


@pytest.fixture
def authorization(plan, signer, engagement) -> ExecutionAuthorization:
    return create_execution_authorization(
        plan,
        signer=signer,
        engagement=engagement,
        worker_identity="worker-01",
        issued_at=ISSUED,
        authorized_until_utc=EXPIRES,
        authorization_id="auth-issue184-test",
    )


def _verify(auth, plan, trust_store, engagement):
    return verify_execution_authorization(
        auth,
        plan,
        trust_store=trust_store,
        engagement=engagement,
        worker_identity="worker-01",
        current_time_iso="2026-10-02T10:30:00Z",
    )


def test_signed_authorization_binds_exact_full_plan(authorization, plan, trust_store, engagement):
    assert _verify(authorization, plan, trust_store, engagement) is authorization
    bound = authorization.to_dict()["bound_parameters"]["action_plan"]
    assert bound == plan.approved_snapshot(include_digest=True)
    assert bound["operations"][0]["tool_version"] == "7.94"
    assert bound["batch"]["max_operations"] == 1


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("target",), "10.0.0.6"),
        (("specialist_id",), "other-specialist"),
        (("operations", 0, "action"), "service_detection"),
        (("operations", 0, "tool_version"), "7.95"),
        (("operations", 0, "arguments", "ports", 1), 8443),
        (("operations", 0, "side_effects", 0), "writes_remote_state"),
        (("operations", 0, "cleanup", "resources"), ["remote-temp-file"]),
        (("credential_references", 0), "different_ref"),
        (("limits", "max_output_bytes"), 99999),
        (("batch", "max_operations"), 2),
        (("platform_prerequisites", 0), "windows"),
    ],
)
def test_every_approved_nested_field_changes_plan_digest(plan, path, replacement):
    document = plan.to_dict()
    cursor = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = replacement
    document.pop("plan_digest")
    rebuilt = ActionPlan.create(
        **{key: value for key, value in document.items() if key not in {"schema_version", "status"}}
    )
    assert rebuilt.plan_digest != plan.plan_digest


def test_approved_plan_fields_are_deeply_immutable(plan):
    with pytest.raises(TypeError):
        plan.operations[0]["arguments"]["options"]["timing"] = 5
    with pytest.raises(TypeError):
        plan.limits["max_output_bytes"] = 1
    with pytest.raises(TypeError):
        plan.batch["max_operations"] = 2
    with pytest.raises(AttributeError):
        plan.credential_references.append("another-ref")


def test_approved_plan_and_authorization_fields_cannot_be_deleted(plan, authorization):
    with pytest.raises(AttributeError):
        del plan.target
    with pytest.raises(AttributeError):
        del authorization.operator


def test_immutable_field_registry_cannot_be_replaced(plan):
    with pytest.raises(AttributeError):
        plan._immutable_fields = frozenset()
    with pytest.raises(AttributeError):
        plan.target = "10.0.0.6"


def test_lifecycle_can_change_without_changing_approved_snapshot(plan):
    snapshot = plan.approved_snapshot(include_digest=True)
    plan.transition_to("pending_approval")
    assert plan.status == "pending_approval"
    assert plan.approved_snapshot(include_digest=True) == snapshot


def test_unsigned_authorization_id_or_rehashed_public_fields_cannot_forge(authorization, plan, trust_store, engagement):
    tampered = authorization.to_dict()
    tampered["authorization_id"] = "auth-forged-id-1234"
    with pytest.raises(AuthorizationError, match="signature"):
        _verify(tampered, plan, trust_store, engagement)

    tampered = authorization.to_dict()
    tampered["bound_parameters"]["action_plan"]["target"] = "10.0.0.6"
    # An attacker can hash public fields but cannot produce the trusted HMAC.
    import hashlib
    import json

    tampered["signature_digest"] = hashlib.sha256(json.dumps(tampered, sort_keys=True).encode()).hexdigest()
    with pytest.raises(AuthorizationError, match="signature"):
        _verify(tampered, plan, trust_store, engagement)


def test_receipt_supplied_key_material_is_rejected(authorization, plan, trust_store, engagement):
    tampered = authorization.to_dict()
    tampered["verification_key"] = SECRET.hex()
    with pytest.raises(Exception):
        _verify(tampered, plan, trust_store, engagement)


def test_key_and_authorization_windows_must_fit_engagement(plan, signer, engagement):
    with pytest.raises(AuthorizationError, match="engagement window"):
        create_execution_authorization(
            plan,
            signer=signer,
            engagement=engagement,
            worker_identity="worker-01",
            issued_at=ISSUED,
            authorized_until_utc="2026-10-02T14:00:00Z",
        )


def test_authorization_expiry_is_exclusive(authorization, plan, trust_store, engagement):
    assert not authorization.is_valid_at(EXPIRES)
    with pytest.raises(AuthorizationError, match="not currently valid"):
        verify_execution_authorization(
            authorization,
            plan,
            trust_store=trust_store,
            engagement=engagement,
            worker_identity="worker-01",
            current_time_iso=EXPIRES,
        )


def _write_inventory(tmp_path, **overrides):
    document = {
        "schema_version": WorkerCapabilityInventory.SCHEMA_VERSION,
        "worker_identity": "worker-01",
        "measured_at": "2026-10-02T09:30:00Z",
        "measurement_source": "trusted-provisioner",
        "tool_versions": {"nmap": "7.94"},
        "platform_capabilities": ["linux"],
    }
    document.update(overrides)
    path = tmp_path / "worker-inventory.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_worker_inventory_provisions_exact_trusted_capabilities(tmp_path):
    inventory = WorkerCapabilityInventory.from_file(_write_inventory(tmp_path), expected_worker_identity="worker-01")
    config = WorkerConfig.from_inventory(inventory)
    assert config.worker_id == "worker-01"
    assert config.tool_versions == {"nmap": "7.94"}
    assert config.platform_capabilities == ("linux",)


def test_worker_accepts_inventory_not_caller_supplied_config(tmp_path):
    inventory = WorkerCapabilityInventory.from_file(_write_inventory(tmp_path))
    config = WorkerConfig.from_inventory(inventory)
    with pytest.raises(TypeError):
        config.tool_versions["nmap"] = "7.95"
    with pytest.raises(WorkerIsolationError, match="inventory"):
        IsolatedWorker(
            config,
            object(),
            object(),
        )
    unverified = WorkerCapabilityInventory(
        schema_version=WorkerCapabilityInventory.SCHEMA_VERSION,
        worker_identity="worker-01",
        measured_at="2026-10-02T09:30:00Z",
        measurement_source="caller-supplied",
        tool_versions={"nmap": "7.94"},
        platform_capabilities=("linux",),
    )
    with pytest.raises(WorkerIsolationError, match="verified"):
        IsolatedWorker(
            unverified,
            object(),
            object(),
        )


def test_worker_inventory_rejects_insecure_permissions(tmp_path):
    path = _write_inventory(tmp_path)
    path.chmod(0o644)
    with pytest.raises(WorkerIsolationError, match="permissions"):
        WorkerCapabilityInventory.from_file(path)


def test_worker_inventory_rejects_identity_mismatch(tmp_path):
    with pytest.raises(WorkerIsolationError, match="identity"):
        WorkerCapabilityInventory.from_file(_write_inventory(tmp_path), expected_worker_identity="worker-02")


@pytest.mark.parametrize(
    "measured_at",
    [
        "not-a-timestamp",
        (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
    ],
)
def test_worker_inventory_rejects_invalid_or_future_measurement(tmp_path, measured_at):
    with pytest.raises(WorkerIsolationError, match="measurement time"):
        WorkerCapabilityInventory.from_file(_write_inventory(tmp_path, measured_at=measured_at))


def test_worker_rejects_measured_tool_version_different_from_signed_plan(tmp_path, plan):
    inventory = WorkerCapabilityInventory.from_file(_write_inventory(tmp_path, tool_versions={"nmap": "7.95"}))
    worker = object.__new__(IsolatedWorker)
    worker.config = WorkerConfig.from_inventory(inventory)
    with pytest.raises(WorkerExecutionError, match="does not match approved version"):
        worker._verify_plan_compatibility(plan)


def test_unknown_revoked_and_operator_mismatched_keys_fail_closed(authorization, plan, engagement):
    cases = [
        TrustedAuthorizationKey(
            key_id="another-key",
            operator="operator@example.test",
            secret=SECRET,
            valid_from="2026-10-02T09:00:00Z",
            valid_until="2026-10-02T13:00:00Z",
        ),
        TrustedAuthorizationKey(
            key_id="operator-key-2026q4",
            operator="operator@example.test",
            secret=SECRET,
            status="revoked",
        ),
        TrustedAuthorizationKey(
            key_id="operator-key-2026q4",
            operator="other@example.test",
            secret=SECRET,
            valid_from="2026-10-02T09:00:00Z",
            valid_until="2026-10-02T13:00:00Z",
        ),
    ]
    for key in cases:
        with pytest.raises(AuthorizationError):
            _verify(authorization, plan, AuthorizationTrustStore([key]), engagement)


def test_persisted_store_consumes_once_across_independent_handles(tmp_path, authorization):
    db_path = tmp_path / "approvals.sqlite3"
    ApprovalStore(db_path).store_authorization(authorization)

    def consume():
        return ApprovalStore(db_path).atomically_consume(
            authorization.authorization_id,
            worker_identity="worker-01",
            current_time_iso="2026-10-02T10:30:00Z",
            expected_authorization=authorization,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [future.exception() or future.result() for future in [pool.submit(consume), pool.submit(consume)]]

    assert sum(isinstance(item, ExecutionAuthorization) for item in outcomes) == 1
    assert sum(isinstance(item, ApprovalStoreConflictError) for item in outcomes) == 1
