"""Security regressions for operation-scoped credential materialization."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cops.contracts.models import ActionPlan
from cops.execution.credentials import (
    CredentialGrant,
    CredentialResolutionError,
    ScopedCredentialResolver,
)
from cops.execution.store import ApprovalStore
from tests.auth_testkit import authorize_test_plan


class RecordingProvider:
    def __init__(self, value: str) -> None:
        self.value = value
        self.references: list[str] = []

    def resolve(self, reference: str) -> str:
        self.references.append(reference)
        return self.value


class SecretBearingFailureProvider:
    def resolve(self, reference: str) -> str:
        del reference
        raise RuntimeError("provider failed while handling secret-value-that-must-not-escape")


class FailingRedactor:
    def add_secrets(self, secrets: tuple[str, ...]) -> None:
        del secrets
        raise RuntimeError("redactor unavailable")


def _load_plan() -> ActionPlan:
    fixture = Path(__file__).parents[1] / "cops" / "contracts" / "fixtures" / "valid_action_plan.json"
    return ActionPlan.from_dict(json.loads(fixture.read_text(encoding="utf-8")))


def _consume(plan: ActionPlan, tmp_path: Path, worker_identity: str = "worker-credential-test"):
    authorization, _, _ = authorize_test_plan(plan, worker_identity=worker_identity)
    store = ApprovalStore(tmp_path / "approvals.sqlite3")
    store.store_authorization(authorization)
    consumed = store.atomically_consume(
        authorization.authorization_id,
        expected_authorization=authorization,
        worker_identity=worker_identity,
    )
    return authorization, consumed


def _grant(
    plan: ActionPlan,
    *,
    worker_identity: str = "worker-credential-test",
    environment_variable: str = "COPS_CREDENTIAL_SERVICE_TOKEN",
    reference: str | None = None,
    operation_index: int = 0,
) -> CredentialGrant:
    operation = plan.operations[operation_index]
    return CredentialGrant(
        reference=(str(plan.credential_references[0]) if reference is None else reference),
        environment_variable=environment_variable,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id,
        worker_identity=worker_identity,
        target=plan.target,
        step_id=str(operation["step_id"]),
        tool=str(operation["tool"]),
        tool_version=str(operation["tool_version"]),
        action=str(operation["action"]),
    )


def test_resolves_only_after_authority_consumption_and_registers_redaction(tmp_path: Path) -> None:
    plan = _load_plan()
    provider = RecordingProvider("short-secret")
    resolver = ScopedCredentialResolver(provider, [_grant(plan)])
    _, consumed = _consume(plan, tmp_path)

    operation_environment = resolver.resolve_for_operation(
        plan=plan,
        authorization=consumed,
        worker_identity="worker-credential-test",
        operation=plan.operations[0],
    )

    assert operation_environment == {"COPS_CREDENTIAL_SERVICE_TOKEN": "short-secret"}
    assert provider.references == ["corp_service_account_token_ref"]
    assert resolver.redactor.redact("output short-secret") == "output [REDACTED:SECRET]"


def test_unconsumed_authorization_is_denied_before_provider_lookup(tmp_path: Path) -> None:
    plan = _load_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(provider, [_grant(plan)])
    approved, _ = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="consumed worker authorization"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=approved,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )

    assert provider.references == []


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("plan_digest", "sha256:" + "0" * 64),
        ("engagement_id", "engagement-outside-approval"),
        ("target", "host-outside-approval.example"),
        ("worker_identity", "other-worker"),
    ],
)
def test_exact_operation_scope_mismatch_is_denied_before_provider_lookup(
    tmp_path: Path,
    field: str,
    wrong_value: str,
) -> None:
    plan = _load_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(provider, [replace(_grant(plan), **{field: wrong_value})])
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="no credential grant"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )

    assert provider.references == []


def test_different_plan_grant_cannot_supply_current_operation(tmp_path: Path) -> None:
    plan = _load_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(
        provider,
        [replace(_grant(plan), plan_id="different-plan")],
    )
    _, consumed = _consume(plan, tmp_path)

    environment = resolver.resolve_for_operation(
        plan=plan,
        authorization=consumed,
        worker_identity="worker-credential-test",
        operation=plan.operations[0],
    )

    assert environment == {}
    assert provider.references == []


@pytest.mark.parametrize(
    "environment_variable",
    [
        "PATH",
        "HOME",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "LANG",
        "COPS_EGRESS_BROKER_FD",
        "COPS_CREDENTIAL_",
    ],
)
def test_runtime_and_broker_environment_bindings_are_denied(
    tmp_path: Path,
    environment_variable: str,
) -> None:
    plan = _load_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(
        provider,
        [_grant(plan, environment_variable=environment_variable)],
    )
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="grant metadata"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )

    assert provider.references == []


def test_nul_in_provider_value_is_denied(tmp_path: Path) -> None:
    plan = _load_plan()
    provider = RecordingProvider("secret\x00suffix")
    resolver = ScopedCredentialResolver(provider, [_grant(plan)])
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="invalid value"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )


def test_provider_exception_is_rewritten_without_secret_or_cause(tmp_path: Path) -> None:
    plan = _load_plan()
    resolver = ScopedCredentialResolver(SecretBearingFailureProvider(), [_grant(plan)])
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError) as caught:
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )

    assert str(caught.value) == "credential provider resolution failed"
    assert caught.value.__cause__ is None
    assert "secret-value-that-must-not-escape" not in repr(caught.value)


def test_redactor_registration_failure_aborts_resolution(tmp_path: Path) -> None:
    plan = _load_plan()
    resolver = ScopedCredentialResolver(
        RecordingProvider("secret-never-returned"),
        [_grant(plan)],
        redactor=FailingRedactor(),  # type: ignore[arg-type]
    )
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="redactor registration failed"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )


def _two_operation_plan() -> ActionPlan:
    original = _load_plan()
    first_operation = dict(original.approved_snapshot()["operations"][0])
    first_operation["step_id"] = "credential-step-one"
    second_operation = dict(first_operation)
    second_operation["step_id"] = "credential-step-two"
    plan = ActionPlan.create(
        plan_id=original.plan_id,
        engagement_id=original.engagement_id,
        scenario_id=original.scenario_id,
        target=original.target,
        specialist_id=original.specialist_id,
        operations=[first_operation, second_operation],
        limits=dict(original.approved_snapshot()["limits"]),
        credential_references=["first-ref", "second-ref"],
        created_at=original.created_at,
        platform_prerequisites=list(original.platform_prerequisites),
        batch={"mode": "sequential", "max_operations": 2, "fail_fast": True},
    )
    return plan


def test_distinct_operations_receive_only_their_exact_grants(tmp_path: Path) -> None:
    plan = _two_operation_plan()
    provider = RecordingProvider("scoped-secret")
    resolver = ScopedCredentialResolver(
        provider,
        [
            _grant(
                plan,
                reference="first-ref",
                environment_variable="COPS_CREDENTIAL_FIRST",
            ),
            _grant(
                plan,
                reference="second-ref",
                environment_variable="COPS_CREDENTIAL_SECOND",
                operation_index=1,
            ),
        ],
    )
    _, consumed = _consume(plan, tmp_path)

    first_environment = resolver.resolve_for_operation(
        plan=plan,
        authorization=consumed,
        worker_identity="worker-credential-test",
        operation=plan.operations[0],
    )
    second_environment = resolver.resolve_for_operation(
        plan=plan,
        authorization=consumed,
        worker_identity="worker-credential-test",
        operation=plan.operations[1],
    )

    assert first_environment == {"COPS_CREDENTIAL_FIRST": "scoped-secret"}
    assert second_environment == {"COPS_CREDENTIAL_SECOND": "scoped-secret"}
    assert provider.references == ["first-ref", "second-ref"]


def test_operation_without_an_exact_grant_is_credential_free(tmp_path: Path) -> None:
    plan = _two_operation_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(
        provider,
        [_grant(plan, reference="first-ref")],
    )
    _, consumed = _consume(plan, tmp_path)

    environment = resolver.resolve_for_operation(
        plan=plan,
        authorization=consumed,
        worker_identity="worker-credential-test",
        operation=plan.operations[1],
    )

    assert environment == {}
    assert provider.references == []


def test_exact_grant_with_undeclared_reference_is_denied(tmp_path: Path) -> None:
    plan = _two_operation_plan()
    provider = RecordingProvider("unused-secret")
    resolver = ScopedCredentialResolver(
        provider,
        [_grant(plan, reference="undeclared-ref")],
    )
    _, consumed = _consume(plan, tmp_path)

    with pytest.raises(CredentialResolutionError, match="not declared"):
        resolver.resolve_for_operation(
            plan=plan,
            authorization=consumed,
            worker_identity="worker-credential-test",
            operation=plan.operations[0],
        )

    assert provider.references == []
