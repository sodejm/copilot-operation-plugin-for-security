"""Execution authorization engine for COPS security operations.

Replaces unkeyed checksum receipts with cryptographically bound, operator-authenticated
approval envelopes bound to immutable cops.action-plan/v1 action plans.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from cops.contracts.lifecycle import ContractError
from cops.contracts.models import ActionPlan, ExecutionAuthorization
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import canonical, digest, timestamp, utc_now


class AuthorizationError(ValueError):
    """Base error for operational authorization failures."""


class AuthorizationRequiredError(AuthorizationError):
    """Operation requires explicit authorization but none was supplied or confirmed."""


class AuthorizationDeniedError(AuthorizationError):
    """Operator explicitly denied or aborted the authorization request."""


class LegacyReceiptDeprecationWarning(UserWarning):
    """Warning emitted when an obsolete unkeyed checksum receipt is encountered."""


def compute_authorization_signature(
    *,
    action_plan_id: str,
    plan_digest: str,
    engagement_id: str,
    operator: str,
    issued_at: str,
    authorized_until_utc: str,
    bound_parameters: dict[str, Any],
    approval_mode: str,
) -> str:
    """Compute deterministic cryptographic signature digest for an execution authorization envelope."""
    payload = {
        "action_plan_id": action_plan_id,
        "plan_digest": plan_digest,
        "engagement_id": engagement_id,
        "operator": operator,
        "issued_at": issued_at,
        "authorized_until_utc": authorized_until_utc,
        "bound_parameters": bound_parameters,
        "approval_mode": approval_mode,
    }
    return digest(payload)


def create_execution_authorization(
    action_plan: ActionPlan | dict[str, Any],
    *,
    operator: str,
    valid_hours: int = 4,
    worker_identity: str | None = None,
    approval_mode: str = "interactive_confirmation",
) -> ExecutionAuthorization:
    """Create and seal a new ExecutionAuthorization envelope bound to an immutable ActionPlan."""
    if isinstance(action_plan, dict):
        action_plan_model = ActionPlan.from_dict(action_plan)
    else:
        action_plan_model = action_plan

    now = datetime.now(timezone.utc)
    issued_at = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    authorized_until_utc = (now + timedelta(hours=valid_hours)).isoformat(timespec="seconds").replace("+00:00", "Z")

    operations_summary = [
        {
            "step_id": op["step_id"],
            "tool": op["tool"],
            "action": op["action"],
        }
        for op in action_plan_model.operations
    ]

    bound_parameters: dict[str, Any] = {
        "specialist_id": action_plan_model.specialist_id,
        "target": action_plan_model.target,
        "operations_summary": operations_summary,
        "limits": action_plan_model.limits,
        "credential_references": sorted(action_plan_model.credential_references),
    }
    if worker_identity:
        bound_parameters["worker_identity"] = worker_identity

    sig_digest = compute_authorization_signature(
        action_plan_id=action_plan_model.plan_id,
        plan_digest=action_plan_model.plan_digest,
        engagement_id=action_plan_model.engagement_id,
        operator=operator,
        issued_at=issued_at,
        authorized_until_utc=authorized_until_utc,
        bound_parameters=bound_parameters,
        approval_mode=approval_mode,
    )

    auth_id = f"auth-{uuid.uuid4().hex[:16]}"

    envelope = ExecutionAuthorization(
        schema_version="cops.execution-authorization/v1",
        authorization_id=auth_id,
        action_plan_id=action_plan_model.plan_id,
        plan_digest=action_plan_model.plan_digest,
        engagement_id=action_plan_model.engagement_id,
        operator=operator,
        status="approved",
        issued_at=issued_at,
        authorized_until_utc=authorized_until_utc,
        bound_parameters=bound_parameters,
        approval_mode=approval_mode,
        signature_digest=sig_digest,
    )

    # Validate resulting envelope against schema and contract rules
    validate_contract(envelope.to_dict(), "execution_authorization")
    return envelope


def verify_execution_authorization(
    authorization: ExecutionAuthorization | dict[str, Any],
    action_plan: ActionPlan | dict[str, Any],
    *,
    worker_identity: str | None = None,
    current_time_iso: str | None = None,
) -> ExecutionAuthorization:
    """Verify that an authorization envelope cryptographically binds to the exact ActionPlan and runtime context.

    Raises AuthorizationError if:
    - Envelope is expired, revoked, or consumed
    - Signature digest mismatch (tampering)
    - Action plan ID or plan_digest mismatch
    - Engagement ID or target mismatch
    - Specialist ID mismatch
    - Bound limits, operations, or credentials mismatch
    - Worker identity mismatch (if bound)
    """
    if isinstance(authorization, dict):
        # Detect legacy receipt format (schema_version 1.0)
        if authorization.get("schema_version") == "1.0" or "receipt_id" in authorization:
            warnings.warn(
                "Legacy unkeyed authorization receipts (schema_version 1.0) are obsolete historical evidence "
                "and cannot authorize new execution.",
                category=LegacyReceiptDeprecationWarning,
                stacklevel=2,
            )
            raise AuthorizationError(
                "legacy authorization receipts (1.0) cannot authorize new execution; "
                "re-authorization with cops.execution-authorization/v1 envelope required"
            )
        try:
            auth_model = ExecutionAuthorization.from_dict(authorization)
        except (ContractError, ValueError) as err:
            raise AuthorizationError(f"invalid or tampered execution authorization envelope: {err}") from err
    else:
        auth_model = authorization

    if isinstance(action_plan, dict):
        plan_model = ActionPlan.from_dict(action_plan)
    else:
        plan_model = action_plan

    # Verify status
    if auth_model.status != "approved":
        raise AuthorizationError(
            f"authorization is not in approved state (current status: '{auth_model.status}')"
        )

    # Verify expiration
    now_dt = timestamp(current_time_iso) if current_time_iso else datetime.now(timezone.utc)
    auth_expiry = timestamp(auth_model.authorized_until_utc)
    if now_dt > auth_expiry:
        raise AuthorizationError(
            f"execution authorization expired at {auth_model.authorized_until_utc} (current: {now_dt.isoformat()})"
        )

    # Verify binding to action plan
    if auth_model.action_plan_id != plan_model.plan_id:
        raise AuthorizationError(
            f"authorization bound to plan '{auth_model.action_plan_id}', but executing plan '{plan_model.plan_id}'"
        )

    if auth_model.plan_digest != plan_model.plan_digest:
        raise AuthorizationError(
            f"action plan digest mismatch: authorization was issued for digest {auth_model.plan_digest}, "
            f"but plan digest is {plan_model.plan_digest} (plan has been modified)"
        )

    if auth_model.engagement_id != plan_model.engagement_id:
        raise AuthorizationError(
            f"engagement ID mismatch: authorization={auth_model.engagement_id}, plan={plan_model.engagement_id}"
        )

    # Verify bound parameters
    bound = auth_model.bound_parameters
    if bound.get("specialist_id") != plan_model.specialist_id:
        raise AuthorizationError(
            f"specialist mismatch: authorized for '{bound.get('specialist_id')}', but plan requests '{plan_model.specialist_id}'"
        )

    if bound.get("target") != plan_model.target:
        raise AuthorizationError(
            f"target mismatch: authorized for '{bound.get('target')}', but plan targets '{plan_model.target}'"
        )

    if bound.get("limits") != plan_model.limits:
        raise AuthorizationError("limits mismatch between authorization and action plan")

    if sorted(bound.get("credential_references", [])) != sorted(plan_model.credential_references):
        raise AuthorizationError("credential references mismatch between authorization and action plan")

    # Verify operations summary match
    expected_ops_summary = [
        {"step_id": op["step_id"], "tool": op["tool"], "action": op["action"]}
        for op in plan_model.operations
    ]
    if bound.get("operations_summary") != expected_ops_summary:
        raise AuthorizationError("operations summary in authorization does not match action plan operations")

    # Verify worker identity if bound in authorization
    bound_worker = bound.get("worker_identity")
    if bound_worker:
        if not worker_identity:
            raise AuthorizationError(
                f"authorization requires worker_identity '{bound_worker}', but execution did not specify worker_identity"
            )
        if bound_worker != worker_identity:
            raise AuthorizationError(
                f"worker identity mismatch: authorized for '{bound_worker}', attempted execution by '{worker_identity}'"
            )

    # Verify signature digest integrity
    expected_sig = compute_authorization_signature(
        action_plan_id=auth_model.action_plan_id,
        plan_digest=auth_model.plan_digest,
        engagement_id=auth_model.engagement_id,
        operator=auth_model.operator,
        issued_at=auth_model.issued_at,
        authorized_until_utc=auth_model.authorized_until_utc,
        bound_parameters=auth_model.bound_parameters,
        approval_mode=auth_model.approval_mode,
    )
    if auth_model.signature_digest != expected_sig:
        raise AuthorizationError("authorization envelope signature digest mismatch (tampered)")

    return auth_model


def consume_execution_authorization(
    authorization: ExecutionAuthorization,
    *,
    worker_identity: str,
    consumed_at: str | None = None,
) -> ExecutionAuthorization:
    """Atomically consume an authorization envelope for execution, marking it non-reusable."""
    if authorization.status != "approved":
        raise AuthorizationError(
            f"cannot consume authorization in '{authorization.status}' state (replay or invalid state)"
        )

    timestamp_str = consumed_at or utc_now()
    authorization.transition_to("consumed")
    authorization.consumed_at = timestamp_str
    authorization.consumed_by_worker = worker_identity
    return authorization


def request_interactive_plan_authorization(
    action_plan: ActionPlan | dict[str, Any],
    *,
    valid_hours: int = 4,
    worker_identity: str | None = None,
    input_func: Callable[[str], str] | None = None,
    output_stream: Any = sys.stdout,
) -> ExecutionAuthorization:
    """Prompt the operator interactively to review and authorize an immutable ActionPlan."""
    if isinstance(action_plan, dict):
        plan_model = ActionPlan.from_dict(action_plan)
    else:
        plan_model = action_plan

    if input_func is None:
        if not sys.stdin.isatty():
            raise AuthorizationRequiredError(
                f"Interactive authorization required for {plan_model.specialist_id} (Plan {plan_model.plan_id}), "
                "but standard input is not a terminal. Provide a pre-signed execution authorization envelope."
            )
        input_func = input

    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USER", "unknown-operator")

    ops_lines = [
        f"    [{op['step_id']}] {op['tool']}:{op['action']} (timeout: {op['timeout_seconds']}s)"
        for op in plan_model.operations
    ]

    banner = [
        "\n" + "=" * 70,
        "  [!] COPS OPERATIONAL EXECUTION AUTHORIZATION GATE REQUIRED",
        "=" * 70,
        f"  Plan ID            : {plan_model.plan_id}",
        f"  Engagement ID      : {plan_model.engagement_id}",
        f"  Scenario ID        : {plan_model.scenario_id}",
        f"  Specialist Profile : {plan_model.specialist_id}",
        f"  Target             : {plan_model.target}",
        f"  Plan Digest        : {plan_model.plan_digest}",
        f"  Authorized TTL     : {valid_hours} hour(s)",
        f"  Requesting User    : {current_user}",
        "  Operations Planned :",
        *ops_lines,
        f"  Limits             : max_duration={plan_model.limits.get('max_duration_seconds')}s, "
        f"egress={'ALLOWED' if plan_model.limits.get('egress_allowed') else 'BLOCKED'}",
        "=" * 70,
        "  CRITICAL: This operation will execute bound security tools against the target.",
        "  Type 'APPROVE' to seal authorization envelope, or anything else to abort.",
        "-" * 70,
    ]
    print("\n".join(banner), file=output_stream, flush=True)

    response = input_func("Enter confirmation [APPROVE/abort]: ").strip()
    if response != "APPROVE":
        raise AuthorizationDeniedError(
            f"Authorization for Plan {plan_model.plan_id} was aborted by operator (received '{response}')."
        )

    auth = create_execution_authorization(
        plan_model,
        operator=current_user,
        valid_hours=valid_hours,
        worker_identity=worker_identity,
        approval_mode="interactive_confirmation",
    )
    print(f"  [+] Execution Authorization granted: {auth.authorization_id}", file=output_stream, flush=True)
    print(f"  [+] Signature Digest: {auth.signature_digest}\n", file=output_stream, flush=True)
    return auth
