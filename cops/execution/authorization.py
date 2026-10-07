"""Authenticated, one-time execution authorization for immutable action plans."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import uuid
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cops.contracts.lifecycle import ContractError
from cops.contracts.models import ActionPlan, ExecutionAuthorization
from cops.contracts.validation import validate_contract
from cops.evidence.canonical import canonical, timestamp, utc_now


class AuthorizationError(ValueError):
    """Base error for operational authorization failures."""


class AuthorizationRequiredError(AuthorizationError):
    """Operation requires explicit authorization but none was supplied."""


class AuthorizationDeniedError(AuthorizationError):
    """Operator explicitly denied the authorization request."""


class LegacyReceiptDeprecationWarning(UserWarning):
    """An obsolete unkeyed checksum receipt was encountered."""


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise AuthorizationError("authorization HMAC secrets must contain at least 32 bytes")
    return secret


@dataclass(frozen=True)
class AuthorizationSigner:
    key_id: str
    operator: str
    secret: bytes
    valid_from: str | None = None
    valid_until: str | None = None

    def __post_init__(self) -> None:
        _validate_secret(self.secret)


@dataclass(frozen=True)
class TrustedAuthorizationKey:
    key_id: str
    operator: str
    secret: bytes
    valid_from: str | None = None
    valid_until: str | None = None
    status: str = "active"

    def __post_init__(self) -> None:
        _validate_secret(self.secret)
        if self.status not in {"active", "revoked"}:
            raise AuthorizationError(f"unsupported trusted key status: {self.status}")


class AuthorizationTrustStore:
    """Verifier-owned key configuration, provisioned outside authorization envelopes."""

    def __init__(self, keys: list[TrustedAuthorizationKey]) -> None:
        self._keys: dict[str, TrustedAuthorizationKey] = {}
        for key in keys:
            if key.key_id in self._keys:
                raise AuthorizationError(f"duplicate trusted authorization key: {key.key_id}")
            self._keys[key.key_id] = key

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> AuthorizationTrustStore:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("schema_version") != "cops.authorization-trust-store/v1":
            raise AuthorizationError("unsupported authorization trust-store schema")
        environment = environ if environ is not None else os.environ
        keys = []
        for item in doc.get("keys", []):
            if item.get("algorithm") != "hmac-sha256":
                raise AuthorizationError(
                    f"trusted key {item.get('key_id')!r} uses an unsupported algorithm"
                )
            secret_env = item.get("secret_env")
            if not secret_env or secret_env not in environment:
                raise AuthorizationError(
                    f"trusted key {item.get('key_id')!r} secret environment variable is unavailable"
                )
            keys.append(
                TrustedAuthorizationKey(
                    key_id=item["key_id"],
                    operator=item["operator_identity"],
                    secret=environment[secret_env].encode("utf-8"),
                    valid_from=item.get("valid_from_utc"),
                    valid_until=item.get("valid_until_utc"),
                    status=item.get("status", "active"),
                )
            )
        return cls(keys)

    def resolve(self, key_id: str, operator: str, issued_at: str, expires_at: str) -> TrustedAuthorizationKey:
        key = self._keys.get(key_id)
        if key is None or key.status != "active" or key.operator != operator:
            raise AuthorizationError("authorization signing key is unknown, revoked, or not trusted for the operator")
        _validate_window(key.valid_from, key.valid_until, issued_at, expires_at, "trusted key")
        return key


def _validate_window(valid_from: str | None, valid_until: str | None,
                     issued_at: str, expires_at: str, label: str) -> None:
    issued, expires = timestamp(issued_at), timestamp(expires_at)
    if expires <= issued:
        raise AuthorizationError("authorization expiry must follow issue time")
    if valid_from and issued < timestamp(valid_from):
        raise AuthorizationError(f"authorization issue time precedes {label} validity")
    if valid_until and expires > timestamp(valid_until):
        raise AuthorizationError(f"authorization expiry exceeds {label} validity")


def _engagement_document(engagement: Any, plan: ActionPlan, operator: str,
                         issued_at: str, expires_at: str) -> dict[str, Any]:
    if engagement is None:
        raise AuthorizationError("explicit active engagement is required")
    doc = engagement.to_dict() if hasattr(engagement, "to_dict") else engagement
    validate_contract(doc, "engagement")
    if doc["status"] != "active" or doc["engagement_id"] != plan.engagement_id:
        raise AuthorizationError("authorization requires the plan's active engagement")
    if doc["operator"] != operator:
        raise AuthorizationError("authorization operator does not match the engagement operator")
    try:
        _validate_window(doc["window"]["started_at"], doc["window"]["authorized_until_utc"],
                         issued_at, expires_at, "engagement window")
    except AuthorizationError as err:
        raise AuthorizationError(f"authorization is outside engagement window: {err}") from err
    return doc


def compute_authorization_signature(payload: dict[str, Any], *, secret: bytes) -> str:
    """Compute an HMAC over every stable authorization field."""
    return hmac.new(_validate_secret(secret), canonical(payload), hashlib.sha256).hexdigest()


def create_execution_authorization(
    action_plan: ActionPlan | dict[str, Any], *, signer: AuthorizationSigner,
    engagement: Any, worker_identity: str, valid_hours: int = 4,
    approval_mode: str = "interactive_confirmation", issued_at: str | None = None,
    authorized_until_utc: str | None = None, authorization_id: str | None = None,
) -> ExecutionAuthorization:
    plan = ActionPlan.from_dict(action_plan) if isinstance(action_plan, dict) else action_plan
    validate_contract(plan.to_dict(), "action_plan")
    if plan.status in {"fulfilled", "rejected", "cancelled"}:
        raise AuthorizationError(f"cannot authorize terminal action plan {plan.plan_id!r}")
    now = datetime.now(UTC)
    issued_at = issued_at or now.isoformat(timespec="seconds").replace("+00:00", "Z")
    authorized_until_utc = authorized_until_utc or (now + timedelta(hours=valid_hours)).isoformat(timespec="seconds").replace("+00:00", "Z")
    _engagement_document(engagement, plan, signer.operator, issued_at, authorized_until_utc)
    _validate_window(signer.valid_from, signer.valid_until, issued_at, authorized_until_utc, "signing key")
    auth = ExecutionAuthorization(
        schema_version="cops.execution-authorization/v1",
        authorization_id=authorization_id or f"auth-{uuid.uuid4().hex[:16]}",
        action_plan_id=plan.plan_id, plan_digest=plan.plan_digest,
        engagement_id=plan.engagement_id, operator=signer.operator, status="approved",
        issued_at=issued_at, authorized_until_utc=authorized_until_utc,
        bound_parameters={"action_plan": plan.approved_snapshot(include_digest=True),
                          "worker_identity": worker_identity},
        approval_mode=approval_mode, signature_algorithm="hmac-sha256",
        signing_key_id=signer.key_id, signature_digest="0" * 64,
    )
    object.__setattr__(
        auth,
        "signature_digest",
        compute_authorization_signature(auth.signed_payload(), secret=signer.secret),
    )
    validate_contract(auth.to_dict(), "execution_authorization")
    return auth


def verify_execution_authorization(
    authorization: ExecutionAuthorization | dict[str, Any],
    action_plan: ActionPlan | dict[str, Any], *, trust_store: AuthorizationTrustStore,
    engagement: Any, worker_identity: str, current_time_iso: str | None = None,
) -> ExecutionAuthorization:
    if trust_store is None:
        raise AuthorizationError("explicit verifier trust store is required")
    if isinstance(authorization, dict):
        if authorization.get("schema_version") == "1.0" or "receipt_id" in authorization:
            warnings.warn("legacy unkeyed authorization receipts cannot authorize execution",
                          LegacyReceiptDeprecationWarning, stacklevel=2)
            raise AuthorizationError("legacy authorization receipts cannot authorize execution")
        try:
            auth = ExecutionAuthorization.from_dict(authorization)
        except (ContractError, ValueError, KeyError) as err:
            raise AuthorizationError(f"invalid or tampered execution authorization envelope: {err}") from err
    else:
        auth = authorization
        validate_contract(auth.to_dict(), "execution_authorization")
    plan = ActionPlan.from_dict(action_plan) if isinstance(action_plan, dict) else action_plan
    validate_contract(plan.to_dict(), "action_plan")
    key = trust_store.resolve(auth.signing_key_id, auth.operator, auth.issued_at, auth.authorized_until_utc)
    expected = compute_authorization_signature(auth.signed_payload(), secret=key.secret)
    if not hmac.compare_digest(auth.signature_digest, expected):
        raise AuthorizationError("authorization signature verification failed")
    if auth.status != "approved":
        raise AuthorizationError(f"authorization is not approved (status: {auth.status})")
    now = timestamp(current_time_iso) if current_time_iso else datetime.now(UTC)
    if now < timestamp(auth.issued_at) or now >= timestamp(auth.authorized_until_utc):
        raise AuthorizationError("authorization is not currently valid")
    _engagement_document(engagement, plan, auth.operator, auth.issued_at, auth.authorized_until_utc)
    if auth.action_plan_id != plan.plan_id or auth.plan_digest != plan.plan_digest or auth.engagement_id != plan.engagement_id:
        raise AuthorizationError("authorization does not bind the requested action plan")
    if auth.to_dict()["bound_parameters"].get("action_plan") != plan.approved_snapshot(include_digest=True):
        raise AuthorizationError("authorization's signed action plan snapshot does not match")
    if auth.bound_parameters.get("worker_identity") != worker_identity:
        raise AuthorizationError("authorization worker identity does not match")
    return auth


def consume_execution_authorization(authorization: ExecutionAuthorization, *, worker_identity: str,
                                    consumed_at: str | None = None) -> ExecutionAuthorization:
    if authorization.status != "approved":
        raise AuthorizationError(f"cannot consume authorization in {authorization.status!r} state")
    authorization.transition_to("consumed")
    authorization.consumed_at = consumed_at or utc_now()
    authorization.consumed_by_worker = worker_identity
    return authorization


def request_interactive_plan_authorization(
    action_plan: ActionPlan | dict[str, Any], *, signer: AuthorizationSigner,
    engagement: Any, worker_identity: str, valid_hours: int = 4,
    input_func: Callable[[str], str] | None = None, output_stream: Any = sys.stdout,
) -> ExecutionAuthorization:
    plan = ActionPlan.from_dict(action_plan) if isinstance(action_plan, dict) else action_plan
    if input_func is None:
        if not sys.stdin.isatty():
            raise AuthorizationRequiredError("interactive authorization requires a terminal")
        input_func = input
    print(f"Authorize immutable plan {plan.plan_id} ({plan.plan_digest}) for {worker_identity}. Type APPROVE:", file=output_stream)
    if input_func("Enter confirmation [APPROVE/abort]: ").strip() != "APPROVE":
        raise AuthorizationDeniedError(f"authorization for {plan.plan_id} was denied")
    return create_execution_authorization(plan, signer=signer, engagement=engagement,
                                          worker_identity=worker_identity,
                                          valid_hours=valid_hours,
                                          approval_mode="interactive_confirmation")
