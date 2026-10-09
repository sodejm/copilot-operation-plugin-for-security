"""Operation-scoped credential resolution for authorized execution.

Credential values remain provider-owned until an authority-issued consumption
receipt, worker, plan, target, tool, and action all match an explicit grant.
Values are returned only as the environment for that one operation and are
registered for output redaction before the caller can launch it.
"""

from __future__ import annotations

import inspect
import multiprocessing
import re
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Any, Protocol

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest

from .redaction import StreamRedactor

_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CREDENTIAL_ENVIRONMENT_PREFIX = "COPS_CREDENTIAL_"
_AUTHORIZATION_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class CredentialResolutionError(RuntimeError):
    """A credential could not be resolved within the authorized operation scope."""


class CredentialProvider(Protocol):
    """Provider that materializes a verifier-owned credential reference."""

    def resolve(self, reference: str) -> str:
        """Return the current secret value for ``reference``."""


class ApprovalConsumptionReceiptView(Protocol):
    """Trusted bindings returned by the consume-only approval authority."""

    authorization_id: str
    authorization_digest: str
    action_plan_id: str
    plan_digest: str
    engagement_id: str
    worker_identity: str
    target: str


class ApprovalReceiptAuthority(Protocol):
    """Authority that proves a receipt came from its consume operation."""

    def validate_receipt_provenance(
        self,
        receipt: ApprovalConsumptionReceiptView,
    ) -> ApprovalConsumptionReceiptView:
        """Return the same receipt only when this authority issued it."""


@dataclass(frozen=True)
class CredentialGrant:
    """Exact binding that permits one plan operation to resolve one reference."""

    reference: str
    environment_variable: str
    plan_id: str
    plan_digest: str
    engagement_id: str
    worker_identity: str
    target: str
    step_id: str
    tool: str
    tool_version: str
    action: str
    operation_index: int
    operation_digest: str


class ScopedCredentialResolver:
    """Resolve credentials only after every approved operation binding matches."""

    def __init__(
        self,
        provider: CredentialProvider,
        grants: list[CredentialGrant] | tuple[CredentialGrant, ...],
        *,
        approval_control: ApprovalReceiptAuthority,
        redactor: StreamRedactor | None = None,
    ) -> None:
        self._provider = provider
        self._grants = tuple(grants)
        self._approval_control = approval_control
        self.redactor = redactor or StreamRedactor()

    @property
    def approval_control(self) -> ApprovalReceiptAuthority:
        """Return the authority that must issue every credential-bearing receipt."""
        return self._approval_control

    def resolve_for_operation(
        self,
        *,
        plan: ActionPlan,
        authorization: ApprovalConsumptionReceiptView,
        worker_identity: str,
        operation: Mapping[str, Any],
        operation_index: int,
        deadline: float | None = None,
        redactor: StreamRedactor | None = None,
    ) -> dict[str, str]:
        """Return an environment for an authority-issued consumption receipt.

        ``authorization`` must be the object returned directly by the
        worker's consume-only ``ApprovalControl`` call. The receipt bindings are
        checked defensively, but caller-constructed authorization status fields
        are not accepted as proof that the authority performed consumption.
        """
        try:
            verified_authorization = self._approval_control.validate_receipt_provenance(authorization)
        except Exception:
            raise CredentialResolutionError("credential consumption receipt provenance is invalid") from None
        if verified_authorization is not authorization:
            raise CredentialResolutionError("credential consumption receipt provenance is invalid")

        operation_data = _plain(operation)
        if not isinstance(operation_data, dict):
            raise CredentialResolutionError("credential request operation is invalid")
        self._validate_authorization_receipt(plan, authorization, worker_identity)
        if (
            not isinstance(operation_index, int)
            or isinstance(operation_index, bool)
            or operation_index < 0
            or operation_index >= len(plan.operations)
            or operation_data != _plain(plan.operations[operation_index])
        ):
            raise CredentialResolutionError("credential request is outside the approved plan")
        operation_digest = digest(operation_data)

        references = {str(reference) for reference in plan.credential_references}
        operation_grants = [
            grant
            for grant in self._grants
            if grant.plan_id == plan.plan_id
            and grant.operation_index == operation_index
            and grant.step_id == operation_data.get("step_id")
            and grant.tool == operation_data.get("tool")
            and grant.tool_version == operation_data.get("tool_version")
            and grant.action == operation_data.get("action")
        ]
        if not operation_grants:
            # A plan can declare credentials for other operations while this
            # operation is deliberately credential-free.
            return {}

        resolved_references: set[str] = set()
        for grant in operation_grants:
            if grant.reference not in references:
                raise CredentialResolutionError("credential grant is not declared by the approved plan")
            if (
                grant.plan_digest != plan.plan_digest
                or grant.engagement_id != plan.engagement_id
                or grant.worker_identity != worker_identity
                or grant.target != plan.target
                or grant.operation_digest != operation_digest
            ):
                raise CredentialResolutionError("no credential grant matches the approved operation")
            if grant.reference in resolved_references:
                raise CredentialResolutionError("credential grants contain a duplicate reference binding")
            resolved_references.add(grant.reference)

        environment_variables: set[str] = set()
        for grant in operation_grants:
            if (
                not grant.reference
                or not _ENVIRONMENT_VARIABLE.fullmatch(grant.environment_variable)
                or not grant.environment_variable.startswith(_CREDENTIAL_ENVIRONMENT_PREFIX)
                or grant.environment_variable == _CREDENTIAL_ENVIRONMENT_PREFIX
            ):
                raise CredentialResolutionError("credential grant metadata is invalid")
            if grant.environment_variable in environment_variables:
                raise CredentialResolutionError("credential grants contain a duplicate environment binding")
            environment_variables.add(grant.environment_variable)

        environment: dict[str, str] = {}
        for grant in operation_grants:
            try:
                value = _resolve_provider(self._provider, grant.reference, deadline)
            except TimeoutError:
                raise CredentialResolutionError("credential provider resolution timed out") from None
            except Exception:
                # A provider exception may embed the secret in its message or
                # attributes, so do not retain it as a chained exception.
                raise CredentialResolutionError("credential provider resolution failed") from None
            if not isinstance(value, str) or not value or "\x00" in value:
                raise CredentialResolutionError("credential provider returned an invalid value")
            environment[grant.environment_variable] = value

        # Register every value after all lookups succeed. The worker
        # shares this redactor with evidence capture before launching the process.
        try:
            (redactor or self.redactor).add_secrets(tuple(environment.values()))
        except Exception:
            raise CredentialResolutionError("credential redactor registration failed") from None
        return environment

    @staticmethod
    def _validate_authorization_receipt(
        plan: ActionPlan,
        authorization_receipt: ApprovalConsumptionReceiptView,
        worker_identity: str,
    ) -> None:
        field_names = (
            "authorization_id",
            "authorization_digest",
            "action_plan_id",
            "plan_digest",
            "engagement_id",
            "worker_identity",
            "target",
        )
        try:
            bindings = {field_name: getattr(authorization_receipt, field_name) for field_name in field_names}
        except (AttributeError, TypeError):
            raise CredentialResolutionError("credential consumption receipt is invalid") from None
        if any(not isinstance(value, str) or not value for value in bindings.values()):
            raise CredentialResolutionError("credential consumption receipt is invalid")
        if not _AUTHORIZATION_DIGEST.fullmatch(bindings["authorization_digest"]):
            raise CredentialResolutionError("credential consumption receipt is invalid")
        if (
            bindings["action_plan_id"] != plan.plan_id
            or bindings["plan_digest"] != plan.plan_digest
            or bindings["engagement_id"] != plan.engagement_id
            or bindings["worker_identity"] != worker_identity
            or bindings["target"] != plan.target
        ):
            raise CredentialResolutionError("credential consumption receipt does not match the operation")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _resolve_provider(provider: CredentialProvider, reference: str, deadline: float | None) -> str:
    """Bound an arbitrary provider without allowing a stalled lookup to hold the worker."""
    if deadline is None:
        return provider.resolve(reference)
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("credential lookup deadline elapsed")

    # The production socket provider enforces its own deadline on every I/O.
    # Legacy providers have no such contract, so isolate them in a disposable
    # process instead of relying on an unkillable thread.
    try:
        supports_deadline = "deadline" in inspect.signature(provider.resolve).parameters
    except (TypeError, ValueError):
        supports_deadline = False
    if supports_deadline:
        return provider.resolve(reference, deadline=deadline)
    if "fork" not in multiprocessing.get_all_start_methods():
        raise RuntimeError("credential provider has no bounded resolution interface")

    context = multiprocessing.get_context("fork")
    receiver, sender = context.Pipe(duplex=False)

    def resolve_in_child() -> None:
        receiver.close()
        try:
            sender.send((True, provider.resolve(reference)))
        except BaseException:
            # Provider errors may contain credential material; return no details.
            sender.send((False, None))
        finally:
            sender.close()

    process = context.Process(target=resolve_in_child, daemon=True)
    try:
        process.start()
        sender.close()
        if not receiver.poll(max(0.0, deadline - monotonic())):
            raise TimeoutError("credential lookup deadline elapsed")
        try:
            succeeded, value = receiver.recv()
        except EOFError:
            raise RuntimeError("credential provider exited without a value") from None
        if not succeeded:
            raise RuntimeError("credential provider failed")
        return value
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.5)
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
