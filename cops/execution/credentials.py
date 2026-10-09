"""Operation-scoped credential resolution for authorized execution.

Credential values remain provider-owned until a consumed authorization, worker,
plan, target, tool, and action all match an explicit grant. Values are returned
only as the environment for that one operation and are registered for output
redaction before the caller can launch it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from cops.contracts.models import ActionPlan, ExecutionAuthorization

from .redaction import StreamRedactor

_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CREDENTIAL_ENVIRONMENT_PREFIX = "COPS_CREDENTIAL_"


class CredentialResolutionError(RuntimeError):
    """A credential could not be resolved within the authorized operation scope."""


class CredentialProvider(Protocol):
    """Provider that materializes a verifier-owned credential reference."""

    def resolve(self, reference: str) -> str:
        """Return the current secret value for ``reference``."""


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


class ScopedCredentialResolver:
    """Resolve credentials only after every approved operation binding matches."""

    def __init__(
        self,
        provider: CredentialProvider,
        grants: list[CredentialGrant] | tuple[CredentialGrant, ...],
        *,
        redactor: StreamRedactor | None = None,
    ) -> None:
        self._provider = provider
        self._grants = tuple(grants)
        self.redactor = redactor or StreamRedactor()

    def resolve_for_operation(
        self,
        *,
        plan: ActionPlan,
        authorization: ExecutionAuthorization,
        worker_identity: str,
        operation: Mapping[str, Any],
    ) -> dict[str, str]:
        """Return an environment for an authority-returned consumption result.

        ``authorization`` must be the object returned by the approval store's
        atomic consumption call.  This resolver checks its bindings defensively;
        it does not treat a caller-constructed object with a ``consumed`` status
        as proof that the authority performed that transition.
        """
        operation_data = _plain(operation)
        if not isinstance(operation_data, dict):
            raise CredentialResolutionError("credential request operation is invalid")
        self._validate_authorization(plan, authorization, worker_identity)
        if operation_data not in [_plain(item) for item in plan.operations]:
            raise CredentialResolutionError("credential request is outside the approved plan")

        references = {str(reference) for reference in plan.credential_references}
        operation_grants = [
            grant
            for grant in self._grants
            if grant.plan_id == plan.plan_id
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
                value = self._provider.resolve(grant.reference)
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
            self.redactor.add_secrets(tuple(environment.values()))
        except Exception:
            raise CredentialResolutionError("credential redactor registration failed") from None
        return environment

    @staticmethod
    def _validate_authorization(
        plan: ActionPlan,
        authorization: ExecutionAuthorization,
        worker_identity: str,
    ) -> None:
        if authorization.status != "consumed" or authorization.consumed_by_worker != worker_identity:
            raise CredentialResolutionError("credential resolution requires a consumed worker authorization")
        if (
            authorization.action_plan_id != plan.plan_id
            or authorization.plan_digest != plan.plan_digest
            or authorization.engagement_id != plan.engagement_id
        ):
            raise CredentialResolutionError("credential request authorization does not match the plan")
        bound_parameters = _plain(authorization.bound_parameters)
        if not isinstance(bound_parameters, dict):
            raise CredentialResolutionError("credential request authorization bindings are invalid")
        if bound_parameters.get("worker_identity") != worker_identity:
            raise CredentialResolutionError("credential request worker is outside the approval")
        if bound_parameters.get("action_plan") != plan.approved_snapshot(include_digest=True):
            raise CredentialResolutionError("credential request plan is outside the approval")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
