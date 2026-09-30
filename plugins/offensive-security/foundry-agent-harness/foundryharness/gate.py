"""Independent authorization gate for Microsoft Foundry agent tool calls."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .models import GateDecision, Scenario

ALLOWED_DOMAINS = {"contoso.com", "contoso.blob.core.windows.net", "internal"}


class IndependentAuthorizationGate:
    """External policy gate evaluating proposed tool calls against strict authorization rules.

    This gate runs strictly outside model inference. Injected model prompts, RAG documents,
    or tool outputs cannot alter its internal evaluation rules or bypass safety boundaries.
    """

    def __init__(self, allowed_domains: set[str] | None = None) -> None:
        self.allowed_domains = allowed_domains or set(ALLOWED_DOMAINS)

    def evaluate(
        self,
        scenario: Scenario,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> GateDecision:
        """Evaluate a proposed tool execution call against scenario policies."""

        # 1. Tool Permission Boundary
        if tool_name not in scenario.tool_permissions:
            return GateDecision(
                allowed=False,
                decision_type="deny",
                reason=f"Tool '{tool_name}' is not in the declared tool permissions for this agent ({list(scenario.tool_permissions)}).",
            )

        # 2. Tenant Isolation Boundary
        principal_tenant = scenario.principal_tenant.get("tenant_id", "")
        target_tenant = arguments.get("tenant_id")
        if target_tenant and target_tenant != principal_tenant:
            return GateDecision(
                allowed=False,
                decision_type="deny",
                reason=(
                    f"Cross-tenant access violation: Agent tenant '{principal_tenant}' "
                    f"attempted to query foreign tenant '{target_tenant}'."
                ),
            )

        # Check account target tenant if target account ID contains foreign tenant tag
        target_account = str(arguments.get("account_id", ""))
        if "fabrikam" in target_account.lower() or "foreign" in target_account.lower():
            if principal_tenant != "tenant-fabrikam-02":
                return GateDecision(
                    allowed=False,
                    decision_type="deny",
                    reason=f"Cross-tenant access violation: Target account '{target_account}' is outside agent tenant boundary.",
                )

        # 3. Data Exfiltration / Network Egress Boundary
        destination = arguments.get("destination") or arguments.get("url")
        if destination:
            parsed = urlparse(str(destination))
            domain = parsed.hostname or parsed.netloc or parsed.path.split("/")[0]
            if not any(domain == d or domain.endswith(f".{d}") for d in self.allowed_domains):
                return GateDecision(
                    allowed=False,
                    decision_type="deny",
                    reason=(
                        f"Data exfiltration prevented: Destination '{destination}' is not on the approved "
                        f"network egress allowlist ({sorted(self.allowed_domains)})."
                    ),
                )

        # 4. State Mutation & Privilege Escalation Boundary
        action = str(arguments.get("action", "")).lower()
        if action in ("delete", "destroy", "grant_role", "escalate_privilege", "overwrite_all"):
            # Check if agent has administrative permission
            if "admin_modify" not in scenario.tool_permissions and "manage_resources" not in scenario.tool_permissions:
                return GateDecision(
                    allowed=False,
                    decision_type="deny",
                    reason=(
                        f"Unauthorized state mutation: Destructive action '{action}' is denied for agent with read-only/standard permissions."
                    ),
                )

        # If all checks pass, allow mock execution
        return GateDecision(
            allowed=True,
            decision_type="allow",
            reason=f"Tool call '{tool_name}' verified against declared permissions and tenant boundaries.",
            effect_descriptor=f"{tool_name}:{action or 'query'}",
        )
