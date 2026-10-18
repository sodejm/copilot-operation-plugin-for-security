"""Opt-in provider assessment through a signed operator gateway emulator.

This module has no provider client, network transport, or credential access. A
production worker must supply its own independently reviewed gateway boundary.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from copy import deepcopy
from queue import Empty, Queue
from threading import Thread
from typing import Any
from urllib.parse import urlsplit

from cops.assessment_budget import (
    AssessmentBudgetLedger,
    AttemptRequest,
    BudgetDenied,
    BudgetLimits,
    BudgetPolicy,
    BudgetStoreError,
)
from cops.evidence.canonical import EvidenceError, canonical, decode_json
from cops.execution.gateway_dispatch import (
    MAX_GATEWAY_RESPONSE_BYTES,
    GatewayDispatchEmulator,
    GatewayDispatchError,
    GatewayDispatchGrant,
)
from cops.provider_assessment import (
    ProviderAssessmentError,
    _bounded,
    _validate,
    normalize_response,
    report_case_id,
)

_PLAN_SCHEMA = "provider-live-plan.schema.json"
_CASES_SCHEMA = "provider-live-cases.schema.json"
_CASES_VERSION = "cops.ai-provider-live-assessment-cases/v2"
_DENIED = "live provider dispatch denied"
_LOG = logging.getLogger(__name__)


class ProviderLiveError(ValueError):
    """A live request failed closed before any gateway dispatch."""


def _deny() -> ProviderLiveError:
    return ProviderLiveError(_DENIED)


def _mark_uncertain_or_observe(ledger: AssessmentBudgetLedger, attempt_id: str) -> str:
    """Keep a committed intent charged even if the store raises after commit."""
    try:
        return ledger.mark_uncertain(attempt_id).state
    except Exception:
        try:
            state = ledger.get_attempt(attempt_id).state
            if state == "dispatched":
                try:
                    return ledger.mark_uncertain(attempt_id).state
                except Exception:
                    state = ledger.get_attempt(attempt_id).state
            return state if state in {"dispatched", "uncertain", "usage_unknown"} else "unknown"
        except Exception:
            return "unknown"


def _redacted_evidence(case: dict[str, Any], estimate: dict[str, int], ledger_state: str) -> dict[str, Any]:
    return {
        "case_id": report_case_id(case["case_id"]),
        "provider": case["provider"],
        "outcome": "uncertain",
        "response_state": "unknown",
        "usage_state": "unknown",
        "ledger_state": ledger_state,
        "billing_state": "unreconciled",
        "tool_proposal_count": 0,
        "tool_proposal_digest": None,
        "estimated_cost_microunits": estimate["cost_microunits"],
    }


def _dispatch_with_deadline(gateway: GatewayDispatchEmulator, *, timeout_ms: int, **kwargs: Any) -> Any:
    """Bound the local emulator wait without replaying an ambiguous dispatch."""
    if timeout_ms <= 0:
        raise TimeoutError("provider dispatch deadline expired")
    result: Queue[tuple[bool, Any]] = Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, gateway.dispatch(**kwargs)))
        except BaseException as exc:
            result.put((False, exc))

    Thread(target=invoke, name="provider-gateway-dispatch", daemon=True).start()
    try:
        succeeded, value = result.get(timeout=timeout_ms / 1000)
    except Empty:
        raise TimeoutError("provider dispatch deadline expired") from None
    if not succeeded:
        raise value
    return value


def live_plan_digest(plan: dict[str, Any]) -> str:
    """Hash the approved plan without its circular, separately signed grants."""
    try:
        _bounded(plan)
        _validate(plan, _PLAN_SCHEMA)
        unsigned = deepcopy(plan)
        for environment in unsigned["environments"]:
            for request in environment["approved_requests"]:
                request.pop("dispatch_grant")
        digest = hashlib.sha256(canonical(unsigned, max_bytes=262_144)).hexdigest()
    except (ProviderAssessmentError, EvidenceError, KeyError, TypeError, ValueError):
        # Raise outside the handler so even exception-graph telemetry cannot
        # reach the original input or validator error.
        pass
    else:
        return digest
    raise _deny()


def _policy(plan: dict[str, Any]) -> BudgetPolicy:
    budget = plan["shared_budget"]
    return BudgetPolicy(
        engagement_id=plan["engagement_id"],
        limits=BudgetLimits(**budget["limits"]),
        currency=budget["currency"],
        price_source=budget["price_source"],
        price_version=budget["price_version"],
        price_effective_date=budget["price_effective_date"],
    )


def _approved_request(plan: dict[str, Any], case: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    environments = plan["environments"]
    if len({item["environment_id"] for item in environments}) != len(environments):
        raise _deny()
    environment = next((item for item in environments if item["environment_id"] == case["environment_id"]), None)
    if environment is None:
        raise _deny()
    scope = (
        "provider",
        "account_or_project_kind",
        "account_or_project",
        "region",
        "model",
        "request_target",
        "endpoint_origin",
        "gateway_path",
        "gateway_endpoint_id",
        "gateway_spiffe_id",
    )
    if any(case[key] != environment[key] for key in scope):
        raise _deny()
    if not set(case["requested_tools"]).issubset(environment["allowed_tools"]):
        raise _deny()
    approved = environment["approved_requests"]
    if len({item["request_id"] for item in approved}) != len(approved):
        raise _deny()
    request = case["request"]
    matched = next((item for item in approved if item["request_id"] == request["request_id"]), None)
    if matched is None or (
        request["canary_id"] != matched["canary_id"]
        or request["body_sha256"] != matched["request_sha256"]
        or request["max_output_tokens"] > matched["max_output_tokens"]
        or case["dispatch_grant"] != matched["dispatch_grant"]
    ):
        raise _deny()
    return environment, matched


def _body(case: dict[str, Any]) -> bytes:
    request = case["request"]
    raw = request["body_canonical_json"].encode("utf-8")
    if len(raw) != request["body_size_bytes"] or len(raw) > 262_144:
        raise _deny()
    malformed = False
    try:
        decoded = decode_json(raw, max_bytes=262_144, max_depth=16)
        if canonical(decoded, max_bytes=262_144, max_depth=16) != raw:
            raise _deny()
    except EvidenceError:
        malformed = True
    if malformed:
        raise _deny()
    if hashlib.sha256(raw).hexdigest() != request["body_sha256"]:
        raise _deny()
    _validate_provider_request(case, decoded)
    return raw


def _validate_provider_request(case: dict[str, Any], body: Any) -> None:
    """Accept only the text canary subset of each pinned provider API.

    Signed bytes alone do not make a provider request safe: an approved digest
    could otherwise include remote tools, stored conversations, or arbitrary
    endpoints. Model, output limit, and endpoint are checked independently.
    """
    if not isinstance(body, dict):
        raise _deny()
    provider = case["provider"]
    target = urlsplit(case["request_target"])
    model = case["model"]
    max_tokens = case["request"]["max_output_tokens"]
    if target.query or target.fragment or target.username or target.password:
        raise _deny()
    if provider in {"openai", "azure"}:
        path = "/v1/responses" if provider == "openai" else "/openai/v1/responses"
        if (
            target.path != path
            or set(body) != {"model", "input", "max_output_tokens", "store", "stream"}
            or body["model"] != model
            or not isinstance(body["input"], str)
            or not body["input"].strip()
            or type(body["max_output_tokens"]) is not int
            or body["max_output_tokens"] != max_tokens
            or body["store"] is not False
            or body["stream"] is not False
        ):
            raise _deny()
    elif provider == "aws":
        if (
            target.path != f"/model/{model}/converse"
            or set(body) != {"messages", "inferenceConfig"}
            or not isinstance(body["messages"], list)
            or len(body["messages"]) != 1
            or not isinstance(body["messages"][0], dict)
            or set(body["messages"][0]) != {"role", "content"}
            or body["messages"][0]["role"] != "user"
            or not isinstance(body["messages"][0]["content"], list)
            or len(body["messages"][0]["content"]) != 1
            or not isinstance(body["messages"][0]["content"][0], dict)
            or set(body["messages"][0]["content"][0]) != {"text"}
            or not isinstance(body["messages"][0]["content"][0]["text"], str)
            or not body["messages"][0]["content"][0]["text"].strip()
            or not isinstance(body["inferenceConfig"], dict)
            or set(body["inferenceConfig"]) != {"maxTokens"}
            or type(body["inferenceConfig"]["maxTokens"]) is not int
            or body["inferenceConfig"]["maxTokens"] != max_tokens
        ):
            raise _deny()
    elif provider == "gcp":
        path = (
            f"/v1/projects/{case['account_or_project']}/locations/{case['region']}"
            f"/publishers/google/models/{model}:generateContent"
        )
        if (
            case["account_or_project_kind"] != "project"
            or target.path != path
            or set(body) != {"contents", "generationConfig"}
            or not isinstance(body["contents"], list)
            or len(body["contents"]) != 1
            or not isinstance(body["contents"][0], dict)
            or set(body["contents"][0]) != {"role", "parts"}
            or body["contents"][0]["role"] != "user"
            or not isinstance(body["contents"][0]["parts"], list)
            or len(body["contents"][0]["parts"]) != 1
            or not isinstance(body["contents"][0]["parts"][0], dict)
            or set(body["contents"][0]["parts"][0]) != {"text"}
            or not isinstance(body["contents"][0]["parts"][0]["text"], str)
            or not body["contents"][0]["parts"][0]["text"].strip()
            or not isinstance(body["generationConfig"], dict)
            or set(body["generationConfig"]) != {"maxOutputTokens"}
            or type(body["generationConfig"]["maxOutputTokens"]) is not int
            or body["generationConfig"]["maxOutputTokens"] != max_tokens
        ):
            raise _deny()
    else:
        raise _deny()


def _tool_names(provider: str, response: dict[str, Any]) -> list[str]:
    if provider == "aws":
        return [item["toolUse"]["name"] for item in response["output"]["message"]["content"] if "toolUse" in item]
    if provider in {"openai", "azure"}:
        return [item["name"] for item in response.get("output", []) if item.get("type") == "function_call"]
    names: list[str] = []
    for candidate in response.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            if "functionCall" in part:
                names.append(part["functionCall"]["name"])
    return names


def execute_live_case(
    plan: dict[str, Any],
    case: dict[str, Any],
    *,
    gateway: GatewayDispatchEmulator,
    ledger: AssessmentBudgetLedger,
    trusted_gateway_origin: str,
    trusted_gateway_identity: str,
    worker_spiffe_id: str,
    cleanup: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Dispatch one approved canary once and emit only redacted evidence.

    Once intent is durable, every transport or response ambiguity remains charged
    and uncertain. This function never retries a gateway or provider call.
    """
    cleanup_attempted = False
    dispatch_intent_uncertain = False
    intent_ledger_state = "unknown"
    denied = False
    try:
        if not isinstance(gateway, GatewayDispatchEmulator) or not isinstance(ledger, AssessmentBudgetLedger):
            raise _deny()
        _bounded(plan)
        _bounded(case)
        _validate(plan, _PLAN_SCHEMA)
        _validate({"schema_version": _CASES_VERSION, "cases": [case]}, _CASES_SCHEMA)
        environment, approved = _approved_request(plan, case)
        provider_host = urlsplit(case["request_target"]).hostname
        gateway_host = urlsplit(trusted_gateway_origin).hostname
        if (
            trusted_gateway_origin != environment["endpoint_origin"]
            or trusted_gateway_identity != environment["gateway_spiffe_id"]
            or not gateway_host
            or gateway_host == provider_host
            or case["estimate"] != approved["estimate"]
            or case["estimate"]["request_bytes"] != case["request"]["body_size_bytes"]
            or case["estimate"]["input_tokens"] < case["request"]["body_size_bytes"]
            or case["estimate"]["output_tokens"] != approved["max_output_tokens"]
            or case["request"]["max_output_tokens"] != approved["max_output_tokens"]
            or ledger.policy != _policy(plan)
        ):
            raise _deny()
        body = _body(case)
        grant = GatewayDispatchGrant.from_dict(approved["dispatch_grant"])
        digest = live_plan_digest(plan)
        scope = (
            "provider",
            "account_or_project_kind",
            "account_or_project",
            "region",
            "model",
            "request_target",
            "gateway_endpoint_id",
        )
        if (
            grant.action_plan_id != plan["action_plan_id"]
            or grant.plan_digest != digest
            or grant.worker_spiffe_id != worker_spiffe_id
            or grant.body_sha256 != case["request"]["body_sha256"]
            or grant.body_bytes != len(body)
            or any(getattr(grant, key) != case[key] for key in scope)
        ):
            raise _deny()
        endpoint = gateway.preflight(
            grant=grant,
            presented_worker_spiffe_id=worker_spiffe_id,
            request_target=case["request_target"],
            body=body,
        )
        if (
            endpoint.gateway_identity != trusted_gateway_identity
            or endpoint.endpoint_origin != trusted_gateway_origin
            or endpoint.gateway_path != case["gateway_path"]
        ):
            raise _deny()
        attempt_id = "live-" + hashlib.sha256(grant.dispatch_id.encode("ascii")).hexdigest()
        try:
            ledger.get_attempt(attempt_id)
        except BudgetDenied as exc:
            if str(exc) != "attempt not found":
                raise
        else:
            raise _deny()
        estimate = case["estimate"]
        ledger.reserve(
            AttemptRequest(
                attempt_id=attempt_id,
                parent_id=None,
                estimated_tokens=estimate["input_tokens"] + estimate["output_tokens"],
                estimated_cost_microunits=estimate["cost_microunits"],
                reserved_output_bytes=estimate["response_bytes"],
            )
        )
        intent = {
            "approval_issued_at": grant.issued_at,
            "approval_expires_at": grant.expires_at,
            "dispatch_id": grant.dispatch_id,
            "plan_digest": digest,
            "body_sha256": grant.body_sha256,
            "provider": case["provider"],
            "account_or_project_kind": case["account_or_project_kind"],
            "account_or_project": case["account_or_project"],
            "region": case["region"],
            "model": case["model"],
            "request_target": case["request_target"],
            "gateway_path": case["gateway_path"],
            "gateway_endpoint_id": case["gateway_endpoint_id"],
            "gateway_identity": trusted_gateway_identity,
            "currency": plan["shared_budget"]["currency"],
        }
        try:
            ledger.mark_dispatched(
                attempt_id,
                approval_receipt_id=grant.authorization_id,
                dispatch_intent=intent,
            )
        except Exception:
            try:
                attempt = ledger.get_attempt(attempt_id)
            except Exception:
                # Store state cannot be proved after a write failure. Do not
                # dispatch or release a reservation on that ambiguity.
                dispatch_intent_uncertain = True
            else:
                if attempt.state == "reserved":
                    try:
                        ledger.release_undispatched(attempt_id)
                    except Exception:
                        _LOG.warning("provider reservation release could not be confirmed")
                    raise _deny()
                dispatch_intent_uncertain = True
                if attempt.state in {"dispatched", "uncertain"}:
                    try:
                        if ledger.get_dispatch_intent(attempt_id) == intent:
                            intent_ledger_state = _mark_uncertain_or_observe(ledger, attempt_id)
                    except Exception:
                        _LOG.warning("provider dispatch intent state could not be confirmed")
    except (
        ProviderAssessmentError,
        GatewayDispatchError,
        BudgetDenied,
        BudgetStoreError,
        EvidenceError,
        KeyError,
        TypeError,
        ValueError,
    ):
        denied = True
    if denied:
        # Raising after the handler prevents sensitive source exceptions from
        # remaining reachable through __context__.
        raise _deny()

    evidence = _redacted_evidence(case, estimate, intent_ledger_state if dispatch_intent_uncertain else "dispatched")
    if dispatch_intent_uncertain:
        return evidence
    try:
        receipt = _dispatch_with_deadline(
            gateway,
            timeout_ms=min(estimate["elapsed_ms"], ledger.remaining_elapsed_ms()),
            grant=grant,
            presented_worker_spiffe_id=worker_spiffe_id,
            request_target=case["request_target"],
            body=body,
        )
        if receipt.response is None or receipt.response.status_code != 200:
            raise ProviderLiveError("gateway response was incomplete")
        if len(receipt.response.body) > estimate["response_bytes"]:
            raise ProviderLiveError("gateway response exceeded reserved bytes")
        response = decode_json(receipt.response.body, max_bytes=MAX_GATEWAY_RESPONSE_BYTES, max_depth=16)
        _validate({"provider": case["provider"], "response": response}, "provider-live-response.schema.json")
        state, tokens, output_tokens = normalize_response(case["provider"], response)
        if state == "partial" or (output_tokens is not None and output_tokens > case["request"]["max_output_tokens"]):
            raise ProviderLiveError("provider response was incomplete")
        proposed = _tool_names(case["provider"], response)
        if not set(proposed).issubset(case["requested_tools"]) or not set(proposed).issubset(
            environment["allowed_tools"]
        ):
            raise ProviderLiveError("provider proposed an unapproved tool")
        if proposed and state == "completed":
            state = "tool_proposal"
        if cleanup is not None:
            cleanup_attempted = True
            if cleanup() is not True:
                raise ProviderLiveError("cleanup did not complete")
        # The provider envelope is not an authenticated usage or billing receipt.
        # Retain the full reservation until an independent reconciliation path
        # verifies the outcome and usage; the emulator must not settle it.
        pending_state = _mark_uncertain_or_observe(ledger, attempt_id)
        evidence.update(
            outcome=state,
            response_state=state,
            usage_state="reported" if tokens is not None else "unknown",
            ledger_state=pending_state,
            tool_proposal_count=len(proposed),
            tool_proposal_digest=hashlib.sha256(canonical(sorted(proposed))).hexdigest() if proposed else None,
        )
        return evidence
    except Exception:
        # Any transport, provider, parser, or cleanup failure after durable intent
        # can have an unknown effect. Preserve the reservation and never replay.
        evidence["ledger_state"] = _mark_uncertain_or_observe(ledger, attempt_id)
        if cleanup is not None and not cleanup_attempted:
            cleanup_attempted = True
            try:
                cleanup()
            except Exception:
                _LOG.warning("provider assessment cleanup did not complete")
        return evidence
    except BaseException:
        # Cancellation has the same uncertain effect, but callers must still
        # receive the cancellation so that their worker can stop promptly.
        _mark_uncertain_or_observe(ledger, attempt_id)
        if cleanup is not None and not cleanup_attempted:
            cleanup_attempted = True
            try:
                cleanup()
            except Exception:
                _LOG.warning("provider assessment cleanup did not complete")
        raise
