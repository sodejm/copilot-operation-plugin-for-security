"""Bounded API request preview, offline replay, and approved live replay."""

from __future__ import annotations

import json
import math
import re
import time
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

from cops.contracts.models import ActionPlan
from cops.evidence.canonical import digest, utc_now
from cops.execution.control import ApprovalConsumptionReceipt, ApprovalControl
from cops.execution.scope_guard import ScopeGuard, ScopeViolationError

from .models import (
    SENSITIVE_FIELD_PATTERNS,
    ApiProtocol,
    ReplayBudget,
    ReplayRequest,
    ReplayResponse,
    ReplaySessionReport,
    SessionContext,
    redact_credential_value,
    redact_mapping,
)


class DestinationViolationError(Exception):
    """A replay destination is outside its explicit destination allowlist."""


class ReplayBudgetExceededError(Exception):
    """An operational replay budget is invalid or exhausted."""


class ReplayAuthorizationError(Exception):
    """Live replay is missing or does not match an approved action plan."""


class DestinationGuard:
    """Match URL hosts against exact hosts, exact host:ports, or wildcard domains."""

    def __init__(self, allowed_destinations: list[str]) -> None:
        self.allowed_destinations = [item.strip().lower() for item in allowed_destinations if item.strip()]

    def is_destination_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host or parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
            return False
        default_port = 443 if parsed.scheme.lower() in {"https", "wss"} else 80
        authority = f"{host}:{parsed.port or default_port}"
        for allowed in self.allowed_destinations:
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if host == suffix or host.endswith("." + suffix):
                    return True
            elif ":" in allowed:
                if authority == allowed:
                    return True
            elif host == allowed:
                return True
        return False

    def check_destination(self, url: str) -> None:
        if not self.is_destination_allowed(url):
            raise DestinationViolationError("destination is outside the authorized allowlist")


class Replayer(ABC):
    """Request replayer interface."""

    @abstractmethod
    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        """Send one request within the supplied budget."""


class OfflineSyntheticReplayer(Replayer):
    """Deterministic offline simulation used for safe previews and tests."""

    def __init__(
        self,
        mock_routes: dict[str, dict[str, Any]] | None = None,
        simulate_latency_ms: float = 2.0,
    ) -> None:
        self.mock_routes = mock_routes or {}
        self.simulate_latency_ms = simulate_latency_ms
        self.requests_sent: list[ReplayRequest] = []

    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        self.requests_sent.append(req)
        parsed = urlparse(req.url)
        route = self.mock_routes.get(f"{req.method.upper()} {parsed.path}") or self.mock_routes.get(parsed.path) or {}
        redirect_to = route.get("redirect_to")
        if redirect_to:
            hops = int(route.get("redirect_hops", 1))
            if hops > budget.max_redirect_hops:
                return ReplayResponse(
                    request_id=req.request_id,
                    status_code=302,
                    headers={"Location": str(redirect_to)},
                    body_excerpt="Redirect limit exceeded",
                    latency_ms=self.simulate_latency_ms,
                    redirect_count=hops,
                    final_url=str(redirect_to),
                    error_message="Maximum redirect hops exceeded",
                    replay_success=False,
                )
            return ReplayResponse(
                request_id=req.request_id,
                status_code=int(route.get("final_status", 200)),
                headers=dict(route.get("headers", {"Content-Type": "application/json"})),
                body_excerpt=str(route.get("body", '{"status":"ok","redirected":true}')),
                latency_ms=self.simulate_latency_ms,
                redirect_count=hops,
                final_url=str(redirect_to),
            )
        if req.protocol == ApiProtocol.GRAPHQL.value or "graphql" in parsed.path.lower():
            query = req.graphql_query or req.body or ""
            body = route.get("body")
            if body is None and ("IntrospectionQuery" in query or "__schema" in query):
                body = '{"data":{"__schema":{"types":[{"name":"User"},{"name":"Query"}]}}}'
            return ReplayResponse(
                request_id=req.request_id,
                status_code=int(route.get("status", 200)),
                headers=dict(route.get("headers", {"Content-Type": "application/json"})),
                body_excerpt=str(body or '{"data":{"result":"success"}}'),
                latency_ms=self.simulate_latency_ms,
                final_url=req.url,
                replay_success=int(route.get("status", 200)) < 400,
            )
        if req.protocol == ApiProtocol.WEBSOCKET.value:
            messages = (req.websocket_messages or ["ping"])[: budget.max_websocket_frames]
            return ReplayResponse(
                request_id=req.request_id,
                status_code=101,
                headers={"Upgrade": "websocket", "Connection": "Upgrade"},
                body_excerpt="WebSocket connection established and frames exchanged",
                latency_ms=self.simulate_latency_ms,
                websocket_replies=[f"echo:{message}" for message in messages],
                final_url=req.url,
            )
        status = int(route.get("status", 200))
        return ReplayResponse(
            request_id=req.request_id,
            status_code=status,
            headers=dict(route.get("headers", {"Content-Type": "application/json"})),
            body_excerpt=str(route.get("body", '{"message":"Synthetic response","success":true}')),
            latency_ms=self.simulate_latency_ms,
            final_url=req.url,
            error_message=route.get("error"),
            replay_success=status < 400,
        )


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    return scheme, (parsed.hostname or "").lower(), parsed.port or (443 if scheme == "https" else 80)


class _CheckedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect target and prevent credential forwarding across origins."""

    def __init__(self, guard: DestinationGuard, scope_guard: ScopeGuard, max_hops: int) -> None:
        super().__init__()
        self.guard = guard
        self.scope_guard = scope_guard
        self.max_hops = max_hops
        self.redirect_count = 0

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        target = urljoin(req.full_url, newurl)
        self.redirect_count += 1
        if self.redirect_count > self.max_hops:
            raise DestinationViolationError("Maximum redirect hops exceeded")
        self.guard.check_destination(target)
        self.scope_guard.check_destination(target)
        old_origin, new_origin = _origin(req.full_url), _origin(target)
        if old_origin[0] == "https" and new_origin[0] != "https":
            raise DestinationViolationError("HTTPS redirect downgrade rejected")
        if old_origin != new_origin and any(SENSITIVE_FIELD_PATTERNS.search(name) for name in req.headers):
            raise DestinationViolationError("cross-origin redirect with credentials rejected")
        return super().redirect_request(req, fp, code, msg, headers, target)


class StandardHttpReplayer(Replayer):
    """Live urllib replayer requiring destination and engagement-scope guards."""

    def __init__(self, destination_guard: DestinationGuard, scope_guard: ScopeGuard) -> None:
        self.destination_guard = destination_guard
        self.scope_guard = scope_guard

    def send(self, req: ReplayRequest, budget: ReplayBudget) -> ReplayResponse:
        if req.protocol == ApiProtocol.WEBSOCKET.value:
            raise ReplayAuthorizationError("live WebSocket replay is unsupported")
        parsed = urlparse(req.url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise DestinationViolationError("only HTTP and HTTPS replay are supported")
        self.destination_guard.check_destination(req.url)
        self.scope_guard.check_destination(req.url)
        url = req.url
        if req.query_parameters:
            parsed = urlparse(url)
            query = urlencode(req.query_parameters)
            url = urlunparse(parsed._replace(query=f"{parsed.query}&{query}" if parsed.query else query))
        handler = _CheckedRedirectHandler(self.destination_guard, self.scope_guard, budget.max_redirect_hops)
        opener = urllib.request.build_opener(handler)
        wire_request = urllib.request.Request(  # noqa: S310 -- HTTP(S) scheme and scope checked above.
            url,
            data=req.body.encode("utf-8") if req.body is not None else None,
            headers=dict(req.headers),
            method=req.method.upper(),
        )
        started = time.monotonic()
        try:
            with opener.open(wire_request, timeout=budget.timeout_seconds) as response:  # noqa: S310  # HTTP(S), scope and redirect destinations are checked above.
                final_url = response.geturl()
                self.destination_guard.check_destination(final_url)
                self.scope_guard.check_destination(final_url)
                body = response.read(2048).decode("utf-8", errors="replace")
                return ReplayResponse(
                    request_id=req.request_id,
                    status_code=int(response.status),
                    headers=dict(response.headers.items()),
                    body_excerpt=body,
                    latency_ms=(time.monotonic() - started) * 1000,
                    redirect_count=handler.redirect_count,
                    final_url=final_url,
                    replay_success=int(response.status) < 400,
                )
        except HTTPError as error:
            final_url = error.geturl()
            self.destination_guard.check_destination(final_url)
            self.scope_guard.check_destination(final_url)
            return ReplayResponse(
                request_id=req.request_id,
                status_code=int(error.code),
                headers=dict(error.headers.items()) if error.headers else {},
                body_excerpt=error.read(2048).decode("utf-8", errors="replace"),
                latency_ms=(time.monotonic() - started) * 1000,
                redirect_count=handler.redirect_count,
                final_url=final_url,
                error_message=f"HTTP {error.code}",
                replay_success=False,
            )
        except (DestinationViolationError, ScopeViolationError):
            raise
        except (URLError, TimeoutError, OSError) as error:
            return ReplayResponse(
                request_id=req.request_id,
                status_code=0,
                latency_ms=(time.monotonic() - started) * 1000,
                redirect_count=handler.redirect_count,
                final_url=url,
                error_message=type(error).__name__,
                replay_success=False,
            )


def _redact_body(body: str | None) -> str | None:
    if body is None:
        return None
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        value = None
    if value is not None:

        def redact(item: Any, sensitive: bool = False) -> Any:
            if sensitive:
                raw = (
                    json.dumps(item, sort_keys=True, separators=(",", ":"))
                    if isinstance(item, (dict, list))
                    else str(item)
                )
                return redact_credential_value(raw)
            if isinstance(item, dict):
                return {
                    key: redact(child, bool(SENSITIVE_FIELD_PATTERNS.search(str(key)))) for key, child in item.items()
                }
            if isinstance(item, list):
                return [redact(child, sensitive) for child in item]
            return item

        return json.dumps(redact(value), sort_keys=True, separators=(",", ":"))
    result = re.sub(
        r"(?i)((?:password|secret|token|auth|key|bearer|credential|session|cookie|jwt|api_key|access_token|refresh_token)=)([^&\s]+)",
        lambda match: match.group(1) + redact_credential_value(match.group(2)),
        body,
    )
    return re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        lambda match: "Bearer " + redact_credential_value(match.group(0).split(None, 1)[1]),
        result,
    )


def _sanitize_request(req: ReplayRequest) -> ReplayRequest:
    return replace(
        req,
        headers=redact_mapping(req.headers),
        query_parameters=redact_mapping(req.query_parameters),
        body=_redact_body(req.body),
        graphql_query=_redact_body(req.graphql_query),
        websocket_messages=[_redact_body(message) or "" for message in req.websocket_messages],
    )


def _sanitize_response(response: ReplayResponse) -> ReplayResponse:
    return replace(
        response,
        headers=redact_mapping(response.headers),
        body_excerpt=_redact_body(response.body_excerpt) or "",
        websocket_replies=[_redact_body(message) or "" for message in response.websocket_replies],
    )


def _validate_budget(budget: ReplayBudget) -> None:
    if budget.max_requests < 1 or budget.max_requests > 1000:
        raise ReplayBudgetExceededError("max_requests must be between 1 and 1000")
    if budget.timeout_seconds <= 0 or budget.timeout_seconds > 86400:
        raise ReplayBudgetExceededError("timeout_seconds must be between 0 and 86400")
    if budget.rate_limit_rps < 0:
        raise ReplayBudgetExceededError("rate_limit_rps cannot be negative")
    if budget.max_redirect_hops < 0:
        raise ReplayBudgetExceededError("max_redirect_hops cannot be negative")


def _report(
    *,
    requests: list[ReplayRequest],
    responses: list[ReplayResponse],
    allowed_destinations: list[str],
    budget: ReplayBudget,
    session_id: str | None,
    violations: int,
) -> ReplaySessionReport:
    targets = sorted({urlparse(item.url).netloc for item in requests if urlparse(item.url).netloc})
    identifier = (
        session_id
        or f"rep-sess-{digest({'destinations': sorted(allowed_destinations), 'requests': [item.request_id for item in requests]})[:12]}"
    )
    return ReplaySessionReport(
        session_id=identifier,
        target_hosts=targets,
        allowed_destinations=list(allowed_destinations),
        budget=budget,
        requests=[_sanitize_request(item) for item in requests],
        responses=[_sanitize_response(item) for item in responses],
        total_dispatched=len(responses),
        total_successful=sum(item.replay_success for item in responses),
        total_failed=sum(not item.replay_success for item in responses),
        destination_violations=violations,
    )


def preview_replay_session(
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Create a redacted, side-effect-free preview without dispatching requests."""
    active_budget = budget or ReplayBudget()
    _validate_budget(active_budget)
    if len(requests) > active_budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    guard = DestinationGuard(allowed_destinations)
    for request in requests:
        guard.check_destination(request.url)
    return _report(
        requests=requests,
        responses=[],
        allowed_destinations=allowed_destinations,
        budget=active_budget,
        session_id=session_id,
        violations=0,
    )


def _live_request(req: ReplayRequest, sessions: dict[str, SessionContext]) -> ReplayRequest:
    if req.session_id is None:
        return req
    session = sessions.get(req.session_id)
    if session is None or not session.is_isolated:
        raise ReplayAuthorizationError("request refers to an unknown or unisolated session")
    if req.role_id is not None and req.role_id != session.role_id:
        raise ReplayAuthorizationError("request role does not match its isolated session")
    headers = dict(session.headers)
    session_header_names = {name.lower() for name in headers}
    credential_overrides = [
        name for name in req.headers if name.lower() in session_header_names and SENSITIVE_FIELD_PATTERNS.search(name)
    ]
    if credential_overrides:
        raise ReplayAuthorizationError("request credentials cannot override isolated session credentials")
    request_cookie = next((value for key, value in req.headers.items() if key.lower() == "cookie"), None)
    if request_cookie is not None and session.cookies:
        raise ReplayAuthorizationError("request cookie cannot override isolated session cookies")
    if session.cookies:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in sorted(session.cookies.items()))
    headers.update(req.headers)
    return replace(req, headers=headers, role_id=req.role_id or session.role_id)


def _plan_parts(
    requests: list[ReplayRequest], budget: ReplayBudget
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if not requests:
        raise ReplayAuthorizationError("live replay requires at least one request")
    operations = [
        {
            "step_id": request.request_id,
            "tool": "cops.web_api.standard-http-replayer",
            "tool_version": "1",
            "action": "replay_http_request",
            "arguments": {
                "request_digest": digest(request.to_dict()),
                "method": request.method.upper(),
                "url": request.url,
                "protocol": request.protocol,
                "session_id": request.session_id or "",
            },
            "timeout_seconds": max(1, math.ceil(budget.timeout_seconds)),
            "side_effects": ["network_connections"],
            "cleanup": {"strategy": "none", "resources": []},
        }
        for request in requests
    ]
    pacing_seconds = (len(requests) - 1) / budget.rate_limit_rps if budget.rate_limit_rps > 0 else 0
    limits = {
        "max_duration_seconds": max(1, math.ceil(budget.timeout_seconds * len(requests) + pacing_seconds)),
        "max_output_bytes": max(1, 2048 * len(requests)),
        "egress_allowed": True,
    }
    batch = {"mode": "sequential", "max_operations": len(requests), "fail_fast": True}
    return operations, limits, batch


def build_replay_action_plan(
    *,
    plan_id: str,
    engagement_id: str,
    scenario_id: str,
    specialist_id: str,
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    credential_references: list[str] | None = None,
    created_at: str | None = None,
) -> ActionPlan:
    """Build the exact immutable plan which an approval must authorize for live replay."""
    active_budget = budget or ReplayBudget()
    _validate_budget(active_budget)
    if not allowed_destinations:
        raise ReplayAuthorizationError("live replay requires an explicit destination allowlist")
    if len(requests) > active_budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    identifiers = [request.request_id for request in requests]
    if len(set(identifiers)) != len(identifiers):
        raise ReplayAuthorizationError("request identifiers must be unique")
    guard = DestinationGuard(allowed_destinations)
    for request in requests:
        guard.check_destination(request.url)
    operations, limits, batch = _plan_parts(requests, active_budget)
    return ActionPlan.create(
        plan_id=plan_id,
        engagement_id=engagement_id,
        scenario_id=scenario_id,
        target=allowed_destinations[0],
        specialist_id=specialist_id,
        operations=operations,
        limits=limits,
        credential_references=list(credential_references or []),
        created_at=created_at or utc_now(),
        batch=batch,
    )


def execute_replay_session(
    requests: list[ReplayRequest],
    allowed_destinations: list[str],
    budget: ReplayBudget | None = None,
    replayer: Replayer | None = None,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Run deterministic offline replay; network replay requires the approved entry point."""
    active_budget = budget or ReplayBudget()
    active_replayer = replayer or OfflineSyntheticReplayer()
    if not isinstance(active_replayer, OfflineSyntheticReplayer):
        raise ReplayAuthorizationError("live replay requires execute_authorized_replay_session")
    _validate_budget(active_budget)
    guard = DestinationGuard(allowed_destinations)
    selected = requests[: active_budget.max_requests]
    responses: list[ReplayResponse] = []
    violations = 0
    for request in selected:
        if not guard.is_destination_allowed(request.url):
            violations += 1
            responses.append(
                ReplayResponse(
                    request_id=request.request_id,
                    status_code=403,
                    body_excerpt="Target destination outside authorized allowlist",
                    final_url=request.url,
                    error_message="rejected by destination allowlist",
                    replay_success=False,
                )
            )
            continue
        responses.append(active_replayer.send(request, active_budget))
    return _report(
        requests=selected,
        responses=responses,
        allowed_destinations=allowed_destinations,
        budget=active_budget,
        session_id=session_id,
        violations=violations,
    )


def execute_authorized_replay_session(
    *,
    requests: list[ReplayRequest],
    sessions: list[SessionContext],
    allowed_destinations: list[str],
    scope_guard: ScopeGuard,
    budget: ReplayBudget,
    action_plan: ActionPlan,
    authorization_id: str,
    approval_control: ApprovalControl,
    worker_identity: str,
    session_id: str | None = None,
) -> ReplaySessionReport:
    """Consume one exact approval, then dispatch the corresponding bounded live replay."""
    _validate_budget(budget)
    if not allowed_destinations:
        raise ReplayAuthorizationError("live replay requires an explicit destination allowlist")
    if len(requests) > budget.max_requests:
        raise ReplayBudgetExceededError("request count exceeds max_requests")
    destination_guard = DestinationGuard(allowed_destinations)
    session_map = {session.session_id: session for session in sessions}
    if len(session_map) != len(sessions):
        raise ReplayAuthorizationError("session identifiers must be unique")
    wire_requests = [_live_request(request, session_map) for request in requests]
    for request in wire_requests:
        destination_guard.check_destination(request.url)
        scope_guard.check_destination(request.url)
    expected_operations, expected_limits, expected_batch = _plan_parts(requests, budget)
    snapshot = action_plan.approved_snapshot()
    if (
        snapshot["target"] != allowed_destinations[0]
        or snapshot["operations"] != expected_operations
        or snapshot["limits"] != expected_limits
        or snapshot["batch"] != expected_batch
    ):
        raise ReplayAuthorizationError("action plan does not match the requested replay")
    approval_control.assert_ready(worker_identity)
    receipt: ApprovalConsumptionReceipt | None = approval_control.consume_authorization(
        authorization_id, action_plan, worker_identity
    )
    try:
        receipt = approval_control.validate_receipt_provenance(receipt)
        replayer = StandardHttpReplayer(destination_guard, scope_guard)
        responses: list[ReplayResponse] = []
        delay = 1.0 / budget.rate_limit_rps if budget.rate_limit_rps > 0 else 0.0
        for index, request in enumerate(wire_requests):
            if index and delay:
                time.sleep(delay)
            responses.append(replayer.send(request, budget))
        return _report(
            requests=requests,
            responses=responses,
            allowed_destinations=allowed_destinations,
            budget=budget,
            session_id=session_id,
            violations=0,
        )
    finally:
        if receipt is not None:
            approval_control.release_receipt_provenance(receipt)
