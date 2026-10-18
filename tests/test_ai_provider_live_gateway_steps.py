"""Executable acceptance scenarios for the local provider gateway emulator."""

import json
from copy import deepcopy

import pytest
from pytest_bdd import given, scenarios, then, when

from cops.evidence.canonical import canonical
from cops.execution.gateway_dispatch import GatewayDispatchResponse
from cops.provider_live import ProviderLiveError, execute_live_case
from test_provider_live_execution import _setup

scenarios("../specs/features/ai_provider_live_gateway.feature")


@pytest.fixture
def context(tmp_path):
    return {"path": tmp_path}


@given("approved live emulator cases for OpenAI, Azure, AWS, and GCP")
def four_cases(context):
    context["cases"] = [
        _setup(context["path"] / provider, provider, scoped_handler=True)
        for provider in ("openai", "azure", "aws", "gcp")
    ]


@when("each case is dispatched through its signed gateway emulator")
def dispatch_four(context):
    context["results"] = [execute_live_case(plan, case, **args) for plan, case, args, _ in context["cases"]]


@then("each result has a normalized outcome and a conservative budget state")
def normalized_results(context):
    assert all(result["outcome"] == "completed" and result["ledger_state"] == "uncertain"
               for result in context["results"])
    assert all(called == ["dispatch-001"] for _, _, _, called in context["cases"])


@then("no prompt, endpoint, account, or provider output appears in public evidence")
def redacted_results(context):
    for (_, case, _, _), result in zip(context["cases"], context["results"], strict=True):
        public = json.dumps(result)
        for private in ("COPS_CANARY_001", "PRIVATE_CANARY_RESPONSE", case["request_target"],
                        case["account_or_project"]):
            assert private not in public


@given("a live case with a changed gateway, worker, provider scope, request, or canary")
def changed_boundaries(context):
    context["changes"] = (
        lambda case, args: args.update(trusted_gateway_origin="https://wrong.example.test"),
        lambda case, args: args.update(worker_spiffe_id="spiffe://example.test/worker/wrong"),
        lambda case, args: case.update(region="other-region"),
        lambda case, args: case["request"].update(body_sha256="0" * 64),
        lambda case, args: case["request"].update(canary_id="other-canary"),
    )


@when("its gateway admission is evaluated")
def evaluate_changes(context):
    context["denials"] = []
    for index, change in enumerate(context["changes"]):
        plan, case, args, called = _setup(context["path"] / f"changed-{index}", "openai")
        case, args = deepcopy(case), dict(args)
        change(case, args)
        with pytest.raises(ProviderLiveError, match="dispatch denied"):
            execute_live_case(plan, case, **args)
        context["denials"].append(called)


@then("the case is denied before a provider-shaped response is processed")
def no_changed_dispatch(context):
    assert len(context["denials"]) == 5
    assert all(called == [] for called in context["denials"])


@given("a previously consumed grant or an exhausted shared budget")
def replay_and_exhaustion(context):
    context["replay"] = _setup(context["path"] / "replay", "openai")
    plan, case, args, _ = context["replay"]
    execute_live_case(plan, case, **args)
    context["exhausted"] = _setup(context["path"] / "exhausted", "openai", max_cost=1)


@when("a further live dispatch is attempted")
def attempt_again(context):
    for plan, case, args, _ in (context["replay"], context["exhausted"]):
        with pytest.raises(ProviderLiveError, match="dispatch denied"):
            execute_live_case(plan, case, **args)


@then("the emulator sends no second request")
def no_second_send(context):
    assert context["replay"][3] == ["dispatch-001"]
    assert context["exhausted"][3] == []


@given("a dispatched case with a malformed, partial, cancelled, or disconnected result")
def unknown_cases(context):
    def malformed(_):
        return GatewayDispatchResponse(200, "application/json", b"{")

    def partial(_):
        return GatewayDispatchResponse(200, "application/json", b'{"status":"incomplete"}')

    def disconnected(_):
        raise ConnectionError("fixture disconnect")

    def cancelled(_):
        raise KeyboardInterrupt()

    context["unknown"] = [
        _setup(context["path"] / name, "openai", handler=handler)
        for name, handler in (("malformed", malformed), ("partial", partial),
                              ("disconnected", disconnected), ("cancelled", cancelled))
    ]


@when("the live result is recorded")
def record_unknown(context):
    context["unknown_results"] = []
    for index, (plan, case, args, _) in enumerate(context["unknown"]):
        if index == 3:
            with pytest.raises(KeyboardInterrupt):
                execute_live_case(plan, case, **args)
            context["unknown_results"].append(None)
        else:
            context["unknown_results"].append(execute_live_case(plan, case, **args))


@then("the attempt remains uncertain without automatic retry")
def unknown_is_charged(context):
    assert all(result["ledger_state"] == "uncertain" for result in context["unknown_results"][:3])
    assert all(args["ledger"].snapshot().charged_attempts == 1 for _, _, args, _ in context["unknown"])


@given("an admitted provider response with a tool proposal")
def proposal(context):
    def handler(_):
        return GatewayDispatchResponse(200, "application/json", canonical({
            "status": "completed",
            "output": [{"type": "function_call", "name": "inspect"}],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        }))

    context["proposal"] = _setup(context["path"] / "proposal", "openai", handler=handler,
                                 allowed_tools=("inspect",))


@when("the response is normalized")
def normalize_proposal(context):
    plan, case, args, _ = context["proposal"]
    context["proposal_result"] = execute_live_case(plan, case, **args)


@then("no provider tool is executed")
def proposal_is_inert(context):
    result = context["proposal_result"]
    assert result["outcome"] == "tool_proposal"
    assert result["tool_proposal_count"] == 1
    assert result["ledger_state"] == "uncertain"
