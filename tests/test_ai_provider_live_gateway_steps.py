"""Executable acceptance scenarios for provider contracts and the local emulator."""

import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from pytest_bdd import given, scenarios, then, when
from test_provider_live_execution import _setup
from test_provider_live_schemas import (
    CASES_SCHEMA,
    CASES_VALIDATOR,
    PLAN_SCHEMA,
    PLAN_VALIDATOR,
    V3_SCOPE,
    _cases,
    _plan,
    _v3_documents,
)

from cops.assessment_budget import AttemptRequest
from cops.evidence.canonical import canonical
from cops.execution.gateway_dispatch import GatewayDispatchResponse
from cops.provider_live import ProviderLiveError, _policy, execute_live_case

scenarios("../specs/features/ai_provider_live_gateway.feature")


@pytest.fixture
def context(tmp_path):
    return {"path": tmp_path}


@given("bounded v3 production plan and cases")
def v3_contracts(context):
    context["contract_documents"] = _v3_documents()


@when("the production contract shape is validated")
def validate_v3_contracts(context):
    for validator, document in zip((PLAN_VALIDATOR, CASES_VALIDATOR), context["contract_documents"], strict=True):
        validator.validate(document)


@then("scoped auth identities, transport, digests, and budgets are mandatory")
def required_v3_scope(context):
    for validator, document, collection in zip(
        (PLAN_VALIDATOR, CASES_VALIDATOR), context["contract_documents"], ("environments", "cases"), strict=True
    ):
        for field in V3_SCOPE:
            invalid = deepcopy(document)
            del invalid[collection][0][field]
            with pytest.raises(ValidationError):
                validator.validate(invalid)
        for field in ("max_output_tokens", "max_response_bytes", "max_elapsed_ms"):
            invalid = deepcopy(document)
            scope = invalid[collection][0]
            grant = (
                scope["approved_requests"][0]["dispatch_grant"]
                if collection == "environments"
                else scope["dispatch_grant"]
            )
            del grant[field]
            with pytest.raises(ValidationError):
                validator.validate(invalid)


@then("unknown v3 contract fields are rejected")
def reject_unknown_v3_fields(context):
    for validator, document in zip((PLAN_VALIDATOR, CASES_VALIDATOR), context["contract_documents"], strict=True):
        invalid = deepcopy(document)
        invalid["unapproved_auth_override"] = "opaque-override"
        with pytest.raises(ValidationError):
            validator.validate(invalid)


@given("historical v2 emulator plan and cases")
def historical_contracts(context):
    context["contract_documents"] = (_plan(), _cases())


@when("their historical schemas are validated")
def validate_historical_contracts(context):
    validate_v3_contracts(context)
    context["historical_readable"] = True


@then("the documents remain readable")
def historical_readable(context):
    assert context["historical_readable"] is True


@then("they cannot satisfy the v3 production contract")
def historical_not_production(context):
    for schema, document in zip((PLAN_SCHEMA, CASES_SCHEMA), context["contract_documents"], strict=True):
        production_schema = deepcopy(schema)
        production_schema["properties"]["schema_version"] = {"const": document["schema_version"].replace("/v2", "/v3")}
        with pytest.raises(ValidationError):
            Draft202012Validator(production_schema).validate(document)


@when("a provider target contains a normalization alias")
def aliased_v3_targets(context):
    context["aliased_targets"] = (
        "https://api.openai.com/v1/%72esponses",
        "https://api.openai.com/v1/../responses",
        "https://api.openai.com/v1/responses?api-version=preview",
    )


@then("the v3 contract rejects the target")
def reject_aliased_v3_targets(context):
    for validator, document, collection in zip(
        (PLAN_VALIDATOR, CASES_VALIDATOR), context["contract_documents"], ("environments", "cases"), strict=True
    ):
        for target in context["aliased_targets"]:
            invalid = deepcopy(document)
            invalid[collection][0]["request_target"] = target
            with pytest.raises(ValidationError):
                validator.validate(invalid)


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
    assert all(
        result["outcome"] == "completed" and result["ledger_state"] == "uncertain" for result in context["results"]
    )
    assert all(called == ["dispatch-001"] for _, _, _, called in context["cases"])


@then("no prompt, endpoint, account, or provider output appears in public evidence")
def redacted_results(context):
    for (_, case, _, _), result in zip(context["cases"], context["results"], strict=True):
        public = json.dumps(result)
        for private in (
            "COPS_CANARY_001",
            "PRIVATE_CANARY_RESPONSE",
            case["request_target"],
            case["account_or_project"],
        ):
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
        for name, handler in (
            ("malformed", malformed),
            ("partial", partial),
            ("disconnected", disconnected),
            ("cancelled", cancelled),
        )
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
        return GatewayDispatchResponse(
            200,
            "application/json",
            canonical(
                {
                    "status": "completed",
                    "output": [{"type": "function_call", "name": "inspect"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                }
            ),
        )

    context["proposal"] = _setup(context["path"] / "proposal", "openai", handler=handler, allowed_tools=("inspect",))


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


@given("a local tool has reserved allowance under an agent parent")
def local_tool_under_parent(context):
    overrides = {"max_attempts": 5, "max_concurrency": 4, "max_children_per_parent": 3}
    context["parent_cases"] = []
    for provider in ("openai", "azure", "aws", "gcp"):
        path = context["path"] / f"shared-{provider}"
        plan, case, args, called = _setup(path, provider, max_cost=5000, limit_overrides=overrides)
        narrow = replace(_policy(plan).limits, max_estimated_cost_microunits=1500)
        args["ledger"].reserve(AttemptRequest("agent-root", None, 0, 0, 0), child_limits=narrow)
        args["ledger"].reserve(AttemptRequest("local-tool", "agent-root", 10, 400, 100))
        context["parent_cases"].append((path, provider, plan, case, args, called, narrow))


@when("approved provider canaries dispatch under that parent")
def dispatch_under_parent(context):
    context["parent_results"] = [
        execute_live_case(plan, case, parent_attempt_id="agent-root", child_limits=narrow, **args)
        for _, _, plan, case, args, _, narrow in context["parent_cases"]
    ]


@then("each provider dispatch consumes the remaining subtree allowance")
def shared_allowance_charged(context):
    assert all(result["ledger_state"] == "uncertain" for result in context["parent_results"])
    for _, _, _, _, args, called, _ in context["parent_cases"]:
        assert called == ["dispatch-001"]
        assert args["ledger"].snapshot().charged_cost_microunits == 1400


@then("a further provider dispatch is denied before gateway send")
def no_subtree_retry(context):
    overrides = {"max_attempts": 5, "max_concurrency": 4, "max_children_per_parent": 3}
    for path, provider, _, _, _, _, _ in context["parent_cases"]:
        plan, case, args, called = _setup(
            path, provider, max_cost=5000, limit_overrides=overrides, dispatch_id="dispatch-002"
        )
        with pytest.raises(ProviderLiveError, match="dispatch denied"):
            execute_live_case(plan, case, parent_attempt_id="agent-root", **args)
        assert called == []


@given("a live provider case with a narrower agent parent budget")
def narrow_agent_parent(context):
    context["narrow_case"] = _setup(context["path"] / "narrow", "openai")
    plan, _, args, _ = context["narrow_case"]
    narrow = replace(_policy(plan).limits, max_estimated_cost_microunits=1500)
    args["ledger"].reserve(AttemptRequest("agent-root", None, 0, 0, 0), child_limits=narrow)


@when("its provider child requests wider limits")
def request_wider_provider_child(context):
    plan, case, args, _ = context["narrow_case"]
    with pytest.raises(ProviderLiveError, match="dispatch denied"):
        execute_live_case(plan, case, parent_attempt_id="agent-root", child_limits=_policy(plan).limits, **args)


@then("the widened provider child is denied before gateway send")
def widened_provider_was_not_sent(context):
    _, _, args, called = context["narrow_case"]
    assert called == []
    assert args["ledger"].snapshot().charged_attempts == 1


@given("two approved provider cases with one shared concurrency slot")
def concurrent_provider_cases(context):
    path = context["path"] / "concurrent"
    context["concurrent_cases"] = [
        _setup(path, provider, dispatch_id=dispatch_id)
        for provider, dispatch_id in (("openai", "dispatch-001"), ("azure", "dispatch-002"))
    ]


@when("both provider dispatches start concurrently")
def dispatch_concurrently(context):
    def invoke(config):
        plan, case, args, called = config
        try:
            execute_live_case(plan, case, **args)
        except ProviderLiveError:
            return "denied", called
        return "dispatched", called

    with ThreadPoolExecutor(max_workers=2) as pool:
        context["concurrent_results"] = list(pool.map(invoke, context["concurrent_cases"]))


@then("only one provider request reaches its gateway emulator")
def one_concurrent_provider_send(context):
    assert sorted(outcome for outcome, _ in context["concurrent_results"]) == ["denied", "dispatched"]
    assert sum(len(called) for _, called in context["concurrent_results"]) == 1
    assert context["concurrent_cases"][0][2]["ledger"].snapshot().charged_attempts == 1
