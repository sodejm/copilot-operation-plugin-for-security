from __future__ import annotations

import json
import traceback

import pytest

from cops.web_api.cli import _merge_inventories, _requests_from_inventory
from cops.web_api.importer import import_har, import_openapi, import_postman, import_raw_http
from cops.web_api.models import ApiInventory, AuthenticationMechanism
from cops.web_api.replay import build_replay_action_plan, execute_replay_session


def _har(auth_type: str, secret: str):
    name = "X-API-Key" if auth_type == "api_key" else "Authorization"
    value = secret if auth_type == "api_key" else f"{auth_type.title()} {secret}"
    return import_har(
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.test/items",
                            "headers": [{"name": name, "value": value}],
                        },
                        "response": {"status": 200},
                    }
                ]
            }
        }
    )


def _openapi(auth_type: str, _secret: str):
    if auth_type == "api_key":
        scheme = {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    else:
        scheme = {"type": "http", "scheme": auth_type}
    return import_openapi(
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test"}],
            "components": {"securitySchemes": {"auth": scheme}},
            "paths": {"/items": {"get": {"security": [{"auth": []}]}}},
        }
    )


def _postman(auth_type: str, secret: str):
    postman_type = "apikey" if auth_type == "api_key" else auth_type
    values = (
        [
            {"key": "key", "value": "X-API-Key", "type": "string"},
            {"key": "value", "value": secret, "type": "string"},
            {"key": "in", "value": "header", "type": "string"},
        ]
        if auth_type == "api_key"
        else [{"key": "token", "value": secret, "type": "string"}]
    )
    return import_postman(
        {
            "info": {"name": "session bindings"},
            "item": [
                {
                    "name": "items",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/items",
                        "auth": {"type": postman_type, postman_type: values},
                    },
                }
            ],
        }
    )


def _raw(auth_type: str, secret: str):
    if auth_type == "api_key":
        header = f"X-API-Key: {secret}"
    else:
        header = f"Authorization: {auth_type.title()} {secret}"
    return import_raw_http(f"GET /items HTTP/1.1\r\nHost: api.example.test\r\n{header}\r\n\r\n")


@pytest.mark.parametrize("factory", [_har, _openapi, _postman, _raw])
@pytest.mark.parametrize("auth_type", ["bearer", "basic", "api_key"])
def test_all_import_families_bind_supported_auth_through_round_trip_and_synthesis(factory, auth_type):
    secret = f"fixture-{factory.__name__}-{auth_type}-secret"
    inventory = factory(auth_type, secret)

    assert len(inventory.endpoints) == 1
    assert len(inventory.sessions) == 1
    endpoint = inventory.endpoints[0]
    session = inventory.sessions[0]
    assert endpoint.session_id == session.session_id
    assert endpoint.auth_mechanisms[0].auth_type == auth_type
    assert session.auth_mechanism.credential_hash == endpoint.auth_mechanisms[0].credential_hash

    restored = ApiInventory.from_dict(inventory.to_dict())
    request = _requests_from_inventory(restored)[0]
    assert request.session_id == restored.sessions[0].session_id
    assert request.role_id == restored.sessions[0].role_id
    if auth_type in ("bearer", "basic"):
        assert set(request.headers) == {"Authorization"}
        assert request.headers["Authorization"].startswith(auth_type.title() + " [REDACTED:")
    else:
        assert request.headers["X-API-Key"].startswith("[REDACTED:")

    encoded = json.dumps({"inventory": restored.to_dict(), "request": request.to_dict()})
    assert secret not in encoded


def test_duplicate_and_same_scheme_sources_keep_distinct_graph_bindings_and_offline_replay():
    first = _raw("bearer", "fixture-first-secret")
    second = _raw("bearer", "fixture-second-secret")
    forward = _merge_inventories([first, second, first], "same scheme")
    reverse = _merge_inventories([first, first, second], "same scheme")

    assert forward.inventory_id == reverse.inventory_id
    assert len(forward.provenance_sources) == 3
    assert len(forward.endpoints) == len(forward.sessions) == 3
    assert len({endpoint.endpoint_id for endpoint in forward.endpoints}) == 3
    assert len({session.session_id for session in forward.sessions}) == 3
    session_ids = {session.session_id for session in forward.sessions}
    assert {endpoint.session_id for endpoint in forward.endpoints} == session_ids

    restored = ApiInventory.from_dict(forward.to_dict())
    requests = _requests_from_inventory(restored)
    assert {request.session_id for request in requests} == session_ids
    plan = build_replay_action_plan(
        plan_id="plan-import-bindings",
        engagement_id="eng-import-bindings",
        scenario_id="scen-import-bindings",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        sessions=restored.sessions,
        allowed_destinations=["api.example.test"],
        created_at="2026-10-18T00:00:00Z",
    )
    assert {operation["arguments"]["session_id"] for operation in plan.operations} == session_ids
    report = execute_replay_session(requests, ["api.example.test"])
    assert report.total_dispatched == 3
    assert {request.session_id for request in report.requests} == session_ids
    encoded = json.dumps({"inventory": restored.to_dict(), "plan": plan.to_dict(), "report": report.to_dict()})
    assert "fixture-first-secret" not in encoded
    assert "fixture-second-secret" not in encoded


@pytest.mark.parametrize("boundary", ["serialize", "deserialize", "synthesize"])
def test_invalid_endpoint_session_references_fail_closed_without_disclosure(boundary):
    inventory = _raw("bearer", "fixture-binding-secret")
    unsafe = "missing-session-fixture-secret"
    if boundary == "deserialize":
        document = inventory.to_dict()
        document["endpoints"][0]["session_id"] = unsafe

        def operation():
            return ApiInventory.from_dict(document)

    elif boundary == "synthesize":
        inventory.endpoints[0].session_id = unsafe

        def operation():
            return _requests_from_inventory(inventory)

    else:
        inventory.sessions[0].auth_mechanism = AuthenticationMechanism(
            auth_type="basic", token_name="Authorization", location="header"
        )
        operation = inventory.to_dict

    with pytest.raises(ValueError) as captured:
        operation()
    rendered = "".join(traceback.format_exception(captured.value))
    assert "session binding is invalid" in rendered
    assert unsafe not in rendered
    assert "fixture-binding-secret" not in rendered
