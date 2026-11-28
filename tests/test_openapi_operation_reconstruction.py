"""Regression evidence for operation-level OpenAPI reconstruction."""

from __future__ import annotations

import copy
import json

import pytest

from cops.web_api.importer import ImporterError, import_openapi


def _endpoint(inventory, suffix: str):
    return next(endpoint for endpoint in inventory.endpoints if endpoint.path.endswith(suffix))


def _oas_document() -> dict:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Reconstruction fixture", "version": "1"},
        "servers": [
            {"url": "https://root.example.test/root/v1/"},
            {"url": "https://unused.example.test/other"},
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "basicAuth": {"type": "http", "scheme": "basic"},
                "headerKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "unusedKey": {"type": "apiKey", "in": "query", "name": "unused-secret"},
            }
        },
        "security": [{"bearerAuth": []}],
        "paths": {
            "/inherited": {"get": {}},
            "/public": {
                "get": {
                    "security": [],
                    "parameters": [{"name": "password", "in": "query"}],
                }
            },
            "/basic": {"get": {"security": [{"basicAuth": []}]}},
            "/and": {"get": {"security": [{"bearerAuth": [], "headerKey": []}]}},
            "/or": {"get": {"security": [{"basicAuth": []}, {"headerKey": []}]}},
            "/anonymous": {"get": {"security": [{"bearerAuth": []}, {}]}},
        },
    }


def test_openapi_effective_security_preserves_overrides_and_alternatives():
    document = _oas_document()
    original = copy.deepcopy(document)

    inventory = import_openapi(document, source_id="fixture")

    assert document == original
    assert [auth.auth_type for auth in _endpoint(inventory, "/inherited").auth_mechanisms] == ["bearer"]
    assert _endpoint(inventory, "/inherited").auth_mechanisms[0].token_name == "Authorization"
    assert _endpoint(inventory, "/public").auth_mechanisms == []
    assert _endpoint(inventory, "/public").query_parameters["password"].startswith("[REDACTED:")
    assert [auth.auth_type for auth in _endpoint(inventory, "/basic").auth_mechanisms] == ["basic"]
    assert [auth.token_name for auth in _endpoint(inventory, "/and").auth_mechanisms] == [
        "Authorization",
        "X-API-Key",
    ]
    assert [auth.auth_type for auth in _endpoint(inventory, "/or").auth_mechanisms] == ["basic"]
    assert _endpoint(inventory, "/anonymous").auth_mechanisms == []
    assert any(feature.feature_name == "security_alternatives" for feature in inventory.unsupported_features)
    assert {session.auth_mechanism.token_name for session in inventory.sessions} == {
        "Authorization",
        "X-API-Key",
    }
    assert "unused-secret" not in json.dumps(inventory.to_dict())


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
def test_query_auth_names_are_case_sensitive_in_and_requirements(dialect):
    schemes = {
        "lower": {"type": "apiKey", "in": "query", "name": "api_key"},
        "upper": {"type": "apiKey", "in": "query", "name": "API_KEY"},
    }
    if dialect == "openapi":
        document = {
            "openapi": "3.0.3",
            "components": {"securitySchemes": schemes},
            "paths": {"/items": {"get": {"security": [{"lower": [], "upper": []}]}}},
        }
    else:
        document = {
            "swagger": "2.0",
            "securityDefinitions": schemes,
            "paths": {"/items": {"get": {"security": [{"lower": [], "upper": []}]}}},
        }

    mechanisms = import_openapi(document).endpoints[0].auth_mechanisms
    assert [(mechanism.location, mechanism.token_name) for mechanism in mechanisms] == [
        ("query", "api_key"),
        ("query", "API_KEY"),
    ]


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
def test_header_auth_names_collide_case_insensitively(dialect):
    schemes = {
        "first": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        "second": {"type": "apiKey", "in": "header", "name": "x-api-key"},
    }
    if dialect == "openapi":
        document = {
            "openapi": "3.0.3",
            "components": {"securitySchemes": schemes},
            "paths": {"/": {"get": {"security": [{"first": [], "second": []}]}}},
        }
    else:
        document = {
            "swagger": "2.0",
            "securityDefinitions": schemes,
            "paths": {"/": {"get": {"security": [{"first": [], "second": []}]}}},
        }
    with pytest.raises(ImporterError, match="cannot be represented safely"):
        import_openapi(document)


@pytest.mark.parametrize(
    "security,schemes",
    [
        ([{"missing": []}], {}),
        ([{"broken": []}], {"broken": {"type": "http", "scheme": "digest"}}),
        ("private-security-value", {}),
    ],
)
def test_unknown_or_malformed_security_fails_closed_without_echo(security, schemes):
    document = {
        "openapi": "3.0.3",
        "components": {"securitySchemes": schemes},
        "paths": {"/": {"get": {"security": security}}},
    }
    with pytest.raises(ImporterError) as caught:
        import_openapi(document)
    assert "missing" not in str(caught.value)
    assert "broken" not in str(caught.value)
    assert "private-security-value" not in str(caught.value)


def test_unused_malformed_declaration_does_not_affect_public_operation():
    inventory = import_openapi(
        {
            "openapi": "3.0.3",
            "components": {"securitySchemes": {"unused": {"type": "private-malformed-value"}}},
            "paths": {"/public": {"get": {"security": []}}},
        }
    )
    assert inventory.endpoints[0].auth_mechanisms == []
    assert inventory.sessions == []
    assert "private-malformed-value" not in json.dumps(inventory.to_dict())


def test_openapi_server_precedence_prefixes_and_deterministic_selection():
    document = _oas_document()
    document["paths"] = {
        "/items": {
            "servers": [{"url": "https://path.example.test/path/v2/"}],
            "get": {"servers": [{"url": "https://op.example.test/op/v3"}]},
            "post": {},
        },
        "/root-item": {"get": {}},
        "/variable": {
            "get": {
                "servers": [
                    {
                        "url": "https://{tenant}.example.test/{version}/",
                        "variables": {"tenant": {"default": "blue"}, "version": {"default": "v4"}},
                    }
                ]
            }
        },
    }
    inventory = import_openapi(document)
    observed = {(endpoint.method, endpoint.host, endpoint.path) for endpoint in inventory.endpoints}
    assert observed == {
        ("GET", "op.example.test", "/op/v3/items"),
        ("POST", "path.example.test", "/path/v2/items"),
        ("GET", "root.example.test", "/root/v1/root-item"),
        ("GET", "blue.example.test", "/v4/variable"),
    }
    assert (
        len([feature for feature in inventory.unsupported_features if feature.feature_name == "server_alternatives"])
        == 1
    )


def test_swagger_security_and_base_path_reconstruction():
    inventory = import_openapi(
        {
            "swagger": "2.0",
            "host": "api.example.test:8443",
            "schemes": ["https", "http"],
            "basePath": "/service/v1/",
            "securityDefinitions": {
                "basicAuth": {"type": "basic"},
                "queryKey": {"type": "apiKey", "in": "query", "name": "api_key"},
                "unused": {"type": "apiKey", "in": "header", "name": "X-Unused"},
            },
            "security": [{"basicAuth": []}],
            "paths": {
                "/private": {"get": {}},
                "/public": {"get": {"security": []}},
                "/key": {"get": {"security": [{"queryKey": []}]}},
            },
        }
    )
    by_path = {endpoint.path: endpoint for endpoint in inventory.endpoints}
    assert by_path["/service/v1/private"].auth_mechanisms[0].token_name == "Authorization"
    assert by_path["/service/v1/public"].auth_mechanisms == []
    assert by_path["/service/v1/key"].auth_mechanisms[0].token_name == "api_key"
    assert "X-Unused" not in json.dumps(inventory.to_dict())


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
def test_prefixed_root_operation_preserves_terminal_slash(dialect):
    if dialect == "openapi":
        document = {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test/service/v1/"}],
            "paths": {"/": {"get": {}}},
        }
    else:
        document = {
            "swagger": "2.0",
            "host": "api.example.test",
            "basePath": "/service/v1/",
            "paths": {"/": {"get": {}}},
        }
    endpoint = import_openapi(document).endpoints[0]
    assert (endpoint.host, endpoint.path) == ("api.example.test", "/service/v1/")


@pytest.mark.parametrize(
    "server",
    [
        {"url": "/relative"},
        {"url": "https://{tenant}.example.test/v1"},
        {"url": "http://api.example.test/v1"},
        {"url": "https://api.example.test/v1?private=value"},
    ],
)
def test_openapi_unrepresentable_server_fails_closed(server):
    with pytest.raises(ImporterError):
        import_openapi({"openapi": "3.0.3", "servers": [server], "paths": {"/": {"get": {}}}})


def test_endpoint_id_is_stable_when_effective_location_is_unchanged():
    first = import_openapi(
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test/prefix"}],
            "paths": {"/items": {"get": {"summary": "first"}}},
        }
    )
    second = import_openapi(
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test/prefix/"}],
            "paths": {"/items": {"get": {"summary": "second"}}},
        }
    )
    assert first.endpoints[0].endpoint_id == second.endpoints[0].endpoint_id
