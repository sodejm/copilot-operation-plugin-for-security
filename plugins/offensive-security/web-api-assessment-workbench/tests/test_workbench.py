"""Tests for Web API Assessment Workbench plugin."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cops.web_api.cli import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    _requests_from_inventory,
)
from cops.web_api.importer import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    import_har,
    import_openapi,
    import_postman,
    import_raw_http,
)
from cops.web_api.models import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ApiInventory,
    ReplayBudget,
    ReplayRequest,
    redact_credential_value,
)
from cops.web_api.replay import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    DestinationGuard,
    DestinationViolationError,
    OfflineSyntheticReplayer,
    execute_replay_session,
    preview_replay_session,
)


class TestWebApiWorkbench(unittest.TestCase):
    """Test suite for Web API inventory intake and request replay."""

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_directory.cleanup()

    def temporary_path(self, name: str) -> Path:
        return Path(self.temp_directory.name, name)

    def test_credential_redaction(self) -> None:
        raw_secret = "super-secret-token-12345"
        redacted = redact_credential_value(raw_secret)
        self.assertTrue(redacted.startswith("[REDACTED:"))
        self.assertNotIn(raw_secret, redacted)

        # Idempotent
        self.assertEqual(redact_credential_value(redacted), redacted)

    def test_authentication_metadata_rejects_plaintext_identity(self) -> None:
        inventory = import_raw_http(
            "GET /private HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer fixture-secret\r\n\r\n"
        )
        document = inventory.to_dict()
        marker = "PLAINTEXT-CREDENTIAL-MARKER"
        document["endpoints"][0]["auth_mechanisms"][0]["credential_hash"] = marker
        document["sessions"][0]["auth_mechanism"]["credential_hash"] = marker

        with self.assertRaisesRegex(ValueError, "inventory authentication mechanism is invalid") as caught:
            ApiInventory.from_dict(document)

        self.assertNotIn(marker, str(caught.exception))

    def test_destination_guard(self) -> None:
        guard = DestinationGuard(["api.example.com", "*.corp.internal"])
        self.assertTrue(guard.is_destination_allowed("https://api.example.com/v1/users"))
        self.assertTrue(guard.is_destination_allowed("https://auth.corp.internal/oauth/token"))
        self.assertTrue(guard.is_destination_allowed("wss://stream.corp.internal/ws"))
        self.assertFalse(guard.is_destination_allowed("https://malicious.com/exfil"))
        self.assertFalse(guard.is_destination_allowed("https://example.com/wrong"))

        with self.assertRaises(DestinationViolationError):
            guard.check_destination("https://evil.attacker.org/steal")

    def test_openapi_import(self) -> None:
        spec = {
            "openapi": "3.0.1",
            "info": {"title": "User API", "version": "1.0"},
            "servers": [{"url": "https://api.example.com/api"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True},
                            {"name": "api_key", "in": "header"},
                        ],
                        "responses": {"200": {"description": "OK"}},
                    },
                    "delete": {
                        "summary": "Delete user",
                        "responses": {"204": {"description": "Deleted"}},
                    },
                }
            },
        }
        temp_file = self.temporary_path("test_spec.json")
        temp_file.write_text(json.dumps(spec), encoding="utf-8")
        try:
            inv = import_openapi(temp_file)
            self.assertEqual(len(inv.endpoints), 2)
            self.assertIn("api.example.com", inv.target_hosts)
            self.assertTrue(inv.credentials_redacted)
            get_ep = next(e for e in inv.endpoints if e.method == "GET")
            self.assertEqual(get_ep.path, "/api/users/{id}")
            self.assertEqual(get_ep.auth_mechanisms, [])
            self.assertIn("api_key", get_ep.headers_schema)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_swagger_2_import_preserves_source(self) -> None:
        spec = {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "1.0"},
            "host": "legacy.example",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/items/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True}],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        source = json.dumps(spec, indent=2)
        temp_file = self.temporary_path("test_swagger_2.json")
        temp_file.write_text(source, encoding="utf-8")
        try:
            inv = import_openapi(temp_file)
            self.assertEqual(len(inv.endpoints), 1)
            self.assertEqual(inv.endpoints[0].host, "legacy.example")
            self.assertEqual(inv.endpoints[0].path, "/v1/items/{id}")
            self.assertEqual(temp_file.read_text(encoding="utf-8"), source)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_har_import(self) -> None:
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "Browser", "version": "1.0"},
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://target.app/api/login",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer my-jwt-secret-xyz"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "cookies": [{"name": "session_id", "value": "secret-session-token"}],
                            "queryString": [],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"username": "admin", "password": "supersecretpassword"}',
                            },
                        },
                        "response": {"status": 200},
                    }
                ],
            }
        }
        temp_file = self.temporary_path("test_har.json")
        temp_file.write_text(json.dumps(har), encoding="utf-8")
        try:
            inv = import_har(temp_file)
            self.assertEqual(len(inv.endpoints), 1)
            ep = inv.endpoints[0]
            self.assertEqual(ep.method, "POST")
            self.assertEqual(ep.path, "/api/login")
            self.assertIn("target.app", inv.target_hosts)
            self.assertNotIn("my-jwt-secret-xyz", str(ep.headers_schema))
            self.assertNotIn("supersecretpassword", str(ep.request_body_schema))
            self.assertTrue(len(inv.sessions) > 0)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_har_authorization_variants_bind_distinct_sessions(self) -> None:
        entries = []
        for scheme, credential in (("Bearer", "private-bearer"), ("Basic", "private-basic")):
            entries.append(
                {
                    "request": {
                        "method": "GET",
                        "url": "https://target.app/api/profile",
                        "headers": [{"name": "Authorization", "value": f"{scheme} {credential}"}],
                        "cookies": [],
                        "queryString": [],
                    },
                    "response": {"status": 200},
                }
            )
        inventory = import_har({"log": {"version": "1.2", "entries": entries}})
        requests = _requests_from_inventory(inventory)
        sessions = {session.session_id: session.auth_mechanism.auth_type for session in inventory.sessions}

        self.assertEqual({request.session_id for request in requests}, set(sessions))
        self.assertEqual(
            {
                (request.headers["Authorization"].split()[0].lower(), sessions[request.session_id])
                for request in requests
            },
            {("bearer", "bearer"), ("basic", "basic")},
        )

    def test_postman_import(self) -> None:
        postman = {
            "info": {
                "_postman_id": "test-collection-id",
                "name": "E-Commerce API",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": "Get Orders",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "X-API-Key", "value": "secret-api-key-123"}],
                        "url": {
                            "raw": "https://orders.internal/api/v1/orders?status=active",
                            "host": ["orders", "internal"],
                            "path": ["api", "v1", "orders"],
                            "query": [{"key": "status", "value": "active"}],
                        },
                    },
                }
            ],
        }
        temp_file = self.temporary_path("test_postman.json")
        temp_file.write_text(json.dumps(postman), encoding="utf-8")
        try:
            inv = import_postman(temp_file)
            self.assertEqual(len(inv.endpoints), 1)
            ep = inv.endpoints[0]
            self.assertEqual(ep.method, "GET")
            self.assertEqual(ep.path, "/api/v1/orders")
            self.assertIn("orders.internal", inv.target_hosts)
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_raw_http_import(self) -> None:
        raw_http = (
            "POST /api/v2/items HTTP/1.1\r\n"
            "Host: service.local\r\n"
            "Authorization: Bearer secret-auth-token\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"item_name": "Widget"}'
        )
        temp_file = self.temporary_path("test_raw.http")
        temp_file.write_text(raw_http, encoding="utf-8")
        try:
            inv = import_raw_http(temp_file)
            self.assertEqual(len(inv.endpoints), 1)
            ep = inv.endpoints[0]
            self.assertEqual(ep.method, "POST")
            self.assertEqual(ep.path, "/api/v2/items")
            self.assertEqual(ep.host, "service.local")
            self.assertTrue(ep.auth_mechanisms[0].is_redacted)
            self.assertNotIn("secret-auth-token", ep.headers_schema.get("Authorization", ""))
        finally:
            if temp_file.exists():
                temp_file.unlink()

    def test_bounded_replay_with_guard_and_budget(self) -> None:
        requests = [
            ReplayRequest(
                request_id="req-1",
                endpoint_id="GET-/api/status",
                method="GET",
                url="https://allowed.host/api/status",
            ),
            ReplayRequest(
                request_id="req-2",
                endpoint_id="POST-/api/data",
                method="POST",
                url="https://evil.exfil.org/api/data",
            ),
        ]
        budget = ReplayBudget(max_requests=5, rate_limit_rps=50.0)
        replayer = OfflineSyntheticReplayer(mock_routes={"GET /api/status": {"status": 200, "body": '{"ok": true}'}})

        report = execute_replay_session(
            requests=requests,
            allowed_destinations=["allowed.host"],
            budget=budget,
            replayer=replayer,
        )

        self.assertEqual(report.total_dispatched, 2)
        self.assertEqual(report.total_successful, 1)
        self.assertEqual(report.total_failed, 1)
        self.assertEqual(report.destination_violations, 1)
        self.assertEqual(report.responses[0].status_code, 200)
        self.assertEqual(report.responses[1].status_code, 403)
        self.assertIn("rejected by destination allowlist", report.responses[1].error_message or "")

    def test_preview_and_offline_replay_do_not_mutate_request(self) -> None:
        request = ReplayRequest(
            request_id="req-immutable",
            endpoint_id="POST-/api/data",
            method="POST",
            url="https://allowed.host/api/data",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"message": "unchanged"}),
        )
        before = request.to_dict()

        preview_replay_session(
            requests=[request],
            allowed_destinations=["allowed.host"],
            budget=ReplayBudget(max_requests=1),
        )
        execute_replay_session(
            requests=[request],
            allowed_destinations=["allowed.host"],
            budget=ReplayBudget(max_requests=1),
            replayer=OfflineSyntheticReplayer(),
        )

        self.assertEqual(request.to_dict(), before)

    def test_redirect_bounds_and_graphql(self) -> None:
        mock_routes = {
            "GET /redirect": {
                "redirect_to": "https://allowed.host/final",
                "redirect_hops": 5,  # exceeds budget max of 3
            }
        }
        replayer = OfflineSyntheticReplayer(mock_routes=mock_routes)
        req_redirect = ReplayRequest(
            request_id="req-redir",
            endpoint_id="GET-/redirect",
            method="GET",
            url="https://allowed.host/redirect",
        )
        budget = ReplayBudget(max_redirect_hops=3)
        resp = replayer.send(req_redirect, budget)
        self.assertFalse(resp.replay_success)
        self.assertIn("Maximum redirect hops exceeded", resp.error_message or "")

        # Test GraphQL Introspection
        req_gql = ReplayRequest(
            request_id="req-gql",
            endpoint_id="POST-/graphql",
            method="POST",
            url="https://allowed.host/graphql",
            protocol="graphql",
            graphql_query="query IntrospectionQuery { __schema { types { name } } }",
        )
        resp_gql = replayer.send(req_gql, budget)
        self.assertTrue(resp_gql.replay_success)
        self.assertIn("__schema", resp_gql.body_excerpt)


if __name__ == "__main__":
    unittest.main()
