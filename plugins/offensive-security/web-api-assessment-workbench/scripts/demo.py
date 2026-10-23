#!/usr/bin/env python3
"""Deterministic offline demonstration for Web API Assessment Workbench."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Use the packaged runtime after portable export, or the repository runtime.
REPO_ROOT = Path(__file__).resolve().parents[4]
VENDORED_ROOT = Path(__file__).resolve().parents[1] / "vendor"
sys.path.insert(0, str(VENDORED_ROOT if (VENDORED_ROOT / "cops").is_dir() else REPO_ROOT))

from cops.web_api.importer import import_openapi  # noqa: E402  # Import after runtime prerequisite/path selection.
from cops.web_api.models import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    ReplayBudget,
    ReplayRequest,
)
from cops.web_api.replay import (  # noqa: E402  # Import after runtime prerequisite/path selection.
    OfflineSyntheticReplayer,
    execute_replay_session,
)


def run_demo() -> dict[str, str | int | bool | dict]:
    """Execute offline demonstration of API inventory intake and bounded request replay."""
    # Synthetic OpenAPI Spec
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Secure Vault API", "version": "1.2.0"},
        "servers": [{"url": "https://api.vault.internal/v1"}],
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "User authentication",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Auth success"}},
                }
            },
            "/secrets": {
                "get": {
                    "summary": "List secret metadata",
                    "parameters": [
                        {
                            "name": "api_key",
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "List secrets"}},
                }
            },
            "/graphql": {
                "post": {
                    "summary": "GraphQL query endpoint",
                    "responses": {"200": {"description": "GraphQL result"}},
                }
            },
            "/stream/events": {
                "get": {
                    "summary": "WebSocket telemetry stream",
                    "responses": {"101": {"description": "Switching protocols"}},
                }
            },
        },
    }

    with tempfile.TemporaryDirectory(prefix="cops-api-demo-") as temporary:
        temp_spec = Path(temporary) / "openapi.json"
        temp_spec.write_text(json.dumps(openapi_spec), encoding="utf-8")
        inventory = import_openapi(temp_spec, source_id="DEMO-SRC-01")

    # Verify inventory properties
    assert inventory.credentials_redacted is True
    assert len(inventory.endpoints) == 4

    # Prepare bounded replay
    requests = [
        ReplayRequest(
            request_id="req-001",
            endpoint_id="POST-/auth/login",
            method="POST",
            url="https://api.vault.internal/v1/auth/login",
            body='{"username": "admin", "password": "[REDACTED:demo_pwd]"}',
        ),
        ReplayRequest(
            request_id="req-002",
            endpoint_id="GET-/secrets",
            method="GET",
            url="https://api.vault.internal/v1/secrets",
            query_parameters={"api_key": "[REDACTED:demo_key]"},
        ),
        ReplayRequest(
            request_id="req-003",
            endpoint_id="POST-/graphql",
            method="POST",
            url="https://api.vault.internal/v1/graphql",
            graphql_query="query IntrospectionQuery { __schema { types { name } } }",
            protocol="graphql",
        ),
        ReplayRequest(
            request_id="req-004",
            endpoint_id="GET-/stream/events",
            method="GET",
            url="wss://api.vault.internal/v1/stream/events",
            protocol="websocket",
            websocket_messages=["ping"],
        ),
    ]

    budget = ReplayBudget(max_requests=10, rate_limit_rps=20.0, timeout_seconds=2.0)
    mock_routes = {
        "POST /v1/auth/login": {"status": 200, "body": '{"token": "[REDACTED:token_hash]"}'},
        "GET /v1/secrets": {"status": 200, "body": '{"secrets": ["vault-1", "vault-2"]}'},
    }
    replayer = OfflineSyntheticReplayer(mock_routes=mock_routes)

    report = execute_replay_session(
        requests=requests,
        allowed_destinations=["api.vault.internal"],
        budget=budget,
        replayer=replayer,
    )

    demo_output = {
        "status": "passed",
        "mode": "offline",
        "network_requests": 0,
        "inventory": {
            "name": inventory.name,
            "target_hosts": inventory.target_hosts,
            "endpoints_count": len(inventory.endpoints),
            "credentials_redacted": inventory.credentials_redacted,
        },
        "replay_summary": {
            "session_id": report.session_id,
            "total_dispatched": report.total_dispatched,
            "total_successful": report.total_successful,
            "total_failed": report.total_failed,
            "destination_violations": report.destination_violations,
        },
    }
    return demo_output


def main() -> int:
    output = run_demo()
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
