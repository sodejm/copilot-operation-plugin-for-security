from __future__ import annotations

import argparse
import json

import pytest

from cops.web_api import models
from cops.web_api.cli import _merge_inventories, _requests_from_inventory, build_web_api_parser, command_web_api
from cops.web_api.importer import import_har, import_openapi
from cops.web_api.models import ApiInventory, AuthenticationMechanism, HttpEndpoint


def _parse_args(*items: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    build_web_api_parser(parser)
    return parser.parse_args(list(items))


def _inventory_file(tmp_path):
    path = tmp_path / "inventory.json"
    ApiInventory(
        inventory_id="inv-preview",
        name="Preview fixture",
        target_hosts=["api.example.test"],
        endpoints=[
            HttpEndpoint(
                endpoint_id="ep-account",
                method="GET",
                host="api.example.test",
                path="/accounts/42",
                query_parameters={"view": "summary"},
            )
        ],
        imported_sources=["fixture-openapi.json"],
        credentials_redacted=True,
    ).save(path)
    return path


def test_authenticated_request_requires_unique_matching_session():
    inventory = ApiInventory(
        inventory_id="inv-missing-session",
        name="Missing session fixture",
        endpoints=[
            HttpEndpoint(
                endpoint_id="ep-private",
                method="GET",
                path="/private",
                auth_mechanisms=[
                    AuthenticationMechanism(auth_type="bearer", token_name="Authorization", location="header")
                ],
            )
        ],
    )

    with pytest.raises(ValueError, match="inventory authentication session binding is invalid"):
        _requests_from_inventory(inventory)


def test_live_dry_run_returns_json_preview_without_dispatch_or_file_write(tmp_path, capsys, monkeypatch):
    inventory_path = _inventory_file(tmp_path)
    output_path = tmp_path / "must-not-be-written.json"

    def reject_dispatch(*args, **kwargs):
        raise AssertionError("preview dispatched replay requests")

    monkeypatch.setattr("cops.web_api.cli.execute_replay_session", reject_dispatch)

    args = _parse_args(
        "replay",
        "--inventory",
        str(inventory_path),
        "--mode",
        "live",
        "--allow-destination",
        "api.example.test,backup.example.test",
        "--max-requests",
        "7",
        "--rate-limit",
        "2.5",
        "--timeout",
        "4",
        "--max-redirects",
        "1",
        "--max-frames",
        "3",
        "--dry-run",
        "--json",
        "--output",
        str(output_path),
    )

    assert command_web_api(args) == 0
    captured = capsys.readouterr()
    preview = json.loads(captured.out)

    assert captured.err == ""
    assert preview["schema_version"] == "cops.web-api-replay-preview/v1"
    assert preview["requested_mode"] == "live"
    assert preview["destinations"] == {
        "allowed": ["api.example.test", "backup.example.test"],
        "target_hosts": ["api.example.test"],
        "request_urls": ["https://api.example.test/accounts/42"],
    }
    assert preview["budget"] == {
        "max_requests": 7,
        "rate_limit_rps": 2.5,
        "timeout_seconds": 4.0,
        "max_redirect_hops": 1,
        "max_websocket_frames": 3,
    }
    assert preview["evidence"]["inventory_id"] == "inv-preview"
    assert preview["evidence"]["inventory_name"] == "Preview fixture"
    assert preview["evidence"]["imported_sources"] == ["fixture-openapi.json"]
    assert preview["evidence"]["prepared_request_count"] == 1
    assert preview["evidence"]["requests"][0]["request_id"] == "req-001"
    assert preview["effects"] == {
        "network_requests": 0,
        "workers_started": 0,
        "authorizations_consumed": 0,
        "authentication_sessions_used": 0,
        "files_written": 0,
        "state_changes": [],
    }
    assert preview["unknowns_and_noise"]
    assert not output_path.exists()


def test_explain_renders_text_preview_and_live_without_preview_still_rejects(
    tmp_path, capsys, monkeypatch
):
    inventory_path = _inventory_file(tmp_path)

    def reject_dispatch(*args, **kwargs):
        raise AssertionError("explain dispatched replay requests")

    monkeypatch.setattr("cops.web_api.cli.execute_replay_session", reject_dispatch)

    explain_args = _parse_args(
        "replay",
        "--inventory",
        str(inventory_path),
        "--mode",
        "live",
        "--explain",
        "--max-requests",
        "9",
    )
    assert command_web_api(explain_args) == 0
    explained = capsys.readouterr()

    assert explained.err == ""
    assert "=== Web API Replay Preview ===" in explained.out
    assert "Requested Mode: live" in explained.out
    assert "Allowed: api.example.test" in explained.out
    assert "Request URL: https://api.example.test/accounts/42" in explained.out
    assert "max_requests: 9" in explained.out
    assert "Prepared requests: 1" in explained.out
    assert "Network requests: 0" in explained.out
    assert "State changes: none" in explained.out
    assert "Unknowns / Noise:" in explained.out

    live_args = _parse_args(
        "replay",
        "--inventory",
        str(inventory_path),
        "--mode",
        "live",
    )
    assert command_web_api(live_args) == 2
    rejected = capsys.readouterr()
    assert "live replay requires the approved Python entry point" in rejected.err


def test_imported_auth_and_server_paths_survive_cli_preview(tmp_path, capsys):
    inventory = import_openapi(
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test/service/v1"}],
            "components": {
                "securitySchemes": {
                    "bearer": {"type": "http", "scheme": "bearer"},
                    "lower": {"type": "apiKey", "in": "query", "name": "api_key"},
                    "upper": {"type": "apiKey", "in": "query", "name": "API_KEY"},
                }
            },
            "security": [{"bearer": []}],
            "paths": {
                "/public": {"get": {"security": []}},
                "/private": {"get": {}},
                "/keys": {"get": {"security": [{"lower": [], "upper": []}]}},
            },
        }
    )
    inventory_path = tmp_path / "openapi-inventory.json"
    inventory.save(inventory_path)

    args = _parse_args("replay", "--inventory", str(inventory_path), "--dry-run", "--json")
    assert command_web_api(args) == 0
    preview = json.loads(capsys.readouterr().out)
    requests = {request["url"]: request for request in preview["evidence"]["requests"]}

    public = requests["https://api.example.test/service/v1/public"]
    private = requests["https://api.example.test/service/v1/private"]
    keys = requests["https://api.example.test/service/v1/keys"]
    assert public["headers"] == {}
    assert public["query_parameters"] == {}
    assert list(private["headers"]) == ["Authorization"]
    assert private["headers"]["Authorization"].startswith("Bearer [REDACTED:")
    assert set(keys["query_parameters"]) == {"api_key", "API_KEY"}
    assert keys["headers"] == {}
    assert "fixture-secret" not in json.dumps(preview)

    raw_requests = {request.url: request for request in _requests_from_inventory(inventory)}
    assert (
        raw_requests["https://api.example.test/service/v1/private"]
        .headers["Authorization"]
        .startswith("Bearer [REDACTED:")
    )


def test_repeated_cli_sources_preserve_provenance_and_content_identity(tmp_path, capsys):
    documents = [
        {
            "openapi": "3.0.3",
            "info": {"title": title},
            "servers": [{"url": "https://api.example.test"}],
            "paths": {path: {"get": {}}},
        }
        for title, path in (("First", "/first"), ("Second", "/second"))
    ]
    paths = []
    for index, document in enumerate(documents):
        path = tmp_path / f"private-source-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        paths.append(path)

    def import_in_order(order):
        args = _parse_args(
            "inventory",
            *(item for index in order for item in ("--openapi", str(paths[index]))),
            "--source-id",
            "opaque-source",
            "--json",
        )
        assert command_web_api(args) == 0
        return json.loads(capsys.readouterr().out)

    forward = import_in_order((0, 1))
    reverse = import_in_order((1, 0))

    assert forward["inventory_id"] == reverse["inventory_id"]
    assert forward["provenance"] is None
    assert len(forward["provenance_sources"]) == 2
    assert {source["source_id"] for source in forward["provenance_sources"]} == {"opaque-source"}
    assert len({source["sha256"] for source in forward["provenance_sources"]}) == 2
    assert all(source["source_type"] == "openapi_import" for source in forward["provenance_sources"])
    assert ApiInventory.from_dict(forward).to_dict() == forward
    assert str(tmp_path) not in json.dumps(forward)


def test_merged_identity_uses_source_content_ignores_timestamps_and_keeps_duplicates():
    first = import_openapi({"openapi": "3.0.3", "paths": {"/same-count-a": {"get": {}}}}, source_id="a")
    second = import_openapi({"openapi": "3.0.3", "paths": {"/same-count-b": {"get": {}}}}, source_id="b")
    anchor = import_openapi({"openapi": "3.0.3", "paths": {}}, source_id="anchor")
    first.provenance.timestamp = "2026-01-01T00:00:00Z"
    second.provenance.timestamp = "2030-01-01T00:00:00Z"

    merged = _merge_inventories([first, second], "merged")
    reordered = _merge_inventories([second, first], "merged")
    duplicate = _merge_inventories([first, first], "duplicates")

    assert merged.inventory_id == reordered.inventory_id
    assert (
        _merge_inventories([first, anchor], "one").inventory_id
        != _merge_inventories([second, anchor], "two").inventory_id
    )
    assert len(duplicate.provenance_sources) == 2
    assert duplicate.provenance_sources[0].sha256 == duplicate.provenance_sources[1].sha256


def test_har_bearer_and_basic_survive_merge_sessions_and_preview_without_secrets(tmp_path, capsys):
    def one_header(value):
        return import_har(
            {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": "https://api.example.test/shared",
                                "method": "GET",
                                "headers": [{"name": "Authorization", "value": value}],
                            }
                        }
                    ]
                }
            }
        )

    inventory = _merge_inventories(
        [one_header("Bearer fixture-bearer-secret"), one_header("Basic Zml4dHVyZTpzZWNyZXQ=")],
        "merged auth",
    )
    assert {endpoint.auth_mechanisms[0].token_name for endpoint in inventory.endpoints} == {"Authorization"}
    assert {endpoint.auth_mechanisms[0].auth_type for endpoint in inventory.endpoints} == {"bearer", "basic"}
    assert {session.auth_mechanism.auth_type for session in inventory.sessions} == {"bearer", "basic"}
    assert len({session.session_id for session in inventory.sessions}) == 2

    raw_requests = _requests_from_inventory(inventory)
    assert len({request.endpoint_id for request in raw_requests}) == 2
    assert {next(iter(request.headers)) for request in raw_requests} == {"Authorization"}
    assert {request.headers["Authorization"].split()[0] for request in raw_requests} == {"Bearer", "Basic"}
    sessions = {session.session_id: session.auth_mechanism.auth_type for session in inventory.sessions}
    assert {request.session_id for request in raw_requests} == set(sessions)
    assert {
        (request.headers["Authorization"].split()[0].lower(), sessions[request.session_id]) for request in raw_requests
    } == {("bearer", "bearer"), ("basic", "basic")}

    inventory_path = tmp_path / "har-inventory.json"
    inventory.save(inventory_path)
    args = _parse_args("replay", "--inventory", str(inventory_path), "--dry-run", "--json")
    assert command_web_api(args) == 0
    preview = json.loads(capsys.readouterr().out)
    values = {request["headers"]["Authorization"] for request in preview["evidence"]["requests"]}
    assert {value.split()[0] for value in values} == {"Bearer", "Basic"}
    assert all(value.split()[1].startswith("[REDACTED:") for value in values)
    assert {request["session_id"] for request in preview["evidence"]["requests"]} == set(sessions)
    encoded = json.dumps(preview)
    assert "fixture-bearer-secret" not in encoded
    assert "Zml4dHVyZTpzZWNyZXQ=" not in encoded


def test_swagger_base_path_and_case_distinct_query_credentials_survive_cli_synthesis():
    inventory = import_openapi(
        {
            "swagger": "2.0",
            "host": "swagger.example.test",
            "basePath": "/service/v2",
            "securityDefinitions": {
                "lower": {"type": "apiKey", "in": "query", "name": "api_key"},
                "upper": {"type": "apiKey", "in": "query", "name": "API_KEY"},
            },
            "paths": {"/items": {"get": {"security": [{"lower": [], "upper": []}]}}},
        }
    )

    request = _requests_from_inventory(inventory)[0]
    assert request.url == "https://swagger.example.test/service/v2/items"
    assert set(request.query_parameters) == {"api_key", "API_KEY"}
    assert request.query_parameters["api_key"] != request.query_parameters["API_KEY"]


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
@pytest.mark.parametrize("delimiter", ["?", "#"])
def test_cli_import_rejects_operation_path_delimiters_without_echo(dialect, delimiter, tmp_path, capsys):
    source = tmp_path / f"{dialect}.json"
    source.write_text(
        json.dumps(
            {
                ("openapi" if dialect == "openapi" else "swagger"): ("3.0.3" if dialect == "openapi" else "2.0"),
                "paths": {f"/items{delimiter}private-cli-value": {"get": {}}},
            }
        ),
        encoding="utf-8",
    )
    args = _parse_args("inventory", "--openapi", str(source), "--json")
    assert command_web_api(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-cli-value" not in captured.err


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("source_id", "/private/customer/openapi.json"),
        ("path_or_uri", r"C:\Customer\openapi.json"),
        ("path_or_uri", "https://user:private-value@example.test/openapi.json"),
        ("sha256", "f" * 63),
    ],
)
@pytest.mark.parametrize("provenance_field", ["provenance", "provenance_sources"])
def test_cli_inspect_json_validates_provenance_without_echo(field, unsafe_value, provenance_field, tmp_path, capsys):
    document = import_openapi({"openapi": "3.0.3", "paths": {}}).to_dict()
    record = dict(document["provenance"])
    record[field] = unsafe_value
    if provenance_field == "provenance":
        document["provenance"] = record
    else:
        document["provenance"] = None
        document["provenance_sources"] = [record]
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    assert command_web_api(_parse_args("inspect", str(source), "--json")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert unsafe_value not in captured.err
    assert str(source) not in captured.err


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "/private/customer/openapi.json",
        r"C:\Customer\openapi.json",
        "customer/openapi.json",
        "source=customer/openapi.json",
        "user:private-value@example.test",
        "https://user:private-value@example.test/openapi.json",
        "token=private-value",
    ],
)
def test_cli_inspect_json_validates_public_labels_without_echo(unsafe_value, tmp_path, capsys):
    document = import_openapi({"openapi": "3.0.3", "paths": {}}).to_dict()
    document["imported_sources"] = [unsafe_value]
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    assert command_web_api(_parse_args("inspect", str(source), "--json")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert unsafe_value not in captured.err
    assert str(source) not in captured.err


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("credential_hash", "PLAINTEXT-CREDENTIAL-MARKER"),
        ("credential_hash", "F" * 64),
        ("is_redacted", False),
        ("is_redacted", "true"),
    ],
)
def test_cli_inspect_json_validates_authentication_metadata_without_echo(field, unsafe_value, tmp_path, capsys):
    document = import_har(
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.test/private",
                            "method": "GET",
                            "headers": [{"name": "Authorization", "value": "Bearer fixture-secret"}],
                        }
                    }
                ]
            }
        }
    ).to_dict()
    document["endpoints"][0]["auth_mechanisms"][0][field] = unsafe_value
    document["sessions"][0]["auth_mechanism"][field] = unsafe_value
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    assert command_web_api(_parse_args("inspect", str(source), "--json")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(unsafe_value) not in captured.err
    assert "fixture-secret" not in captured.err
    assert str(source) not in captured.err


def test_cli_inspect_json_uses_bounded_document_reader(tmp_path, capsys, monkeypatch):
    marker = "private-inspect-secret"
    source = tmp_path / f"{marker}.json"
    source.write_bytes(b"{" + marker.encode() + (b"x" * 128))
    monkeypatch.setattr(models, "MAX_WEB_API_DOCUMENT_BYTES", 32)

    assert command_web_api(_parse_args("inspect", str(source), "--json")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert marker not in captured.err
    assert str(source) not in captured.err


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
def test_cli_import_rejects_unresolved_authorities_without_echo(dialect, tmp_path, capsys):
    source = tmp_path / f"{dialect}.json"
    if dialect == "openapi":
        document = {
            "openapi": "3.0.3",
            "servers": [{"url": "https://:443/private-cli-value"}],
            "paths": {"/": {"get": {}}},
        }
    else:
        document = {
            "swagger": "2.0",
            "host": ":private-cli-value",
            "paths": {"/": {"get": {}}},
        }
    source.write_text(json.dumps(document), encoding="utf-8")

    args = _parse_args("inventory", "--openapi", str(source), "--json")
    assert command_web_api(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-cli-value" not in captured.err


@pytest.mark.parametrize("delimiter", ["?", "#"])
def test_cli_replay_rejects_inventory_path_delimiters_without_echo(delimiter, tmp_path, capsys):
    inventory_path = tmp_path / "unsafe-inventory.json"
    ApiInventory(
        inventory_id="inv-unsafe",
        name="Unsafe fixture",
        target_hosts=["api.example.test"],
        endpoints=[
            HttpEndpoint(
                endpoint_id="ep-unsafe",
                method="GET",
                host="api.example.test",
                path=f"/items{delimiter}private-cli-value",
            )
        ],
    ).save(inventory_path)

    args = _parse_args("replay", "--inventory", str(inventory_path), "--dry-run", "--json")
    assert command_web_api(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-cli-value" not in captured.err
