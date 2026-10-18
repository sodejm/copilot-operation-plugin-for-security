"""Regression evidence for API import identity and persistence boundaries."""

import hashlib
import json
import traceback
from dataclasses import asdict

import pytest

from cops.discovery.models import EvidenceProvenance
from cops.web_api.importer import ImporterError, import_har, import_openapi, import_postman, import_raw_http
from cops.web_api.models import (
    ReplayBudget,
    ReplayRequest,
    ReplayResponse,
    ReplaySessionReport,
    redact_credential_value,
)
from cops.web_api.replay import build_replay_action_plan, preview_replay_session
from cops.web_api.sanitization import sanitize_body


def test_supplied_provenance_cannot_attest_different_content():
    supplied = EvidenceProvenance("fixture", "openapi", "0" * 64, "2026-10-18T00:00:00Z", "source")
    with pytest.raises(ImporterError, match="does not match input content"):
        import_openapi('{"paths": {}}', provenance=supplied)


@pytest.mark.parametrize("field", ["auth", "key", "session", "cookie", "jwt"])
def test_plain_text_credential_assignments_are_redacted(field):
    assert "fixture-secret" not in sanitize_body(f"{field}=fixture-secret")


@pytest.mark.parametrize("via_file", [False, True])
def test_provenance_hashes_exact_input_without_retaining_source(tmp_path, via_file):
    source = '{ "openapi": "3.0.0", "paths": {}, "info": {"title": "synthetic"}}\r\n'
    path = tmp_path / "private-capture.json"
    path.write_bytes(source.encode())
    inventory = import_openapi(path if via_file else source, source_id="fixture")
    expected = hashlib.sha256(source.encode()).hexdigest()
    assert inventory.provenance.sha256 == expected
    assert inventory.provenance.path_or_uri == f"sha256:{expected}"
    assert str(path) not in json.dumps(inventory.to_dict())
    changed = import_openapi(source + " ", source_id="fixture")
    assert changed.provenance.sha256 != expected


def test_mapping_provenance_is_canonical_and_long_inline_input_is_not_a_path():
    value = {"paths": {}, "info": {"title": "a" * 10000}}
    inventory = import_openapi(value, source_id="fixture")
    assert (
        inventory.provenance.sha256
        == hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    assert import_openapi(json.dumps(value)).endpoints == []


@pytest.mark.parametrize("value", ['{"paths": {}, "private-value":', "[]", "null", "42"])
def test_invalid_json_errors_do_not_echo_source(value):
    with pytest.raises(ImporterError) as caught:
        import_openapi(value)
    rendered = "".join(traceback.format_exception(caught.value))
    assert "private-value" not in rendered


def test_har_separates_origins_and_removes_userinfo_and_query_values():
    urls = [
        "https://fixture-user:fixture-password@ONE.example:8443/x?ordinary=fixture-query",
        "http://one.example:8443/x",
        "https://two.example/x",
    ]
    inventory = import_har({"log": {"entries": [{"request": {"url": url, "method": "GET"}} for url in urls]}})
    assert len(inventory.endpoints) == 3
    assert len({endpoint.endpoint_id for endpoint in inventory.endpoints}) == 3
    assert inventory.target_hosts == ["one.example:8443", "two.example"]
    assert inventory.endpoints[0].query_parameters["ordinary"].startswith("[REDACTED:")
    assert "fixture-" not in json.dumps(inventory.to_dict())


def test_structured_postman_url_and_key_headers_are_imported():
    inventory = import_postman(
        {
            "item": [
                {
                    "request": {
                        "url": {
                            "protocol": "https",
                            "host": ["api", "example"],
                            "port": "8443",
                            "path": ["v1", "objects"],
                            "query": [{"key": "ordinary", "value": "fixture-query"}],
                        },
                        "header": [{"key": "Authorization", "value": "Bearer fixture-token"}],
                    }
                }
            ]
        }
    )
    endpoint = inventory.endpoints[0]
    assert (endpoint.host, endpoint.path) == ("api.example:8443", "/v1/objects")
    assert "Authorization" in endpoint.headers_schema
    assert "ordinary" in endpoint.query_parameters
    assert "fixture-" not in json.dumps(inventory.to_dict())


@pytest.mark.parametrize("host_header", ["host", "HOST", "Host"])
def test_raw_http_host_is_case_insensitive(host_header):
    inventory = import_raw_http(f"GET /x?ordinary=fixture-query HTTP/1.1\r\n{host_header}: [::1]:8443\r\n\r\n")
    assert inventory.target_hosts == ["[::1]:8443"]
    assert "fixture-query" not in json.dumps(inventory.to_dict())


@pytest.mark.parametrize(
    "raw_request",
    [
        "GET / HTTP/1.1\r\nHost: a.example\r\nhost: a.example\r\n\r\n",
        "GET https://a.example/x HTTP/1.1\r\nHost: b.example\r\n\r\n",
        "private-value",
    ],
)
def test_ambiguous_raw_http_rejected_without_echo(raw_request):
    with pytest.raises(ImporterError) as caught:
        import_raw_http(raw_request)
    assert "private-value" not in str(caught.value)


@pytest.mark.parametrize(
    "reference",
    [
        "https://fixture-user:fixture-password@example.test/x?ordinary=fixture-query#fixture-fragment",
        "//fixture-user:fixture-password@example.test/x",
        "callback?ordinary=fixture-query",
        "?ordinary=fixture-query",
        "/callback?ordinary=fixture-query",
    ],
)
def test_persisted_requests_responses_and_metadata_redact_references(reference):
    request = ReplayRequest(
        "request",
        "endpoint",
        "GET",
        "https://example.test/x?ordinary=fixture-query",
        headers={"Location": reference, "Refresh": f"0; url={reference}"},
        query_parameters={"ordinary": "fixture-query"},
        body=json.dumps({"next": reference}),
        graphql_query=f'query {{ next(url: "{reference}") }}',
        websocket_messages=[reference],
    )
    response = ReplayResponse(
        "request",
        200,
        headers={"Location": reference},
        body_excerpt=reference,
        final_url=reference,
        websocket_replies=[reference],
        error_message=reference,
    )
    original = asdict(request)
    report = ReplaySessionReport("session", ["example.test"], ["example.test"], ReplayBudget(), [request], [response])
    inventory = import_openapi({"paths": {"/": {"get": {"summary": reference}}}, "info": {"title": reference}})
    for document in (
        request.to_dict(),
        response.to_dict(),
        report.to_dict(),
        inventory.to_dict(),
        preview_replay_session([request], ["example.test"]).to_dict(),
    ):
        encoded = json.dumps(document)
        assert "fixture-" not in encoded
    assert asdict(request) == original


def test_redaction_marker_cannot_hide_suffix_and_is_idempotent():
    fake = "[REDACTED:123456789abc]fixture-secret"
    assert redact_credential_value(fake) != fake
    clean = redact_credential_value("fixture-secret")
    assert redact_credential_value(clean) == clean


def test_approval_request_digest_does_not_use_lossy_report_serialization():
    def plan(password):
        return build_replay_action_plan(
            plan_id="plan-original",
            engagement_id="eng-web-api-lab",
            scenario_id="scen-web-api-assessment",
            specialist_id="web-api-assessment-workbench",
            requests=[
                ReplayRequest("r", "e", "POST", "https://example.test/x", body=json.dumps({"password": password}))
            ],
            allowed_destinations=["example.test"],
            created_at="2026-10-18T00:00:00Z",
        )

    assert plan("first").operations != plan("second").operations
