"""Regression evidence for API import identity and persistence boundaries."""

import hashlib
import json
import traceback
from dataclasses import asdict

import pytest

from cops.discovery.models import EvidenceProvenance
from cops.web_api.importer import ImporterError, import_har, import_openapi, import_postman, import_raw_http
from cops.web_api.models import (
    ApiInventory,
    AuthenticationMechanism,
    ReplayBudget,
    ReplayRequest,
    ReplayResponse,
    ReplaySessionReport,
    redact_credential_value,
)
from cops.web_api.replay import build_replay_action_plan, preview_replay_session
from cops.web_api.sanitization import sanitize_body


def test_supplied_provenance_cannot_attest_different_content():
    supplied = EvidenceProvenance("fixture", "openapi_import", "0" * 64, "2026-10-18T00:00:00Z", f"sha256:{'0' * 64}")
    with pytest.raises(ImporterError, match="does not match input content"):
        import_openapi('{"paths": {}}', provenance=supplied)


@pytest.mark.parametrize(
    "source_id",
    [
        "/private/tmp/customer/openapi.json",
        r"C:\Customer\openapi.json",
        "relative/openapi.json",
        "customer-secret-token",
    ],
)
@pytest.mark.parametrize("boundary", ["argument", "supplied"])
def test_import_rejects_nonopaque_source_ids_without_disclosure(source_id, boundary):
    document = {"openapi": "3.0.3", "paths": {}}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    supplied = None
    argument = None
    if boundary == "argument":
        argument = source_id
    else:
        digest = hashlib.sha256(payload).hexdigest()
        supplied = EvidenceProvenance(
            source_id,
            "openapi_import",
            digest,
            "2026-10-18T00:00:00Z",
            f"sha256:{digest}",
        )

    with pytest.raises(ImporterError, match="API import provenance is invalid") as caught:
        import_openapi(document, source_id=argument, provenance=supplied)

    assert source_id not in "".join(traceback.format_exception(caught.type, caught.value, caught.tb))


INVALID_PROVENANCE_VALUES = (
    ("source_id", "/private/customer.json"),
    ("source_id", r"C:\Customer\api.json"),
    ("source_id", "customer-secret-token"),
    ("source_type", "../private/openapi_import"),
    ("source_type", "credential-export"),
    ("sha256", "f" * 63),
    ("sha256", "G" * 64),
    ("path_or_uri", "/private/customer.json"),
    ("path_or_uri", r"C:\Customer\api.json"),
    ("path_or_uri", "https://user:secret@example.test/api.json"),
    ("path_or_uri", f"sha256:{'1' * 64}"),
    ("timestamp", "/private/timestamp"),
    ("timestamp", "token=private-value"),
    ("raw_record_ref", "/private/record.json"),
    ("raw_record_ref", r"C:\Customer\record.json"),
    ("raw_record_ref", "https://user:secret@example.test/record"),
)

UNSAFE_PUBLIC_LABELS = (
    "/private/customer/openapi.json",
    r"C:\Customer\openapi.json",
    "customer/openapi.json",
    "source=customer/openapi.json",
    "user:private-value@example.test",
    "https://user:private-value@example.test/openapi.json",
    "token=private-value",
)


@pytest.mark.parametrize(
    "boundary", ["deserialize-provenance", "deserialize-sources", "serialize-provenance", "serialize-sources"]
)
@pytest.mark.parametrize(("field", "unsafe_value"), INVALID_PROVENANCE_VALUES)
def test_inventory_contract_rejects_unsafe_provenance_without_disclosure(boundary, field, unsafe_value):
    inventory = import_openapi({"openapi": "3.0.3", "paths": {}}, source_id="opaque-source")
    document = inventory.to_dict()

    if boundary.startswith("deserialize"):
        record = dict(document["provenance"])
        record[field] = unsafe_value
        if boundary == "deserialize-provenance":
            document["provenance"] = record
        else:
            document["provenance"] = None
            document["provenance_sources"] = [record]

        def operation():
            return ApiInventory.from_dict(document)

    else:
        setattr(inventory.provenance, field, unsafe_value)
        if boundary == "serialize-sources":
            inventory.provenance_sources = [inventory.provenance]
            inventory.provenance = None
        operation = inventory.to_dict

    with pytest.raises(ValueError, match="inventory provenance record is invalid") as caught:
        operation()
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert unsafe_value not in rendered


def test_inventory_contract_rejects_unknown_provenance_fields_without_disclosure():
    document = import_openapi({"openapi": "3.0.3", "paths": {}}).to_dict()
    document["provenance"]["private-path"] = "/private/customer/openapi.json"

    with pytest.raises(ValueError, match="inventory provenance record is invalid") as caught:
        ApiInventory.from_dict(document)

    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert "private-path" not in rendered
    assert "/private/customer/openapi.json" not in rendered


@pytest.mark.parametrize("unsafe_value", UNSAFE_PUBLIC_LABELS)
@pytest.mark.parametrize("field", ["name", "imported_sources"])
@pytest.mark.parametrize("boundary", ["deserialize", "serialize"])
def test_inventory_contract_rejects_unsafe_public_labels_without_disclosure(boundary, field, unsafe_value):
    inventory = import_openapi({"openapi": "3.0.3", "paths": {}})
    if boundary == "deserialize":
        document = inventory.to_dict()
        document[field] = [unsafe_value] if field == "imported_sources" else unsafe_value

        def operation():
            return ApiInventory.from_dict(document)

    else:
        setattr(inventory, field, [unsafe_value] if field == "imported_sources" else unsafe_value)
        operation = inventory.to_dict

    with pytest.raises(ValueError, match="inventory public metadata is invalid") as caught:
        operation()
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert unsafe_value not in rendered


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("credential_hash", "PLAINTEXT-CREDENTIAL-MARKER"),
        ("credential_hash", "A" * 64),
        ("credential_hash", "f" * 63),
        ("is_redacted", False),
        ("is_redacted", "true"),
        ("auth_type", "unsupported"),
        ("location", "body"),
    ],
)
@pytest.mark.parametrize("boundary", ["deserialize", "serialize"])
@pytest.mark.parametrize("target", ["endpoint", "session", "matching"])
def test_inventory_contract_rejects_unsafe_authentication_metadata_without_disclosure(
    boundary, target, field, unsafe_value
):
    inventory = import_raw_http(
        "GET /private HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer fixture-secret\r\n\r\n"
    )
    if boundary == "deserialize":
        document = inventory.to_dict()
        if target in {"endpoint", "matching"}:
            document["endpoints"][0]["auth_mechanisms"][0][field] = unsafe_value
        if target in {"session", "matching"}:
            document["sessions"][0]["auth_mechanism"][field] = unsafe_value

        def operation():
            return ApiInventory.from_dict(document)

    else:
        if target in {"endpoint", "matching"}:
            setattr(inventory.endpoints[0].auth_mechanisms[0], field, unsafe_value)
        if target in {"session", "matching"}:
            setattr(inventory.sessions[0].auth_mechanism, field, unsafe_value)
        operation = inventory.to_dict

    with pytest.raises(ValueError, match="inventory authentication mechanism is invalid") as caught:
        operation()
    rendered = "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert str(unsafe_value) not in rendered
    assert "fixture-secret" not in rendered


def test_authentication_mechanism_accepts_only_redacted_declaration_or_digest_identity():
    declaration = AuthenticationMechanism(auth_type="bearer", token_name="Authorization")
    digest = AuthenticationMechanism(
        auth_type="api_key",
        token_name="X-API-Key",
        credential_hash=hashlib.sha256(b"fixture-secret").hexdigest(),
    )

    assert AuthenticationMechanism.from_dict(declaration.to_dict()) == declaration
    assert AuthenticationMechanism.from_dict(digest.to_dict()) == digest


@pytest.mark.parametrize(
    ("loader", "document", "expected_name"),
    [
        (
            import_openapi,
            {"openapi": "3.0.3", "info": {"title": "/private/customer/openapi.json"}, "paths": {}},
            "OpenAPI Spec: OpenAPI Service",
        ),
        (
            import_postman,
            {"info": {"name": r"C:\Customer\collection.json"}, "item": []},
            "Postman: Postman Collection",
        ),
    ],
)
def test_importer_replaces_unsafe_source_titles_with_safe_defaults(loader, document, expected_name):
    inventory = loader(document)
    encoded = json.dumps(inventory.to_dict())

    assert inventory.name == expected_name
    assert "Customer" not in encoded


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


def test_single_source_provenance_round_trips_in_legacy_shape():
    inventory = import_openapi(
        {"openapi": "3.0.3", "paths": {"/items": {"get": {}}}},
        source_id="opaque-source",
    )

    serialized = inventory.to_dict()
    restored = ApiInventory.from_dict(serialized)

    assert serialized["provenance"] is not None
    assert serialized["provenance_sources"] == []
    assert restored.to_dict() == serialized


def test_mapping_provenance_is_canonical_and_long_inline_input_is_not_a_path():
    value = {"openapi": "3.0.3", "paths": {}, "info": {"title": "a" * 10000}}
    inventory = import_openapi(value, source_id="fixture")
    assert (
        inventory.provenance.sha256
        == hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    assert import_openapi(json.dumps(value)).endpoints == []


@pytest.mark.parametrize("dialect", ["openapi", "swagger"])
@pytest.mark.parametrize("delimiter", ["?", "#"])
def test_openapi_operation_paths_reject_query_and_fragment_delimiters_without_echo(dialect, delimiter):
    marker = f"/items{delimiter}private-operation-value"
    document = {
        ("openapi" if dialect == "openapi" else "swagger"): ("3.0.3" if dialect == "openapi" else "2.0"),
        "paths": {marker: {"get": {}}},
    }
    with pytest.raises(ImporterError) as caught:
        import_openapi(document)
    assert "private-operation-value" not in str(caught.value)


@pytest.mark.parametrize(
    "document",
    [
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://:443/private-authority-value"}],
            "paths": {"/": {"get": {}}},
        },
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test:private-authority-value/v1"}],
            "paths": {"/": {"get": {}}},
        },
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test:70000/private-authority-value"}],
            "paths": {"/": {"get": {}}},
        },
        {
            "swagger": "2.0",
            "host": ":443",
            "basePath": "/private-authority-value",
            "paths": {"/": {"get": {}}},
        },
        {
            "swagger": "2.0",
            "host": "api.example.test:private-authority-value",
            "paths": {"/": {"get": {}}},
        },
        {
            "swagger": "2.0",
            "host": "api.example.test:70000",
            "basePath": "/private-authority-value",
            "paths": {"/": {"get": {}}},
        },
    ],
)
def test_openapi_authorities_require_hostname_and_valid_port_without_echo(document):
    with pytest.raises(ImporterError) as caught:
        import_openapi(document)

    assert "private-authority-value" not in str(caught.value)


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
    inventory = import_openapi(
        {"openapi": "3.0.3", "paths": {"/": {"get": {"summary": reference}}}, "info": {"title": reference}}
    )
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


@pytest.mark.parametrize(
    "declaration",
    [
        {},
        {"swagger": "1.2"},
        {"swagger": 2.0},
        {"openapi": "4.0.0"},
        {"openapi": "3.0"},
        {"openapi": 3},
        {"openapi": "3.0.3-secret"},
        {"openapi": "3.0.3", "swagger": "2.0"},
        {"openapi": None},
        {"swagger": None},
    ],
)
def test_openapi_rejects_missing_unsupported_or_conflicting_versions(declaration):
    with pytest.raises(ImporterError, match="unsupported or conflicting version") as caught:
        import_openapi({**declaration, "paths": {"/items": {"get": {}}}})
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "declaration", [{"swagger": "2.0"}, {"openapi": "3.0.3"}, {"openapi": "3.1.0"}, {"openapi": "3.2.0"}]
)
def test_openapi_accepts_supported_declared_versions(declaration):
    inventory = import_openapi({**declaration, "host": "api.example.test", "paths": {"/items": {"get": {}}}})
    assert len(inventory.endpoints) == 1
