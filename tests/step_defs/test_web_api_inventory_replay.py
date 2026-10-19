from __future__ import annotations

import argparse
import hashlib
import json
import traceback

from pytest_bdd import given, scenario, then, when

from cops.web_api import importer, models
from cops.web_api.cli import (
    _merge_inventories,
    _replay_preview_document,
    _requests_from_inventory,
    build_web_api_parser,
    command_web_api,
)
from cops.web_api.importer import ImporterError, import_har, import_openapi, import_postman, import_raw_http
from cops.web_api.models import ApiInventory, AuthenticationMechanism, ReplayBudget
from cops.web_api.replay import build_replay_action_plan, execute_replay_session

FEATURE = "../../specs/features/web_api_inventory_replay.feature"


@scenario(FEATURE, "Import input is bounded before parsing")
def test_import_input_is_bounded_before_parsing():
    pass


@scenario(FEATURE, "Merged inventory provenance is lossless and stable")
def test_merged_inventory_provenance_is_lossless_and_stable():
    pass


@scenario(FEATURE, "Provenance records are safe at every public boundary")
def test_provenance_records_are_safe_at_every_public_boundary():
    pass


@scenario(FEATURE, "Saved web API documents are bounded and validated before inspection")
def test_saved_web_api_documents_are_bounded_and_validated_before_inspection():
    pass


@scenario(FEATURE, "Public inventory labels cannot disclose source references")
def test_public_inventory_labels_cannot_disclose_source_references():
    pass


@scenario(FEATURE, "Authentication metadata is credential-free at every public boundary")
def test_authentication_metadata_is_credential_free_at_every_public_boundary():
    pass


@scenario(FEATURE, "HAR standard authorization survives merge and preview")
def test_har_standard_authorization_survives_merge_and_preview():
    pass


@scenario(FEATURE, "Authenticated imports keep explicit session identity end to end")
def test_authenticated_imports_keep_explicit_session_identity_end_to_end():
    pass


@scenario(FEATURE, "Same-scheme sources remain distinct through merge")
def test_same_scheme_sources_remain_distinct_through_merge():
    pass


@scenario(FEATURE, "Invalid endpoint session references fail closed")
def test_invalid_endpoint_session_references_fail_closed():
    pass


@given("exact-limit and oversized API import sources", target_fixture="bounded_sources")
def exact_limit_and_oversized_sources(tmp_path, monkeypatch):
    limit = 512
    monkeypatch.setattr(importer, "MAX_IMPORT_BYTES", limit)
    cases = (
        ("har", import_har, json.dumps({"log": {"entries": []}}).encode()),
        ("openapi", import_openapi, json.dumps({"openapi": "3.0.3", "paths": {}}).encode()),
        ("postman", import_postman, json.dumps({"info": {"name": "bounded"}, "item": []}).encode()),
        ("raw", import_raw_http, b"GET / HTTP/1.1\r\nHost: bounded.example\r\n\r\n"),
    )
    sources = []
    for suffix, loader, base in cases:
        exact_content = base + (b" " * (limit - len(base)))
        exact = tmp_path / f"exact-{suffix}.input"
        oversized = tmp_path / f"private-path-{suffix}.input"
        exact.write_bytes(exact_content)
        oversized.write_bytes(base + (b"x" * (limit + 1 - len(base))))
        sources.append((loader, exact, exact_content, oversized))
    return sources


@when("each supported format is imported offline", target_fixture="bounded_results")
def import_each_supported_format_offline(bounded_sources):
    results = []
    for loader, exact, exact_content, oversized in bounded_sources:
        inventory = loader(exact)
        try:
            loader(oversized)
        except ImporterError as error:
            rendered = "".join(traceback.format_exception(error))
        else:
            raise AssertionError("oversized import unexpectedly succeeded")
        results.append((inventory, exact_content, oversized, rendered))
    return results


@then("the exact-limit source keeps its exact content digest")
def exact_limit_source_keeps_digest(bounded_results):
    for inventory, exact_content, _oversized, _rendered in bounded_results:
        assert inventory.provenance.sha256 == hashlib.sha256(exact_content).hexdigest()


@then("the oversized source fails without disclosing content or its path")
def oversized_source_fails_without_disclosure(bounded_results):
    for _inventory, _exact_content, oversized, rendered in bounded_results:
        assert "API import input exceeds the byte limit" in rendered
        assert str(oversized) not in rendered
        assert "private-path" not in rendered


@given("repeated API sources with opaque provenance identities", target_fixture="provenance_sources")
def repeated_api_sources_with_opaque_provenance():
    first = import_openapi({"openapi": "3.0.3", "paths": {"/first": {"get": {}}}}, source_id="opaque-a")
    second = import_openapi({"openapi": "3.0.3", "paths": {"/second": {"get": {}}}}, source_id="opaque-b")
    first.provenance.timestamp = "2026-01-01T00:00:00Z"
    second.provenance.timestamp = "2030-01-01T00:00:00Z"
    return first, second


@when("the sources are imported in different orders", target_fixture="merged_inventories")
def import_sources_in_different_orders(provenance_sources):
    first, second = provenance_sources
    return (
        _merge_inventories([first, second, first], "forward"),
        _merge_inventories([first, first, second], "reverse"),
    )


@then("every source provenance record is preserved including duplicates")
def every_source_provenance_is_preserved(merged_inventories):
    forward, reverse = merged_inventories
    assert len(forward.provenance_sources) == 3
    assert len(reverse.provenance_sources) == 3
    assert forward.to_dict() == ApiInventory.from_dict(forward.to_dict()).to_dict()
    counts = {source.sha256: 0 for source in forward.provenance_sources}
    for source in forward.provenance_sources:
        counts[source.sha256] += 1
    assert sorted(counts.values()) == [1, 2]


@then("the merged inventory identity is independent of order and timestamps")
def merged_identity_is_stable(merged_inventories):
    forward, reverse = merged_inventories
    assert forward.inventory_id == reverse.inventory_id


@given("malformed path-bearing and digest provenance records", target_fixture="malformed_provenance")
def malformed_path_bearing_and_digest_records():
    return (
        ("source_id", "/private/customer/openapi.json"),
        ("source_id", r"C:\Customer\openapi.json"),
        ("source_id", "customer-secret-token"),
        ("sha256", "f" * 63),
        ("path_or_uri", "/private/customer/openapi.json"),
        ("path_or_uri", r"C:\Customer\openapi.json"),
        ("path_or_uri", "https://user:secret@example.test/openapi.json"),
        ("path_or_uri", f"sha256:{'1' * 64}"),
        ("raw_record_ref", "/private/customer/record.json"),
    )


@when("provenance deserialization and serialization are attempted", target_fixture="provenance_failures")
def attempt_provenance_boundaries(malformed_provenance):
    failures = []
    for field, unsafe_value in malformed_provenance:
        inventory = import_openapi({"openapi": "3.0.3", "paths": {}}, source_id="opaque-source")
        document = inventory.to_dict()
        record = dict(document["provenance"])
        record[field] = unsafe_value
        document["provenance"] = None
        document["provenance_sources"] = [record]
        try:
            ApiInventory.from_dict(document)
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("malformed provenance unexpectedly deserialized")

        setattr(inventory.provenance, field, unsafe_value)
        try:
            inventory.to_dict()
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("malformed provenance unexpectedly serialized")
    return failures


@then("every malformed provenance record is rejected without disclosure")
def malformed_provenance_is_rejected_without_disclosure(provenance_failures):
    for unsafe_value, rendered in provenance_failures:
        assert "inventory provenance record is invalid" in rendered
        assert unsafe_value not in rendered


@given("exact-limit and oversized saved inventory documents", target_fixture="saved_inventory_sources")
def exact_limit_and_oversized_saved_inventory_documents(tmp_path, monkeypatch):
    inventory = import_openapi({"openapi": "3.0.3", "paths": {}})
    encoded = json.dumps(inventory.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    limit = len(encoded) + 17
    monkeypatch.setattr(models, "MAX_WEB_API_DOCUMENT_BYTES", limit)
    exact = tmp_path / "exact-inventory.json"
    oversized = tmp_path / "private-saved-inventory-secret.json"
    exact.write_bytes(encoded + (b" " * (limit - len(encoded))))
    oversized.write_bytes(encoded + (b"x" * (limit + 1 - len(encoded))))
    return exact, oversized, inventory.to_dict()


@when("the saved inventories are loaded through the public document boundary", target_fixture="saved_inventory_results")
def load_saved_inventories_through_public_boundary(saved_inventory_sources):
    exact, oversized, expected = saved_inventory_sources
    accepted = ApiInventory.load(exact)
    try:
        ApiInventory.load(oversized)
    except ValueError as error:
        rendered = "".join(traceback.format_exception(error))
    else:
        raise AssertionError("oversized saved inventory unexpectedly loaded")
    return accepted, expected, oversized, rendered


@then("the exact-limit saved inventory is accepted")
def exact_limit_saved_inventory_is_accepted(saved_inventory_results):
    accepted, expected, _oversized, _rendered = saved_inventory_results
    assert accepted.to_dict() == expected


@then("the oversized saved inventory fails without disclosing content or its path")
def oversized_saved_inventory_fails_without_disclosure(saved_inventory_results):
    _accepted, _expected, oversized, rendered = saved_inventory_results
    assert "web API document exceeds the byte limit" in rendered
    assert str(oversized) not in rendered
    assert "private-saved-inventory-secret" not in rendered


@given("inventory documents with unsafe public source labels", target_fixture="unsafe_public_labels")
def inventory_documents_with_unsafe_public_source_labels():
    return (
        "/private/customer/openapi.json",
        r"C:\Customer\openapi.json",
        "customer/openapi.json",
        "source=customer/openapi.json",
        "user:private-value@example.test",
        "https://user:private-value@example.test/openapi.json",
        "token=private-value",
    )


@when(
    "deserialization serialization and JSON inspection are attempted",
    target_fixture="public_label_failures",
)
def attempt_public_label_boundaries(unsafe_public_labels, tmp_path, capsys):
    failures = []
    parser = argparse.ArgumentParser()
    build_web_api_parser(parser)
    for index, unsafe_value in enumerate(unsafe_public_labels):
        inventory = import_openapi({"openapi": "3.0.3", "paths": {}})
        document = inventory.to_dict()
        document["imported_sources"] = [unsafe_value]
        try:
            ApiInventory.from_dict(document)
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("unsafe public label unexpectedly deserialized")

        inventory.imported_sources = [unsafe_value]
        try:
            inventory.to_dict()
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("unsafe public label unexpectedly serialized")

        path = tmp_path / f"inventory-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        args = parser.parse_args(["inspect", str(path), "--json"])
        assert command_web_api(args) == 1
        captured = capsys.readouterr()
        failures.append((unsafe_value, captured.out + captured.err))
    return failures


@then("every unsafe public source label is rejected without disclosure")
def unsafe_public_source_labels_are_rejected(public_label_failures):
    for unsafe_value, rendered in public_label_failures:
        assert "inventory public metadata is invalid" in rendered
        assert unsafe_value not in rendered


@given(
    "inventory documents and objects with unsafe authentication metadata",
    target_fixture="unsafe_authentication_metadata",
)
def inventory_documents_and_objects_with_unsafe_authentication_metadata():
    return (
        ("credential_hash", "PLAINTEXT-AUTHENTICATION-MARKER"),
        ("credential_hash", "A" * 64),
        ("is_redacted", "private-redaction-marker"),
    )


@when(
    "authentication deserialization serialization and JSON inspection are attempted",
    target_fixture="authentication_boundary_results",
)
def attempt_authentication_metadata_boundaries(unsafe_authentication_metadata, tmp_path, capsys):
    failures = []
    parser = argparse.ArgumentParser()
    build_web_api_parser(parser)
    for index, (field, unsafe_value) in enumerate(unsafe_authentication_metadata):
        inventory = import_raw_http(
            "GET /private HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer fixture-secret\r\n\r\n"
        )
        document = inventory.to_dict()
        document["endpoints"][0]["auth_mechanisms"][0][field] = unsafe_value
        document["sessions"][0]["auth_mechanism"][field] = unsafe_value
        try:
            ApiInventory.from_dict(document)
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("unsafe authentication metadata unexpectedly deserialized")

        setattr(inventory.endpoints[0].auth_mechanisms[0], field, unsafe_value)
        setattr(inventory.sessions[0].auth_mechanism, field, unsafe_value)
        try:
            inventory.to_dict()
        except ValueError as error:
            failures.append((unsafe_value, "".join(traceback.format_exception(error))))
        else:
            raise AssertionError("unsafe authentication metadata unexpectedly serialized")

        path = tmp_path / f"authentication-inventory-{index}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        args = parser.parse_args(["inspect", str(path), "--json"])
        assert command_web_api(args) == 1
        captured = capsys.readouterr()
        failures.append((unsafe_value, captured.out + captured.err))

    digest = hashlib.sha256(b"fixture-credential").hexdigest()
    valid = (
        AuthenticationMechanism(auth_type="bearer", token_name="Authorization"),
        AuthenticationMechanism(auth_type="api_key", token_name="X-API-Key", credential_hash=digest),
    )
    round_trips = tuple(AuthenticationMechanism.from_dict(mechanism.to_dict()) for mechanism in valid)
    return failures, valid, round_trips


@then("every unsafe authentication mechanism is rejected without disclosure")
def unsafe_authentication_metadata_is_rejected(authentication_boundary_results):
    failures, _valid, _round_trips = authentication_boundary_results
    for unsafe_value, rendered in failures:
        assert "inventory authentication mechanism is invalid" in rendered
        assert unsafe_value not in rendered
        assert "fixture-secret" not in rendered


@then("declaration-only and digest authentication identities round trip")
def valid_authentication_metadata_round_trips(authentication_boundary_results):
    _failures, valid, round_trips = authentication_boundary_results
    assert round_trips == valid


@given("separate HAR sources for one Bearer and one Basic route", target_fixture="har_sources")
def separate_har_sources_for_standard_authorization():
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

    secrets = ("fixture-bearer-secret", "Zml4dHVyZTpzZWNyZXQ=")
    return one_header(f"Bearer {secrets[0]}"), one_header(f"Basic {secrets[1]}"), secrets


@when("the HAR inventories are merged and prepared for preview", target_fixture="har_preview")
def merge_har_sources_and_prepare_preview(har_sources):
    bearer, basic, secrets = har_sources
    inventory = _merge_inventories([bearer, basic], "merged auth")
    requests = _requests_from_inventory(inventory)
    preview = _replay_preview_document(
        inventory=inventory,
        requests=requests,
        destinations=["api.example.test"],
        budget=ReplayBudget(),
        requested_mode="offline",
    )
    return inventory, requests, preview, secrets


@then("both mechanisms retain the Authorization header name")
def mechanisms_retain_authorization_header(har_preview):
    inventory, _requests, _preview, _secrets = har_preview
    mechanisms = [mechanism for endpoint in inventory.endpoints for mechanism in endpoint.auth_mechanisms]
    assert {(mechanism.auth_type, mechanism.token_name) for mechanism in mechanisms} == {
        ("bearer", "Authorization"),
        ("basic", "Authorization"),
    }


@then("each authorization alternative has a distinct endpoint and matching session binding")
def authorization_alternatives_have_distinct_endpoints_and_sessions(har_preview):
    inventory, requests, preview, _secrets = har_preview
    assert len(inventory.endpoints) == 2
    assert len({endpoint.endpoint_id for endpoint in inventory.endpoints}) == 2
    assert len(inventory.sessions) == 2
    assert len({session.session_id for session in inventory.sessions}) == 2
    assert {session.auth_mechanism.auth_type for session in inventory.sessions} == {"bearer", "basic"}
    sessions = {session.session_id: session.auth_mechanism.auth_type for session in inventory.sessions}
    assert {request.session_id for request in requests} == set(sessions)
    assert {
        (request.headers["Authorization"].split()[0].lower(), sessions[request.session_id]) for request in requests
    } == {("bearer", "bearer"), ("basic", "basic")}
    assert {request["session_id"] for request in preview["evidence"]["requests"]} == set(sessions)


@then("preview uses scheme-prefixed redacted Authorization values")
def preview_uses_scheme_prefixed_values(har_preview):
    _inventory, requests, preview, _secrets = har_preview
    values = [request["headers"]["Authorization"] for request in preview["evidence"]["requests"]]
    assert {value.split()[0] for value in values} == {"Bearer", "Basic"}
    assert all(value.split()[1].startswith("[REDACTED:") for value in values)
    assert {request.headers["Authorization"].split()[0] for request in requests} == {"Bearer", "Basic"}


@then("no plaintext credential enters inventory or preview evidence")
def plaintext_credentials_are_absent(har_preview):
    inventory, _requests, preview, secrets = har_preview
    evidence = json.dumps({"inventory": inventory.to_dict(), "preview": preview})
    assert all(secret not in evidence for secret in secrets)


def _raw_bearer_inventory(secret: str):
    return import_raw_http(f"GET /items HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer {secret}\r\n\r\n")


@given("authenticated HAR OpenAPI Postman and raw HTTP sources", target_fixture="authenticated_import_sources")
def authenticated_har_openapi_postman_and_raw_sources():
    secrets = (
        "fixture-har-bearer-secret",
        "fixture-postman-api-key-secret",
        "fixture-raw-basic-secret",
    )
    har = import_har(
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.test/har",
                            "headers": [{"name": "Authorization", "value": f"Bearer {secrets[0]}"}],
                        }
                    }
                ]
            }
        }
    )
    openapi = import_openapi(
        {
            "openapi": "3.0.3",
            "servers": [{"url": "https://api.example.test"}],
            "components": {"securitySchemes": {"basic": {"type": "http", "scheme": "basic"}}},
            "paths": {"/openapi": {"get": {"security": [{"basic": []}]}}},
        }
    )
    postman = import_postman(
        {
            "info": {"name": "authenticated fixture"},
            "item": [
                {
                    "name": "postman",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/postman",
                        "auth": {
                            "type": "apikey",
                            "apikey": [
                                {"key": "key", "value": "X-API-Key"},
                                {"key": "value", "value": secrets[1]},
                                {"key": "in", "value": "header"},
                            ],
                        },
                    },
                }
            ],
        }
    )
    raw = import_raw_http(f"GET /raw HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Basic {secrets[2]}\r\n\r\n")
    return (har, openapi, postman, raw), secrets


@when(
    "the sources are imported serialized merged previewed and replayed offline",
    target_fixture="authenticated_import_result",
)
def authenticated_sources_pass_every_offline_boundary(authenticated_import_sources):
    inventories, secrets = authenticated_import_sources
    restored = [ApiInventory.from_dict(inventory.to_dict()) for inventory in inventories]
    merged = _merge_inventories(restored, "authenticated imports")
    round_tripped = ApiInventory.from_dict(merged.to_dict())
    requests = _requests_from_inventory(round_tripped)
    preview = _replay_preview_document(
        inventory=round_tripped,
        requests=requests,
        destinations=["api.example.test"],
        budget=ReplayBudget(),
        requested_mode="offline",
    )
    plan = build_replay_action_plan(
        plan_id="plan-web-auth-bindings",
        engagement_id="eng-web-auth-bindings",
        scenario_id="scen-web-auth-bindings",
        specialist_id="web-api-assessment-workbench",
        requests=requests,
        sessions=round_tripped.sessions,
        allowed_destinations=["api.example.test"],
        created_at="2026-10-18T00:00:00Z",
    )
    report = execute_replay_session(requests, ["api.example.test"])
    return round_tripped, requests, preview, plan, report, secrets


@then("every authenticated endpoint keeps its explicit matching session")
def every_authenticated_endpoint_keeps_its_session(authenticated_import_result):
    inventory, requests, _preview, plan, report, _secrets = authenticated_import_result
    session_ids = {session.session_id for session in inventory.sessions}
    assert len(inventory.endpoints) == len(inventory.sessions) == 4
    assert {endpoint.session_id for endpoint in inventory.endpoints} == session_ids
    assert {request.session_id for request in requests} == session_ids
    assert {operation["arguments"]["session_id"] for operation in plan.operations} == session_ids
    assert {request.session_id for request in report.requests} == session_ids


@then("Bearer Basic and API-key requests use only redacted placeholders")
def imported_requests_use_only_redacted_placeholders(authenticated_import_result):
    _inventory, requests, _preview, _plan, _report, _secrets = authenticated_import_result
    credential_values = [
        value
        for request in requests
        for name, value in request.headers.items()
        if name.lower() in {"authorization", "x-api-key"}
    ]
    assert any(value.startswith("Bearer [REDACTED:") for value in credential_values)
    assert any(value.startswith("Basic [REDACTED:") for value in credential_values)
    assert any(value.startswith("[REDACTED:") for value in credential_values)


@then("no plaintext credential enters persisted or replay evidence")
def imported_plaintext_credentials_are_absent(authenticated_import_result):
    inventory, requests, preview, plan, report, secrets = authenticated_import_result
    evidence = json.dumps(
        {
            "inventory": inventory.to_dict(),
            "requests": [request.to_dict() for request in requests],
            "preview": preview,
            "plan": plan.to_dict(),
            "report": report.to_dict(),
        }
    )
    assert all(secret not in evidence for secret in secrets)


@given(
    "duplicate and distinct sources using the same authentication scheme",
    target_fixture="same_scheme_sources",
)
def duplicate_and_distinct_same_scheme_sources():
    first = _raw_bearer_inventory("fixture-first-context-secret")
    second = _raw_bearer_inventory("fixture-second-context-secret")
    return first, second


@when("the authenticated inventories are merged in different orders", target_fixture="same_scheme_merges")
def merge_authenticated_inventories_in_different_orders(same_scheme_sources):
    first, second = same_scheme_sources
    return (
        _merge_inventories([first, second, first], "forward"),
        _merge_inventories([first, first, second], "reverse"),
    )


@then("endpoint and session references remain valid and source scoped")
def endpoint_and_session_references_are_source_scoped(same_scheme_merges):
    for inventory in same_scheme_merges:
        restored = ApiInventory.from_dict(inventory.to_dict())
        session_ids = {session.session_id for session in restored.sessions}
        assert len(restored.endpoints) == len(restored.sessions) == 3
        assert len(session_ids) == 3
        assert {endpoint.session_id for endpoint in restored.endpoints} == session_ids
        assert {request.session_id for request in _requests_from_inventory(restored)} == session_ids


@then("the merged identity is stable without conflating credential contexts")
def merged_identity_is_stable_without_context_conflation(same_scheme_merges):
    forward, reverse = same_scheme_merges
    assert forward.inventory_id == reverse.inventory_id
    assert len(forward.provenance_sources) == 3
    assert len({session.auth_mechanism.credential_hash for session in forward.sessions}) == 2


@given(
    "inventories with missing malformed or conflicting endpoint session references",
    target_fixture="invalid_session_operations",
)
def inventories_with_invalid_endpoint_session_references():
    missing = _raw_bearer_inventory("fixture-missing-binding-secret")
    missing.endpoints[0].session_id = "missing-session-private-value"

    malformed = _raw_bearer_inventory("fixture-malformed-binding-secret")
    malformed_document = malformed.to_dict()
    malformed_document["endpoints"][0]["session_id"] = "/private/session-reference"

    conflicting = _raw_bearer_inventory("fixture-conflicting-binding-secret")
    conflicting.sessions[0].auth_mechanism = AuthenticationMechanism(
        auth_type="basic",
        token_name="Authorization",
        location="header",
    )
    return (
        missing.to_dict,
        lambda: ApiInventory.from_dict(malformed_document),
        lambda: _requests_from_inventory(missing),
        conflicting.to_dict,
    )


@when(
    "serialization request synthesis and deserialization are attempted",
    target_fixture="invalid_session_failures",
)
def attempt_invalid_endpoint_session_boundaries(invalid_session_operations):
    failures = []
    for operation in invalid_session_operations:
        try:
            operation()
        except ValueError as error:
            failures.append("".join(traceback.format_exception(error)))
        else:
            raise AssertionError("invalid endpoint session association unexpectedly succeeded")
    return failures


@then("each invalid association fails without disclosing source content")
def invalid_associations_fail_without_disclosure(invalid_session_failures):
    assert len(invalid_session_failures) == 4
    for rendered in invalid_session_failures:
        assert "session binding is invalid" in rendered
        assert "private/session-reference" not in rendered
        assert "fixture-" not in rendered
