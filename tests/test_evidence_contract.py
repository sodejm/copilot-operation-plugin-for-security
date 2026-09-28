"""Behavior-first tests for shared provenance and integrity."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cops.evidence import EvidenceError, assess, build_envelope, canonical, decode_json, validate_envelope


def envelope(**changes):
    args = dict(acquisition_id="collection-1", product="graph", api="v1.0/users",
                tenant="tenant-1", scope=["users"], identity="user-1", locator="user-1",
                payload={"id": "user-1"}, acquired_at="2026-09-28T00:00:00Z",
                transformed_at="2026-09-28T00:00:00Z", request_fingerprint="a" * 64,
                page=1)
    args.update(changes)
    return build_envelope(**args)


def receipt(**changes):
    result = dict(schema_version="cops.acquisition/v1", acquisition_id="collection-1",
                  generation=1, adapter="test", adapter_version="1", tenant="tenant-1",
                  scope=["users"], request_fingerprint="a" * 64,
                  started_at="2026-09-28T00:00:00Z", finished_at="2026-09-28T00:00:00Z",
                  status="partial", reasons=["record_limit"], consistency="unknown",
                  limits=dict(pages=10, attempts=10, records=10, response_bytes=1024,
                              total_bytes=10240, record_bytes=1024, storage_bytes=10240,
                              depth=32, request_seconds=10, active_seconds=100, retries=1),
                  consumed=dict(pages=1, attempts=1, records=1, duplicates=0, bytes=100,
                                storage_bytes=100, active_seconds=1))
    result.update(changes)
    return result


def test_round_trip_and_identity_scope():
    item = envelope()
    validate_envelope(decode_json(json.dumps(item).encode()))
    assert item["record_id"] == envelope()["record_id"]
    assert item["record_id"] != envelope(tenant="tenant-2")["record_id"]
    assert item["record_id"] != envelope(payload={"id": "changed"})["record_id"]


@pytest.mark.parametrize("field,value", [("schema_version", "v99"), ("acquired_at", "yesterday"),
                                         ("acquired_at", "2026-09-28T00:00:00"), ("source", {})])
def test_reject_malformed_contract(field, value):
    item = envelope()
    item[field] = value
    with pytest.raises(EvidenceError):
        validate_envelope(item)


def test_integrity_and_payload_limit():
    item = envelope()
    item["payload"]["id"] = "tampered"
    with pytest.raises(EvidenceError, match="integrity"):
        validate_envelope(item)
    with pytest.raises(EvidenceError):
        envelope(payload={"id": "x" * 1024}, max_bytes=512)


@pytest.mark.parametrize("payload", [
    ["x" * 512] * 16,
    {str(index) + "x" * 512: None for index in range(16)},
    1 << 65536,
], ids=["repeated_strings", "large_keys", "large_integer"])
def test_oversize_payload_rejected_before_serialization(monkeypatch, payload):
    def unexpected_serialization(*_args, **_kwargs):
        pytest.fail("oversize payload reached JSON serialization")

    monkeypatch.setattr(json, "dumps", unexpected_serialization)
    with pytest.raises(EvidenceError, match="payload_limit"):
        canonical(payload, max_bytes=4096)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[[[[0]]]]'])
def test_bounded_json(raw):
    with pytest.raises(EvidenceError):
        decode_json(raw, max_depth=3)


def test_freshness_does_not_invent_observation_time():
    acquisition = receipt()
    assert assess(envelope(), acquisition, as_of="2026-09-28T00:10:00Z", max_age_seconds=60) == {
        "completeness": "partial", "freshness": "unknown"}
    item = envelope(observed_at="2026-09-27T00:00:00Z")
    assert assess(item, acquisition, as_of="2026-09-28T00:00:00Z", max_age_seconds=60)["freshness"] == "stale"


def test_assessment_rejects_incomplete_receipt_before_claiming_completion():
    with pytest.raises(EvidenceError, match="missing_provenance"):
        assess(envelope(), {"status": "complete"}, as_of="2026-09-28T00:10:00Z", max_age_seconds=60)


@pytest.mark.parametrize("changes", [{"acquisition_id": "collection-2"}, {"tenant": "tenant-2"},
                                      {"scope": ["resources"]}, {"request_fingerprint": "b" * 64}])
def test_assessment_rejects_receipt_from_another_query(changes):
    with pytest.raises(EvidenceError, match="acquisition_mismatch"):
        assess(envelope(), receipt(**changes), as_of="2026-09-28T00:10:00Z", max_age_seconds=60)


def test_explicit_depth_budget_applies_to_integrity_and_assessment():
    payload = {"id": "user-1"}
    for _ in range(40):
        payload = {"nested": payload}
    item = envelope(payload=payload, max_depth=64)
    validate_envelope(item, max_depth=64)
    assert assess(item, receipt(), as_of="2026-09-28T00:10:00Z",
                  max_age_seconds=60, max_depth=64)["freshness"] == "unknown"
