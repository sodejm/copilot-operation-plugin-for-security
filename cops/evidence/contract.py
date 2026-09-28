"""Immutable-by-export envelopes with tenant-bound, content-derived identities."""
from .canonical import digest
from .validation import validate_envelope


def build_envelope(*, acquisition_id, product, api, tenant, scope, identity, locator,
                   payload, acquired_at, transformed_at, request_fingerprint, page,
                   observed_at=None, emitted_at=None, region=None, source_version=None,
                   parents=None, raw_reference=None, max_bytes=1024 * 1024, max_depth=32):
    # Serialize/deserialize to detach caller-owned mutable structures.
    from .canonical import canonical, decode_json
    payload = decode_json(canonical(payload, max_bytes=max_bytes, max_depth=max_depth),
                          max_bytes=max_bytes, max_depth=max_depth)
    scope = sorted(set(scope))
    record_id = digest(["cops.record/v1", product, tenant, scope, identity, source_version,
                        digest(payload, max_bytes=max_bytes, max_depth=max_depth)], max_bytes=max_bytes)
    result = {
        "schema_version": "cops.evidence/v1", "acquisition_id": acquisition_id,
        "record_id": record_id,
        "source": {"product": product, "api": api, "tenant": tenant, "scope": scope,
                   "region": {"value": region, "unknown_reason": "not_available" if region is None else None},
                   "identity": identity, "locator": locator, "version": source_version},
        "observed": {"at": observed_at, "unknown_reason": "not_available" if observed_at is None else None},
        "emitted": {"at": emitted_at, "unknown_reason": "not_available" if emitted_at is None else None},
        "acquired_at": acquired_at, "transformed_at": transformed_at,
        "request_fingerprint": request_fingerprint, "page": page,
        "normalization": ["projection/v1"], "redaction": ["omit-unselected-fields/v1"],
        "sensitivity": "restricted", "payload": payload,
        "parents": list(parents or []), "raw_reference": raw_reference,
    }
    result["content_hash"] = digest(result, max_bytes=max_bytes, max_depth=max_depth)
    return validate_envelope(result, max_bytes=max_bytes, max_depth=max_depth)
