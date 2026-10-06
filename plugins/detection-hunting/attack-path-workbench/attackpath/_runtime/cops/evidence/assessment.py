"""Provider-independent receipt and observation assessment; reports omit payloads."""
import math

from .canonical import EvidenceError, timestamp
from .validation import validate_envelope, validate_receipt


def assess(envelope, receipt, *, as_of, max_age_seconds, max_bytes=1024 * 1024, max_depth=32):
    validate_envelope(envelope, max_bytes=max_bytes, max_depth=max_depth)
    validate_receipt(receipt)
    if (receipt["acquisition_id"] != envelope["acquisition_id"]
            or receipt["tenant"] != envelope["source"]["tenant"]
            or receipt["scope"] != envelope["source"]["scope"]
            or receipt["request_fingerprint"] != envelope["request_fingerprint"]):
        raise EvidenceError("acquisition_mismatch")
    if type(max_age_seconds) not in (int, float) or not math.isfinite(max_age_seconds) or max_age_seconds < 0:
        raise EvidenceError("invalid_limit")
    now = timestamp(as_of)
    observed = envelope["observed"]["at"]
    freshness = "unknown"
    if observed is not None:
        age = (now - timestamp(observed)).total_seconds()
        if age >= 0:
            freshness = "fresh" if age <= max_age_seconds else "stale"
    return {"completeness": receipt["status"], "freshness": freshness}


def report(envelopes, receipt, *, as_of, max_age_seconds, max_bytes=1024 * 1024, max_depth=32):
    validate_receipt(receipt)
    return {"acquisition_id": receipt["acquisition_id"], "status": receipt["status"],
            "records": [{"record_id": item["record_id"],
                         **assess(item, receipt, as_of=as_of, max_age_seconds=max_age_seconds,
                                  max_bytes=max_bytes, max_depth=max_depth)}
                        for item in envelopes]}
