#!/usr/bin/env python3
"""Run an offline playback across provider, cache, and failure paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Repository path setup precedes standalone entry point imports.
# ruff: noqa: E402
ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_intel import Approval, Cache, Indicator, Source, enrich

from cops.connectors.interfaces import Response


class PlaybackError(RuntimeError):
    """Raised when synthetic playback evidence violates its contract."""


def require(condition: bool, message: str) -> None:
    """Fail closed even when Python runs with optimization enabled."""
    if not condition:
        raise PlaybackError(message)


class ResponseSequence:
    """Inject fixed responses while recording each attempted request."""

    def __init__(self, responses: list[Response]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def factory(self, origin: str, path: str, method: str) -> ResponseSequence:
        self.origin = origin
        self.path = path
        self.method = method
        return self

    def send(self, request: object, headers: dict, *, timeout: float, max_bytes: int) -> Response:
        self.requests.append(
            {
                "origin": self.origin,
                "path": self.path,
                "method": self.method,
                "timeout": timeout,
                "max_bytes": max_bytes,
            }
        )
        if not self.responses:
            raise PlaybackError("playback attempted an unplanned request")
        return self.responses.pop(0)


def approved(indicator: Indicator, source: Source) -> Approval:
    return Approval(source=source.name, indicator_digest=indicator.digest)


def main() -> int:
    now = 1_700_000_100
    indicator = Indicator("domain", "example.org")
    cache = Cache(positive_ttl=10, negative_ttl=5)
    misp = Source("misp", "misp.example.org", "/attributes/restSearch", "synthetic-token")
    misp_transport = ResponseSequence(
        [
            Response(
                200,
                json.dumps(
                    {
                        "Attribute": [
                            {
                                "type": "domain",
                                "value": "example.org",
                                "to_ids": True,
                                "timestamp": "1700000000",
                                "distribution": 0,
                                "uuid": "synthetic-malicious",
                            },
                            {
                                "type": "domain",
                                "value": "example.org",
                                "to_ids": False,
                                "timestamp": "1700000001",
                                "distribution": 1,
                                "uuid": "synthetic-context",
                            },
                        ]
                    }
                ).encode(),
            )
        ]
    )
    initial = enrich(
        indicator,
        misp,
        approved(indicator, misp),
        cache=cache,
        transport_factory=misp_transport.factory,
        now=now,
    )
    fresh = enrich(indicator, misp, approved(indicator, misp), cache=cache, cache_only=True, now=now + 5)
    stale = enrich(
        indicator,
        misp,
        approved(indicator, misp),
        cache=cache,
        cache_only=True,
        allow_stale=True,
        now=now + 11,
    )
    replay = enrich(
        indicator,
        misp,
        approved(indicator, misp),
        cache=cache,
        cache_only=True,
        now=now + 11,
        as_of=now + 5,
    )

    marking = "marking-definition--11111111-1111-1111-1111-111111111111"
    taxii = Source("taxii", "taxii.example.org", "/taxii2/collections/demo/objects/", "synthetic-token")
    taxii_transport = ResponseSequence(
        [
            Response(
                200,
                json.dumps(
                    {
                        "more": True,
                        "objects": [
                            {
                                "type": "indicator",
                                "id": "indicator--11111111-1111-4111-8111-111111111111",
                                "pattern": "[domain-name:value = 'example.org']",
                                "created": "2023-11-14T22:00:00Z",
                                "confidence": 70,
                                "object_marking_refs": [marking],
                            }
                        ],
                    }
                ).encode(),
            )
        ]
    )
    taxii_partial = enrich(
        indicator,
        taxii,
        approved(indicator, taxii),
        transport_factory=taxii_transport.factory,
        now=now,
    )

    microsoft = Source("microsoft", "graph.microsoft.com", "/v1.0/security/threatIntelligence/hosts", "synthetic-token")
    microsoft_transport = ResponseSequence([Response(503, b"{}"), Response(503, b"{}"), Response(503, b"{}")])
    microsoft_failure = enrich(
        indicator,
        microsoft,
        approved(indicator, microsoft),
        transport_factory=microsoft_transport.factory,
        now=now,
    )

    require(initial["status"] == "positive" and bool(initial["conflicts"]), "MISP conflict evidence missing")
    require(
        fresh["cache"] == "fresh" and stale["cache"] == "stale" and replay["cache"] == "fresh",
        "cache freshness or as-of replay evidence is invalid",
    )
    require(
        taxii_partial["status"] == "partial" and taxii_partial["error"] == "pagination_limit",
        "TAXII partial-result evidence missing",
    )
    require(
        microsoft_failure["status"] == "error" and microsoft_failure["error"] == "http_503",
        "Microsoft retry-exhaustion evidence missing",
    )
    result = {
        "schema": "cops.threat-intelligence-playback/v1",
        "network_mode": "injected-mock-only",
        "live_integrations_validated": False,
        "request_attempts": {
            "misp": len(misp_transport.requests),
            "taxii": len(taxii_transport.requests),
            "microsoft": len(microsoft_transport.requests),
        },
        "misp": {
            "initial": initial,
            "fresh_cache": fresh,
            "stale_cache": stale,
            "as_of_replay": replay,
        },
        "taxii_partial": taxii_partial,
        "microsoft_failure": microsoft_failure,
    }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
