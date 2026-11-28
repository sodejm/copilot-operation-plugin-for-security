"""Bounded read-only lookups; provider claims are never combined into a verdict."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit, urlunsplit

from cops.connectors.interfaces import Request
from cops.connectors.transport import HttpsTransport
from cops.evidence import EvidenceError

KINDS = {"ip", "domain", "url", "hash", "certificate", "email", "azure_application_id"}
MISP_TYPES = {
    "ip": "ip-src",
    "domain": "domain",
    "url": "url",
    "hash": "sha256",
    "certificate": "x509-fingerprint-sha256",
    "email": "email-src",
}
STIX_TYPES = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "certificate": "x509-certificate",
    "email": "email-addr",
}
MAX_BODY = 1_048_576
MAX_RETRY_AFTER = 86400
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
MARKING = re.compile(r"marking-definition--[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _domain(value, *, allow_single=False):
    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid_indicator") from None
    if not DOMAIN.fullmatch(canonical) and not (allow_single and LABEL.fullmatch(canonical)):
        raise ValueError("invalid_indicator")
    if "." in canonical and (len(canonical.rsplit(".", 1)[1]) < 2 or canonical.rsplit(".", 1)[1].isdecimal()):
        raise ValueError("invalid_indicator")
    return canonical


def _host(value):
    try:
        address = ipaddress.ip_address(value)
        return f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        return _domain(value, allow_single=True)


def _non_global_host(value):
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return "." not in value or value.endswith(".local")


def _retry_after_seconds(value, now):
    if not isinstance(value, str) or len(value) > 128:
        return 60
    value = value.strip()
    if value.isascii() and value.isdecimal():
        if len(value) > 5:
            return 60
        return max(1, min(int(value), MAX_RETRY_AFTER))
    try:
        deadline = parsedate_to_datetime(value)
        if deadline.tzinfo is None:
            return 60
        return max(1, min(math.ceil(deadline.timestamp() - now), MAX_RETRY_AFTER))
    except (TypeError, ValueError, OverflowError, IndexError):
        return 60


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str = field(repr=False)
    original_value: str = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if self.kind not in KINDS or not isinstance(self.value, str) or not 1 <= len(self.value) <= 2048:
            raise ValueError("invalid_indicator")
        value = self.value
        object.__setattr__(self, "original_value", value)
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid_indicator")
        try:
            if self.kind == "ip":
                ipaddress.ip_address(value)
            elif self.kind == "domain":
                object.__setattr__(self, "value", _domain(value))
            elif self.kind == "url":
                part = urlsplit(value)
                if (
                    part.scheme not in ("http", "https")
                    or not part.hostname
                    or part.username is not None
                    or part.password is not None
                    or part.fragment
                    or part.port not in (None, 80, 443)
                ):
                    raise ValueError
                host = _host(part.hostname)
                netloc = host + (f":{part.port}" if part.port is not None else "")
                object.__setattr__(self, "value", urlunsplit((part.scheme, netloc, part.path, part.query, "")))
            elif self.kind in ("hash", "certificate"):
                if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    raise ValueError
            elif self.kind == "email":
                if not re.fullmatch(r"[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}", value):
                    raise ValueError
            elif self.kind == "azure_application_id":
                if not re.fullmatch(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", value):
                    raise ValueError
        except (ValueError, UnicodeError):
            raise ValueError("invalid_indicator") from None

    @property
    def digest(self):
        return hashlib.sha256(f"{self.kind}\0{self.value}".encode()).hexdigest()

    @property
    def sensitive(self):
        if self.kind in ("email", "azure_application_id"):
            return True
        if self.kind == "ip":
            return _non_global_host(self.value)
        if self.kind == "url":
            part = urlsplit(self.value)
            return bool(part.path and part.path != "/" or part.query or _non_global_host(part.hostname))
        return False


@dataclass(frozen=True)
class Approval:
    source: str
    indicator_digest: str
    allow_sensitive: bool = False


@dataclass(frozen=True)
class Source:
    name: str
    origin: str
    path: str
    token: str = field(repr=False)

    def __post_init__(self):
        if self.name not in ("misp", "taxii", "microsoft"):
            raise ValueError("invalid_source")
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", self.origin) or self.origin.startswith(".") or ".." in self.origin:
            raise ValueError("invalid_source")
        if (
            not self.path.startswith("/")
            or "?" in self.path
            or "#" in self.path
            or ".." in self.path.split("/")
            or len(self.path) > 512
        ):
            raise ValueError("invalid_source")
        if self.name == "microsoft" and (
            self.origin != "graph.microsoft.com"
            or self.path not in ("/v1.0/security/threatIntelligence/hosts", "/v1.0/servicePrincipals")
        ):
            raise ValueError("invalid_source")
        if self.name == "misp" and self.path != "/attributes/restSearch":
            raise ValueError("invalid_source")
        if self.name == "taxii" and not re.fullmatch(r"/taxii2/collections/[A-Za-z0-9_-]{1,128}/objects/", self.path):
            raise ValueError("invalid_source")
        if not isinstance(self.token, str) or not self.token:
            raise ValueError("invalid_source")


class Cache:
    def __init__(self, positive_ttl=3600, negative_ttl=300, history_limit=100):
        if not all(type(v) is int and 1 <= v <= 86400 for v in (positive_ttl, negative_ttl)):
            raise ValueError("invalid_cache_ttl")
        if type(history_limit) is not int or not 1 <= history_limit <= 10000:
            raise ValueError("invalid_history_limit")
        self.positive_ttl, self.negative_ttl = positive_ttl, negative_ttl
        self.history_limit = history_limit
        self.entries = {}
        self.history = {}
        self.history_truncated = set()
        self.throttled_until = {}

    def get(self, key, now, allow_stale=False):
        item = self.entries.get(key)
        if item is None:
            return None
        result, expiry, _ = item
        if now >= expiry and not allow_stale:
            return None
        return {**deepcopy(result), "cache": "stale" if now >= expiry else "fresh"}

    def put(self, key, result, now):
        if result["status"] not in ("positive", "negative"):
            return
        ttl = self.positive_ttl if result["status"] == "positive" else self.negative_ttl
        item = (deepcopy({**result, "retrieved_at": _stamp(now), "expires_at": _stamp(now + ttl)}), now + ttl, now)
        if key not in self.entries or now >= self.entries[key][2]:
            self.entries[key] = item
        history = self.history.setdefault(key, [])
        history.append(item)
        if len(history) > self.history_limit:
            history.sort(key=lambda entry: entry[2])
            history.pop(0)
            self.history_truncated.add(key)

    def replay(self, key, as_of):
        history = self.history.get(key, [])
        eligible = [item for item in history if item[2] <= as_of]
        if not eligible:
            status = "history_unavailable" if key in self.history_truncated else "cache_miss"
            return {"status": status, "claims": [], "conflicts": [], "cache": None, "as_of": _stamp(as_of)}
        result, expiry, _ = max(enumerate(eligible), key=lambda entry: (entry[1][2], entry[0]))[1]
        return {**deepcopy(result), "cache": "stale" if as_of >= expiry else "fresh", "as_of": _stamp(as_of)}

    def rate_limit(self, scope, now, seconds):
        self.throttled_until[scope] = max(self.throttled_until.get(scope, 0), now + seconds)

    def retry_after(self, scope, now):
        return max(0, math.ceil(self.throttled_until.get(scope, 0) - now))


def _stamp(seconds):
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def _time(value):
    if type(value) in (int, float) or isinstance(value, str) and value.isdecimal():
        try:
            return _stamp(float(value))
        except (ValueError, OverflowError):
            return None
    if isinstance(value, str) and len(value) <= 40:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return None
            return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return None


def _seconds(value):
    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
        try:
            _stamp(value)
        except (ValueError, OverflowError, OSError):
            raise ValueError("invalid_time") from None
        return float(value)
    if isinstance(value, str):
        normalized = _time(value)
        if normalized is not None:
            return datetime.fromisoformat(normalized.replace("Z", "+00:00")).timestamp()
    raise ValueError("invalid_time")


def _restrictions(source, row):
    if source == "misp":
        distribution = row.get("distribution")
        valid_number = type(distribution) is int and 0 <= distribution <= 5
        valid_text = isinstance(distribution, str) and distribution in "012345"
        if valid_number or valid_text:
            return [f"misp:distribution:{distribution}"]
    if source == "taxii":
        markings = row.get("object_marking_refs")
        if (
            isinstance(markings, list)
            and 1 <= len(markings) <= 32
            and all(isinstance(item, str) and MARKING.fullmatch(item) for item in markings)
        ):
            return [f"stix:{item}" for item in sorted(set(markings))]
    return ["unknown"]


def _claim(source, assertion, observed, retrieved, restrictions, confidence=None, expiry=None, locator=None):
    return {
        "source": source,
        "assertion": assertion,
        "observed_at": _time(observed),
        "retrieved_at": _stamp(retrieved),
        "sharing_restrictions": restrictions,
        "confidence": confidence if type(confidence) in (int, float) and 0 <= confidence <= 100 else None,
        "expires_at": _time(expiry),
        "provenance": locator,
    }


def normalize(source, indicator, data, *, retrieved_at=None):
    """Return only claims matching the selected indicator, with bounded cardinality."""
    if not isinstance(data, dict):
        raise ValueError("schema_drift")
    retrieved = _seconds(time.time() if retrieved_at is None else retrieved_at)
    claims = []
    if source == "misp":
        rows = data.get("Attribute", data.get("response", {}).get("Attribute", []))
        if not isinstance(rows, list):
            raise ValueError("schema_drift")
        for row in rows[:1000]:
            if not isinstance(row, dict):
                continue
            try:
                matched = Indicator(indicator.kind, row.get("value")).value == indicator.value
            except (ValueError, TypeError):
                matched = False
            if not matched:
                continue
            if row.get("type") != MISP_TYPES.get(indicator.kind):
                continue
            claims.append(
                _claim(
                    "misp",
                    "malicious" if row.get("to_ids") is True else "context",
                    row.get("timestamp"),
                    retrieved,
                    _restrictions("misp", row),
                    locator=str(row.get("uuid", ""))[:128],
                )
            )
    elif source == "taxii":
        rows = data.get("objects")
        if not isinstance(rows, list):
            raise ValueError("schema_drift")
        for row in rows[:1000]:
            if not isinstance(row, dict) or row.get("type") != "indicator":
                continue
            pattern = row.get("pattern")
            stix = (
                "ipv6-addr"
                if indicator.kind == "ip" and ipaddress.ip_address(indicator.value).version == 6
                else STIX_TYPES.get(indicator.kind)
            )
            # Only exact simple STIX comparison patterns are treated as a match.
            if stix in ("file", "x509-certificate"):
                expected = f"[{stix}:hashes.'SHA-256' = '{indicator.value}']"
            else:
                expected = f"[{stix}:value = '{indicator.value.replace(chr(39), chr(92) + chr(39))}']"
            if pattern != expected:
                continue
            claims.append(
                _claim(
                    "taxii",
                    "indicator",
                    row.get("modified", row.get("created")),
                    retrieved,
                    _restrictions("taxii", row),
                    row.get("confidence"),
                    row.get("valid_until"),
                    str(row.get("id", ""))[:128],
                )
            )
    elif source == "microsoft":
        if indicator.kind == "azure_application_id":
            if data.get("appId", "").lower() != indicator.value.lower() or not isinstance(data.get("id"), str):
                raise ValueError("schema_drift")
            claims.append(
                _claim("microsoft", "tenant_service_principal", None, retrieved, ["unknown"], locator=data["id"][:128])
            )
        else:
            if data.get("host") != indicator.value and data.get("id") != indicator.value:
                raise ValueError("schema_drift")
            claims.append(
                _claim(
                    "microsoft",
                    "host_record",
                    data.get("lastSeenDateTime"),
                    retrieved,
                    ["unknown"],
                    locator=str(data.get("id", ""))[:128],
                )
            )
    else:
        raise ValueError("invalid_source")
    return claims


def conflicts(claims):
    assertions = {claim["assertion"] for claim in claims}
    return (
        [{"assertions": sorted(assertions), "sources": sorted({c["source"] for c in claims})}]
        if "malicious" in assertions and "context" in assertions
        else []
    )


def _request(source, indicator):
    if source.name == "misp":
        body = json.dumps(
            {"type": MISP_TYPES[indicator.kind], "value": indicator.value, "limit": 1000}, separators=(",", ":")
        ).encode()
        return Request(
            "POST",
            f"https://{source.origin}{source.path}",
            body,
            {"Authorization": source.token, "Content-Type": "application/json", "Accept": "application/json"},
        )
    if source.name == "taxii":
        return Request(
            "GET",
            f"https://{source.origin}{source.path}?limit=1000",
            headers={"Authorization": f"Bearer {source.token}", "Accept": "application/taxii+json;version=2.1"},
        )
    return Request(
        "GET",
        f"https://{source.origin}{_microsoft_path(source, indicator)}",
        headers={"Authorization": f"Bearer {source.token}", "Accept": "application/json"},
    )


def _microsoft_path(source, indicator):
    if indicator.kind == "azure_application_id":
        return f"{source.path}(appId='{indicator.value.lower()}')"
    return f"{source.path}/{quote(indicator.value, safe='')}"


def enrich(
    indicator,
    source,
    approval,
    *,
    cache=None,
    transport_factory=HttpsTransport,
    now=None,
    cache_only=False,
    allow_stale=False,
    as_of=None,
):
    """A privacy decision precedes every outbound lookup; no provider data is executed."""
    if not isinstance(indicator, Indicator) or not isinstance(source, Source):
        raise ValueError("invalid_input")
    if (
        not isinstance(approval, Approval)
        or approval.source != source.name
        or approval.indicator_digest != indicator.digest
        or indicator.sensitive
        and not approval.allow_sensitive
    ):
        return {"status": "privacy_denied", "claims": [], "conflicts": [], "cache": None}
    microsoft_supported = (source.path == "/v1.0/servicePrincipals" and indicator.kind == "azure_application_id") or (
        source.path == "/v1.0/security/threatIntelligence/hosts" and indicator.kind in ("ip", "domain")
    )
    if (
        source.name == "microsoft"
        and not microsoft_supported
        or source.name == "misp"
        and indicator.kind not in MISP_TYPES
        or source.name == "taxii"
        and indicator.kind not in STIX_TYPES
    ):
        return {"status": "unsupported", "claims": [], "conflicts": [], "cache": None}
    now = _seconds(time.time() if now is None else now)
    if as_of is not None:
        as_of = _seconds(as_of)
    cache = cache if cache is not None else Cache()
    # A shared in-memory cache must never return one credential scope's result
    # to another; retain only a digest of the credential in the cache key.
    key = (source.name, source.origin, source.path, hashlib.sha256(source.token.encode()).hexdigest(), indicator.digest)
    if as_of is not None:
        return cache.replay(key, as_of)
    cached = cache.get(key, now, allow_stale=cache_only and allow_stale)
    if cached is not None:
        return cached
    if cache_only:
        return {"status": "cache_miss", "claims": [], "conflicts": [], "cache": None}
    scope = key[:-1]
    remaining = cache.retry_after(scope, now)
    if remaining:
        return {
            "status": "error",
            "error": "rate_limited",
            "retry_after_seconds": remaining,
            "claims": [],
            "conflicts": [],
            "cache": None,
        }
    request = _request(source, indicator)
    path = _microsoft_path(source, indicator) if source.name == "microsoft" else source.path
    transport = transport_factory(source.origin, path, request.method)
    for attempt in range(3):
        try:
            response = transport.send(request, {}, timeout=10, max_bytes=MAX_BODY)
        except EvidenceError as error:
            if error.code in ("request_timeout", "transport") and attempt < 2:
                continue
            return {"status": "error", "error": error.code, "claims": [], "conflicts": [], "cache": None}
        if response.status == 429 or response.status == 503 and response.retry_after is not None:
            seconds = _retry_after_seconds(response.retry_after, now)
            cache.rate_limit(scope, now, seconds)
            return {
                "status": "error",
                "error": "rate_limited",
                "retry_after_seconds": seconds,
                "claims": [],
                "conflicts": [],
                "cache": None,
            }
        if response.status in (500, 502, 503, 504) and attempt < 2:
            continue
        if response.status == 404 and source.name == "microsoft":
            result = {"status": "negative", "claims": [], "conflicts": [], "cache": None}
        elif response.status != 200:
            return {"status": "error", "error": f"http_{response.status}", "claims": [], "conflicts": [], "cache": None}
        else:
            try:
                data = json.loads(response.body)
                if (
                    source.name == "taxii"
                    and data.get("more") is True
                    or source.name == "misp"
                    and len(data.get("Attribute", [])) >= 1000
                ):
                    return {
                        "status": "partial",
                        "error": "pagination_limit",
                        "claims": normalize(source.name, indicator, data, retrieved_at=now),
                        "conflicts": [],
                        "cache": None,
                    }
                claims = normalize(source.name, indicator, data, retrieved_at=now)
            except (ValueError, UnicodeDecodeError, TypeError, AttributeError):
                return {"status": "error", "error": "schema_drift", "claims": [], "conflicts": [], "cache": None}
            result = {
                "status": "positive" if claims else "negative",
                "claims": claims,
                "conflicts": conflicts(claims),
                "cache": None,
            }
        cache.put(key, result, now)
        return {
            **result,
            "retrieved_at": _stamp(now),
            "expires_at": _stamp(now + (cache.positive_ttl if result["status"] == "positive" else cache.negative_ttl)),
        }
    return {"status": "error", "error": "retry_exhausted", "claims": [], "conflicts": [], "cache": None}
