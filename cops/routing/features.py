"""Deterministic, privacy-preserving feature extraction for specialist routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any


@dataclass(frozen=True)
class RoutingFeatures:
    """Feature labels and counts without raw identifiers or prompt content."""

    labels: tuple[str, ...]
    counts: tuple[tuple[str, int], ...]

    def redacted_dict(self) -> dict[str, Any]:
        return {"labels": list(self.labels), "counts": dict(self.counts)}


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    ("ipv4_address", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    ("ipv6_address", re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)),
    ("url", re.compile(r"\bhttps?://[^\s<>]+", re.IGNORECASE)),
    ("email_address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)),
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)),
    ("aws_account_id", re.compile(r"\b(?:aws(?: account)?[ :=-]*)\d{12}\b", re.IGNORECASE)),
    (
        "azure_subscription_id",
        re.compile(r"\b(?:subscription(?: id)?[ :=-]*)[0-9a-f]{8}-[0-9a-f-]{27,36}\b", re.IGNORECASE),
    ),
    (
        "gcp_project_id",
        re.compile(r"\b(?:gcp|google cloud|project(?: id)?)[ :=-]+[a-z][a-z0-9-]{4,28}[a-z0-9]\b", re.IGNORECASE),
    ),
)

_FILE_FORMATS = {
    ".evtx": "evtx_file",
    ".pcap": "pcap_file",
    ".pcapng": "pcap_file",
    ".har": "har_file",
    ".json": "json_file",
    ".yaml": "yaml_file",
    ".yml": "yaml_file",
    ".tf": "terraform_file",
    ".tfplan": "terraform_plan",
    ".sarif": "sarif_file",
    ".spdx": "sbom_file",
    ".cyclonedx": "sbom_file",
    ".exe": "binary_file",
    ".dll": "binary_file",
}


def extract_routing_features(text: str) -> RoutingFeatures:
    """Extract only routing-safe categories and counts from untrusted prompt text."""
    counts: dict[str, int] = {}
    for label, pattern in _PATTERNS:
        count = len(pattern.findall(text))
        if count:
            counts[label] = count

    lowered = text.lower()
    if re.search(r"\b(?:securityevent|deviceprocessevents|union|summarize|project)\b.*\|", lowered):
        counts["kql_query"] = 1
    if all(marker in lowered for marker in ("logsource:", "detection:", "condition:")):
        counts["sigma_rule"] = 1

    for candidate in re.findall(r"(?<!\S)([^\s<>]+)(?=\s|$)", lowered):
        label = _FILE_FORMATS.get(PurePath(candidate.strip("'\".,:;()[]{}")).suffix)
        if label:
            counts[label] = counts.get(label, 0) + 1

    return RoutingFeatures(labels=tuple(sorted(counts)), counts=tuple(sorted(counts.items())))
