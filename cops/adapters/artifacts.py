"""Fixed offline artifact adapters; these do not authorize active acquisition."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ArtifactAdapter:
    adapter_id: str
    formats: tuple[str, ...]
    platforms: tuple[str, ...]
    prerequisites: tuple[str, ...]
    max_bytes: int
    max_records: int
    deadline_seconds: int


ARTIFACT_ADAPTERS = MappingProxyType({
    "cryptographic-verification/v1": ArtifactAdapter(
        adapter_id="cryptographic-verification/v1", formats=("certificate_chain", "jwt_verification"),
        platforms=("linux", "darwin", "win32"), prerequisites=("cryptography==50.0.2",),
        max_bytes=256 * 1024, max_records=16, deadline_seconds=0,
    ),
    "raw-forensic-image/v1": ArtifactAdapter(
        adapter_id="raw-forensic-image/v1", formats=("raw disk image", "raw memory image"),
        platforms=("posix",), prerequisites=("python-stdlib",),
        max_bytes=128 * 1024 * 1024, max_records=128, deadline_seconds=0,
    ),
    "sysmon-evtx/v1": ArtifactAdapter(
        adapter_id="sysmon-evtx/v1", formats=("EVTX 3.1", "EVTX 3.2"),
        platforms=("linux",), prerequisites=("python-evtx==0.8.1", "hexdump==3.3"),
        max_bytes=8 * 1024 * 1024, max_records=4096, deadline_seconds=10,
    ),
})


def artifact_adapter(adapter_id: str) -> ArtifactAdapter:
    """Only reviewed built-ins are registered; no artifact can select executable code."""
    try:
        return ARTIFACT_ADAPTERS[adapter_id]
    except KeyError as exc:
        raise ValueError("unsupported artifact adapter") from exc
