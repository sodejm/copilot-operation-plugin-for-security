"""Fail-closed gate for discovery operations that would perform live network I/O."""

LIVE_DISCOVERY_UNAVAILABLE = (
    "Unauthenticated live discovery is unavailable; use the plan-bound service-validation laboratory"
)


def reject_unauthorized_live_discovery(
    *, mode: str | None = None, collector: object | None = None, offline_collector_type: type | None = None
) -> None:
    """Reject live discovery and collectors outside the exact trusted offline implementation."""
    if mode == "live":
        raise ValueError(LIVE_DISCOVERY_UNAVAILABLE)
    if collector is not None and (offline_collector_type is None or type(collector) is not offline_collector_type):
        raise ValueError(LIVE_DISCOVERY_UNAVAILABLE)
