"""Measure complete TCP-port coverage in a disposable loopback-only Linux namespace."""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import time
from pathlib import Path

from cops.discovery import ActiveScanner, ActiveScanSession, ScanBudget
from cops.discovery.active_scanner import StandardSocketDispatcher


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_isolated_network() -> None:
    require(sys.platform == "linux", "A Linux network namespace is required")
    interfaces = {name for _, name in socket.if_nameindex()}
    require(interfaces == {"lo"}, f"Expected only loopback, found {sorted(interfaces)}")


def main() -> None:
    require_isolated_network()
    ports = list(range(1, 65536))
    session = ActiveScanSession(
        session_id="full-tcp-loopback",
        scope_reference="disposable-loopback-acceptance",
        approved_targets=["127.0.0.1"],
        approved_ports=ports,
        budget=ScanBudget(
            timeout_seconds=0.05,
            max_total_seconds=120.0,
            rate_limit_pps=1_000_000.0,
            max_targets=1,
            max_probes=len(ports),
            max_concurrency=1,
        ),
    )
    temp_root: Path | None = None
    with tempfile.TemporaryDirectory(prefix="cops-full-tcp-") as directory:
        temp_root = Path(directory)
        checkpoint = temp_root / "session.json"
        started = time.monotonic()
        result = ActiveScanner(
            session,
            StandardSocketDispatcher(),
            checkpoint=checkpoint,
            scope={"ip_ranges": ["127.0.0.1/32"]},
        ).run()
        elapsed = time.monotonic() - started
        coverage = result.coverage_summary()
        require(result.status == "completed", f"Unexpected status: {result.status}")
        require(coverage["planned"] == len(ports), f"Unexpected planned coverage: {coverage}")
        require(coverage["attempted"] == len(ports), f"Unexpected attempted coverage: {coverage}")
        require(coverage["completed"] == len(ports), f"Unexpected completed coverage: {coverage}")
        require(coverage["pending_reconciliation"] == 0, f"Pending probes remain: {coverage}")
        require(coverage["skipped"]["total"] == 0, f"Skipped probes remain: {coverage}")
        require(coverage["unassessed"] == 0, f"Unassessed probes remain: {coverage}")
        require({assessment.port for assessment in result.assessments} == set(ports), "Port coverage is incomplete")

        reloaded = ActiveScanSession.load_checkpoint(checkpoint)
        reload_equal = reloaded.to_dict() == result.to_dict()
        journal_retired = not ActiveScanSession.checkpoint_journal_path(checkpoint).exists()
        checkpoint_bytes = checkpoint.stat().st_size
        require(reload_equal, "Reloaded checkpoint differs from completed session")
        require(journal_retired, "Completed checkpoint journal was not retired")

    require(temp_root is not None and not temp_root.exists(), "Temporary checkpoint directory was not removed")
    print(
        json.dumps(
            {
                "checkpoint_bytes": checkpoint_bytes,
                "checkpoint_reload_equal": reload_equal,
                "cleanup": "complete",
                "coverage": coverage,
                "elapsed_seconds": round(elapsed, 3),
                "isolation": "linux-loopback-only",
                "journal_retired": journal_retired,
                "port_states": coverage["port_states"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
