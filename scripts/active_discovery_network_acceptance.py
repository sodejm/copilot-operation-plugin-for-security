"""Run bounded active-discovery acceptance cases inside a loopback-only Linux namespace.

Run through the documented Docker command. This module fails closed if any
non-loopback interface is present and uses only ephemeral TCP listeners.
"""

from __future__ import annotations

import errno
import json
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from cops.discovery import (
    ActiveScanner,
    ActiveScanSession,
    PortState,
    ScanBudget,
    ServiceReachability,
    compare_active_scans,
)
from cops.discovery.active_scanner import StandardSocketDispatcher


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def require_isolated_network() -> None:
    require(sys.platform == "linux", "A Linux network namespace is required")
    interfaces = {name for _, name in socket.if_nameindex()}
    require(interfaces == {"lo"}, f"Expected only loopback, found {sorted(interfaces)}")


@contextmanager
def listener(address: str = "127.0.0.1"):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((address, 0))
        server.listen(8)
        yield server
    finally:
        server.close()


def accepted_count(server: socket.socket) -> int:
    server.settimeout(0.01)
    count = 0
    while True:
        try:
            connection, _ = server.accept()
        except TimeoutError:
            break
        with connection:
            count += 1
    return count


def session(name: str, host: str, ports: list[int], budget: ScanBudget | None = None) -> ActiveScanSession:
    return ActiveScanSession(
        session_id=name,
        scope_reference="disposable-loopback-acceptance",
        approved_targets=[host],
        approved_ports=ports,
        budget=budget or ScanBudget(timeout_seconds=0.3, rate_limit_pps=100, max_total_seconds=60),
    )


def scan(
    scan_session: ActiveScanSession,
    dispatcher: StandardSocketDispatcher | None = None,
    ip_range: str = "127.0.0.1/32",
    checkpoint: Path | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> ActiveScanSession:
    if checkpoint is None:
        with tempfile.TemporaryDirectory() as temp_dir:
            return scan(scan_session, dispatcher, ip_range, Path(temp_dir) / "checkpoint.json", sleeper)
    return ActiveScanner(
        session=scan_session,
        dispatcher=dispatcher or StandardSocketDispatcher(),
        scope={"ip_ranges": [ip_range]},
        checkpoint=checkpoint,
        sleeper=sleeper,
    ).run()


class TimedDispatcher(StandardSocketDispatcher):
    def __init__(self) -> None:
        self.dispatch_times: list[float] = []

    def dispatch_probe(self, *args, **kwargs):
        self.dispatch_times.append(time.monotonic())
        return super().dispatch_probe(*args, **kwargs)


class ShiftedResolver(StandardSocketDispatcher):
    """Ask the disposable UDP DNS responder before each real TCP probe."""

    def __init__(self, dns_port: int) -> None:
        self.dns_port = dns_port
        self.resolutions: list[str] = []
        self.dispatched_ports: list[int] = []

    def resolve_target(self, target_host: str) -> str:
        require(target_host == "service.acceptance.test", "Unexpected hostname")
        qname = b"\x07service\x0aacceptance\x04test\x00"
        query = struct.pack("!HHHHHH", 0x212, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.3)
            client.sendto(query, ("127.0.0.1", self.dns_port))
            response, _ = client.recvfrom(512)
        require(
            response[:2] == query[:2] and len(response) >= len(query) + 16, "DNS responder returned an invalid answer"
        )
        resolved_ip = socket.inet_ntoa(response[-4:])
        self.resolutions.append(resolved_ip)
        return resolved_ip

    def dispatch_probe(self, *args, **kwargs):
        self.dispatched_ports.append(kwargs["port"])
        return super().dispatch_probe(*args, **kwargs)


class ShiftedDnsServer(socketserver.UDPServer):
    allow_reuse_address = False

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), self.Answer)
        self.answers = iter(("127.0.0.1", "127.0.0.2"))
        self.answer_count = 0

    class Answer(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            query, reply_socket = self.request
            require(
                query[12:] == b"\x07service\x0aacceptance\x04test\x00\x00\x01\x00\x01",
                "DNS responder received an unexpected question",
            )
            answer_ip = next(self.server.answers)
            self.server.answer_count += 1
            response = (
                query[:2]
                + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                + query[12:]
                + b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 0, 4)
                + socket.inet_aton(answer_ip)
            )
            reply_socket.sendto(response, self.client_address)


@contextmanager
def shifted_dns_server():
    server = ShiftedDnsServer()
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def check_rate_limit() -> dict[str, object]:
    with listener() as first, listener() as second:
        ports = [first.getsockname()[1], second.getsockname()[1]]
        dispatcher = TimedDispatcher()
        result = scan(
            session(
                "rate-limit",
                "127.0.0.1",
                ports,
                ScanBudget(timeout_seconds=0.3, rate_limit_pps=5, max_total_seconds=60),
            ),
            dispatcher,
        )
        spacing = dispatcher.dispatch_times[1] - dispatcher.dispatch_times[0]
        accepted = [accepted_count(first), accepted_count(second)]
        require(result.status == "completed", "Rate-limited scan did not complete")
        require(
            [a.port_state for a in result.assessments] == [PortState.OPEN.value] * 2,
            "Rate-limited probes did not reach both listeners",
        )
        require(accepted == [1, 1], "Rate-limited scan sent an unexpected number of connections")
        require(spacing >= 0.19, "Five-probes-per-second budget was not enforced")
        return {
            "minimum_spacing_ms": 200,
            "observed_spacing_ms": round(spacing * 1000, 1),
            "listener_accepts": accepted,
            "states": [a.port_state for a in result.assessments],
        }


def check_unreachable() -> dict[str, object]:
    with listener() as closed_socket:
        closed_port = closed_socket.getsockname()[1]
    unreachable = scan(session("unreachable", "198.51.100.1", [closed_port]), ip_range="198.51.100.1/32")
    closed = scan(session("closed-control", "127.0.0.1", [closed_port]))
    remote_result = unreachable.assessments[0]
    local_result = closed.assessments[0]
    require(
        remote_result.port_state == PortState.UNREACHABLE.value, "No-route target was not classified as unreachable"
    )
    require(
        remote_result.reachability == ServiceReachability.UNREACHABLE.value,
        "No-route target reachability was misclassified",
    )
    require(local_result.port_state == PortState.CLOSED.value, "Closed loopback control was not classified as closed")
    require(
        local_result.reachability == ServiceReachability.REACHABLE.value,
        "Closed loopback control reachability was misclassified",
    )
    require(
        str(errno.ENETUNREACH) in (remote_result.error_message or ""),
        "No-route case did not produce the expected kernel error",
    )
    return {
        "no_route_errno": errno.ENETUNREACH,
        "no_route_state": remote_result.port_state,
        "closed_control_state": local_result.port_state,
    }


def check_dns_shift() -> dict[str, object]:
    with listener("127.0.0.1") as approved, listener("127.0.0.2") as shifted, shifted_dns_server() as dns:
        first_port = approved.getsockname()[1]
        second_port = shifted.getsockname()[1]
        with socket.create_connection(("127.0.0.2", second_port), timeout=0.3):
            pass
        require(accepted_count(shifted) == 1, "Shifted-address listener is not reachable")
        dispatcher = ShiftedResolver(dns.server_address[1])
        result = scan(session("dns-shift", "service.acceptance.test", [first_port, second_port]), dispatcher)
        require(dispatcher.dispatched_ports == [first_port], "Probe escaped after resolver shift")
        require(
            dns.answer_count == 2 and dispatcher.resolutions == ["127.0.0.1", "127.0.0.2"],
            "Scanner did not observe both live DNS answers",
        )
        require(accepted_count(approved) == 1, "Approved listener was not reached")
        require(accepted_count(shifted) == 0, "Shifted listener received a scanner connection")
        require(len(result.quarantined_targets) == 1, "Resolver shift was not quarantined")
        quarantine = result.quarantined_targets[0]
        require(
            quarantine.original_ip == "127.0.0.1" and quarantine.new_ip == "127.0.0.2",
            "Quarantine did not record both addresses",
        )
        return {
            "resolution_sequence": [quarantine.original_ip, quarantine.new_ip],
            "dns_answers": dns.answer_count,
            "scanner_probe_count": result.total_probes_dispatched,
            "shifted_listener_scanner_accepts": 0,
            "quarantine_reason": quarantine.reason,
        }


def check_partial_resume() -> dict[str, object]:
    with listener() as first, listener() as second, tempfile.TemporaryDirectory() as temp_dir:
        ports = [first.getsockname()[1], second.getsockname()[1]]
        checkpoint = Path(temp_dir) / "checkpoint.json"

        def interrupt_after_first(_: float) -> None:
            raise KeyboardInterrupt("simulated controller interruption after durable probe result")

        try:
            scan(
                session(
                    "partial-resume",
                    "127.0.0.1",
                    ports,
                    ScanBudget(timeout_seconds=0.3, max_total_seconds=2.0, rate_limit_pps=5),
                ),
                checkpoint=checkpoint,
                sleeper=interrupt_after_first,
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("Controller interruption did not stop scan")
        partial = ActiveScanSession.load_checkpoint(checkpoint)
        require(partial.status == "in_progress", "Interrupted scan did not retain progress")
        require(not partial.pending_probe_keys, "Completed probe left an uncertain pending operation")
        require(partial.total_probes_dispatched == 1, "Interrupted scan dispatched too many probes")
        interrupted_status = partial.status
        completed = scan(partial, checkpoint=checkpoint)
        accepted = [accepted_count(first), accepted_count(second)]
        require(completed.status == "completed", "Resumed scan did not complete")
        require(completed.total_probes_dispatched == 2, "Resumed scan did not cover both ports")
        require(accepted == [1, 1], "Resume repeated or skipped a socket connection")
        return {
            "partial_status": interrupted_status,
            "partial_probes": 1,
            "resumed_status": completed.status,
            "total_probes": completed.total_probes_dispatched,
            "listener_accepts": accepted,
        }


def check_remediation() -> dict[str, object]:
    with listener() as persistent:
        persistent_port = persistent.getsockname()[1]
        with listener() as removed:
            removed_port = removed.getsockname()[1]
            baseline = scan(session("remediation-baseline", "127.0.0.1", [persistent_port, removed_port]))
            require(
                [a.port_state for a in baseline.assessments] == [PortState.OPEN.value] * 2,
                "Baseline did not prove both listeners open",
            )
            require(accepted_count(removed) == 1, "Baseline did not reach removable listener")
        current = scan(session("remediation-current", "127.0.0.1", [persistent_port, removed_port]))
        delta = compare_active_scans(baseline, current)
        require(
            [a.port_state for a in current.assessments] == [PortState.OPEN.value, PortState.CLOSED.value],
            "Retest did not confirm open and closed",
        )
        require(
            len(delta.remediated_exposures) == 1 and delta.remediated_exposures[0]["port"] == removed_port,
            "Closed listener was not the sole remediated exposure",
        )
        require(
            len(delta.persistent_exposures) == 1 and delta.persistent_exposures[0]["port"] == persistent_port,
            "Open control was not persistent",
        )
        require(
            not delta.unverified_exposures and delta.remediation_rate == 50.0,
            "Remediation rate included an unverified result",
        )
        require(accepted_count(persistent) == 2, "Persistent listener did not receive both probes")
        return {
            "baseline_states": [a.port_state for a in baseline.assessments],
            "retest_states": [a.port_state for a in current.assessments],
            "remediated": 1,
            "persistent": 1,
            "unverified": 0,
            "remediation_rate_percent": delta.remediation_rate,
        }


def main() -> None:
    require_isolated_network()
    cases = {
        "rate_limit": check_rate_limit(),
        "unreachable": check_unreachable(),
        "dns_shift": check_dns_shift(),
        "partial_resume": check_partial_resume(),
        "remediation": check_remediation(),
    }
    print(json.dumps({"isolation": "linux_loopback_only", "cases": cases}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
