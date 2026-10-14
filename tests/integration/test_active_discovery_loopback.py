"""Exercise approved loopback probes through the real scanner on each native CI host."""

import errno
import os
import socket

import pytest

from scripts.active_discovery_network_acceptance import (
    check_ipv6,
    check_server_first_banner,
    check_udp,
    check_udp_dns,
)


def require_loopback_sockets() -> None:
    """Skip a restricted developer sandbox, but fail when CI requires live sockets."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        try:
            server.bind(("127.0.0.1", 0))
        except PermissionError as exc:
            if exc.errno == errno.EPERM and os.environ.get("COPS_REQUIRE_NATIVE_LOOPBACK") != "1":
                pytest.skip("Local socket binds are denied by the host sandbox")
            raise


def test_native_ipv4_loopback_probes() -> None:
    require_loopback_sockets()
    udp = check_udp()
    dns = check_udp_dns()
    banner = check_server_first_banner()

    assert udp["states"] == ["open", "unknown"]
    assert dns["truncated"] is True
    assert banner["service"] == "ssh"


def test_native_ipv6_loopback_probes() -> None:
    require_loopback_sockets()
    result = check_ipv6()
    if result["status"] == "unavailable":
        pytest.skip(result["reason"])

    assert result["tcp_states"] == ["open", "closed"]
    assert result["udp_states"] == ["open", "unknown"]
