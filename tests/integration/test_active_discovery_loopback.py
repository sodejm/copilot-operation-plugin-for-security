"""External live scanner entry points remain unavailable before network I/O."""

from unittest.mock import patch

import pytest

from cops.discovery.active_scanner import StandardSocketDispatcher


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_direct_standard_socket_scanner_is_unavailable_before_io(address: str) -> None:
    dispatcher = StandardSocketDispatcher(udp_dns_probe_ports=[53])
    with (
        patch("socket.getaddrinfo") as resolve,
        patch("socket.create_connection") as connect,
        patch("socket.socket") as udp_socket,
    ):
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            dispatcher.resolve_target(address)
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            dispatcher.dispatch_probe(address, address, 80)
        with pytest.raises(ValueError, match="Unauthenticated live discovery is unavailable"):
            dispatcher._dispatch_udp(address, address, 53, 0.1, "external")

    resolve.assert_not_called()
    connect.assert_not_called()
    udp_socket.assert_not_called()
