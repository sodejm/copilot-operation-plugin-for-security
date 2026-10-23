"""One fixed DNS A record for the isolated exposure lab; never forwards queries."""

from __future__ import annotations

import secrets
import socket
import socketserver
import struct
import threading
from typing import Any

HOST = "preview.example.test"
ADDRESS = "127.0.0.1"
_QUESTION = b"".join(bytes([len(label)]) + label.encode("ascii") for label in HOST.split(".")) + b"\0\0\1\0\1"


def _query(transaction: bytes) -> bytes:
    return transaction + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + _QUESTION


def _answer(transaction: bytes) -> bytes:
    return (
        transaction
        + struct.pack("!5H", 0x8500, 1, 1, 0, 0)
        + _QUESTION
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 0, 4)
        + socket.inet_aton(ADDRESS)
    )


def validate_response(response: bytes, transaction: bytes) -> str:
    """Accept only the fixed, complete response with the requested transaction ID."""
    if len(transaction) != 2 or response != _answer(transaction):
        raise ValueError("unexpected laboratory DNS response")
    return ADDRESS


class ExposureDNS:
    def __init__(self, telemetry: Any) -> None:
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data, transport = self.request
                if len(data) >= 2 and data == _query(data[:2]):
                    telemetry.record(
                        "exposure_dns_answered",
                        risk="benign",
                        host=HOST,
                        address=ADDRESS,
                        transaction_id=data[:2].hex(),
                    )
                    transport.sendto(_answer(data[:2]), self.client_address)

        self.server = socketserver.UDPServer((ADDRESS, 0), Handler)
        self.server.max_packet_size = 513
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def resolve_exposure(port: int) -> str:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid laboratory DNS port")
    transaction = secrets.token_bytes(2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect((ADDRESS, port))
        client.send(_query(transaction))
        return validate_response(client.recv(513), transaction)
