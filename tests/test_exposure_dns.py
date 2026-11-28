from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest

from cops.laboratory.exposure_dns import ADDRESS, HOST, ExposureDNS, resolve_exposure, validate_response
from cops.laboratory.service_lab import _Telemetry


def response() -> bytes:
    question = b"\x07preview\x07example\x04test\0\0\1\0\1"
    return b"\x12\x34" + struct.pack("!5H", 0x8500, 1, 1, 0, 0) + question + b"\xc0\x0c\0\1\0\1\0\0\0\0\0\4\x7f\0\0\1"


def test_response_requires_exact_transaction_question_and_answer() -> None:
    wire = response()
    assert validate_response(wire, b"\x12\x34") == ADDRESS
    # Every byte participates in validation, including IDs, flags, counts and address.
    for offset in range(len(wire)):
        altered = bytearray(wire)
        altered[offset] ^= 1
        with pytest.raises(ValueError, match="unexpected"):
            validate_response(bytes(altered), b"\x12\x34")
    for invalid in (wire[:-1], wire + b"\0", b""):
        with pytest.raises(ValueError):
            validate_response(invalid, b"\x12\x34")


def test_actual_dns_exchange_and_unknown_query_rejection(tmp_path: Path) -> None:
    telemetry = _Telemetry(tmp_path / "dns.jsonl", correlation_id="dns-test")
    dns = ExposureDNS(telemetry)
    dns.start()
    try:
        assert resolve_exposure(dns.port) == ADDRESS
        assert [(item["host"], item["address"]) for item in telemetry.events] == [(HOST, ADDRESS)]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.1)
            client.sendto(b"unregistered query", (ADDRESS, dns.port))
            with pytest.raises(TimeoutError):
                client.recv(513)
        assert len(telemetry.events) == 1
    finally:
        dns.stop()
    assert not dns.thread.is_alive()
