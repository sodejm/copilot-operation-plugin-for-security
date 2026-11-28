"""Kernel evidence for the synthetic, network-disabled acceptance container."""

from __future__ import annotations

import errno
import os
import platform
import re
import socket
from pathlib import Path

from .source_snapshot import verify_source_snapshot


def inspect_acceptance_boundary() -> tuple[bool, tuple[str, ...], str | None]:
    """Verify a launcher-bound Linux network namespace, never just an env marker.

    The host launcher separately verifies the immutable image and Docker inspect
    configuration. This proof is for synthetic acceptance, not execution authority.
    """
    nonce = os.environ.get("COPS_LABORATORY_CONTAINER_NONCE", "")
    digest = os.environ.get("COPS_LABORATORY_SOURCE_DIGEST", "")
    if not re.fullmatch(r"[0-9a-f]{32}", nonce) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False, (), "not running through the inspected acceptance launcher"
    if platform.system() != "Linux":
        return False, (), "acceptance container requires Linux kernel evidence"
    evidence = [f"launcher_nonce={nonce}", f"source_sha256={digest}"]
    try:
        verify_source_snapshot(Path(__file__).resolve().parents[2], digest)
        evidence.append("source_manifest=verified")
        interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
        evidence.append("interfaces=" + ",".join(interfaces))
        if interfaces != ["lo"]:
            return False, tuple(evidence), "network namespace contains a non-loopback interface"
        ipv4 = Path("/proc/net/route").read_text().splitlines()[1:]
        ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
        if any(row.split()[0] != "lo" for row in ipv4 if row.strip()):
            return False, tuple(evidence), "non-loopback IPv4 route exists"
        if any(row.split()[-1] != "lo" for row in ipv6 if row.strip()):
            return False, tuple(evidence), "non-loopback IPv6 route exists"
        evidence.append("kernel_routes=loopback-only")
        denied = {
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
            errno.ENETDOWN,
            errno.EADDRNOTAVAIL,
            errno.EAFNOSUPPORT,
            errno.EPROTONOSUPPORT,
            errno.EACCES,
            errno.EPERM,
        }
        # Reserved documentation addresses; attempted only after route inspection.
        for family, destination in (
            (socket.AF_INET, ("198.51.100.1", 443)),
            (socket.AF_INET6, ("2001:db8::1", 443, 0, 0)),
        ):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(1)
                    result = connection.connect_ex(destination)
            except OSError as exc:
                result = exc.errno
            if result not in denied:
                return False, tuple(evidence), "egress was reachable or its denial was inconclusive"
            evidence.append(f"egress_family_{family}={errno.errorcode.get(result, result)}")
    except (OSError, ValueError, IndexError, TypeError, KeyError):
        return False, tuple(evidence), "source or kernel network evidence is unavailable or malformed"
    return True, tuple(evidence), None
