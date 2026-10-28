"""One-shot fixed-trigger capability for supervisor-owned Web API replay."""

from __future__ import annotations

import json
import math
import multiprocessing
import socket
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from time import monotonic
from types import MappingProxyType
from typing import Any

from cops.execution.egress import BROKER_FD_ENV

from .worker_replay import WebApiReplayError, WebApiReplayMediator

DISPATCH_TRIGGER = b'{"version":"cops.web-api-replay/v1","action":"dispatch"}\n'
MAX_BROKER_RESPONSE_BYTES = 2_097_152 + 4096
DISPATCH_NOT_DISPATCHED = "not_dispatched"
DISPATCH_ATTEMPTED_UNCERTAIN = "dispatch_attempted_uncertain"
DISPATCH_COMPLETED = "completed"


@dataclass
class ReplayBrokerChannel:
    environment: Mapping[str, str]
    pass_fds: tuple[int, ...]
    result: dict[str, Any] | None = None
    dispatch_state: str = DISPATCH_NOT_DISPATCHED


class WebApiReplayBroker:
    """Keep all request data in a trusted broker; expose exactly one dispatch."""

    def __init__(self, mediator: WebApiReplayMediator) -> None:
        self._mediator = mediator
        self._used = False
        self._lock = threading.Lock()

    @contextmanager
    def open_channel(
        self,
        *,
        deadline: float,
        cancellation_event: threading.Event | None = None,
    ) -> Iterator[ReplayBrokerChannel]:
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            raise WebApiReplayError("invalid replay broker deadline")
        if deadline <= monotonic() or (cancellation_event is not None and cancellation_event.is_set()):
            raise WebApiReplayError("replay broker deadline or cancellation prevents dispatch")
        with self._lock:
            if self._used:
                raise WebApiReplayError("replay broker capability is already consumed")
            self._used = True
        if "fork" not in multiprocessing.get_all_start_methods():
            raise WebApiReplayError("replay broker requires a fork-capable supervisor")
        context = multiprocessing.get_context("fork")
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        reader, writer = context.Pipe(duplex=False)
        cancelled = context.Event()
        dispatch_attempted = context.Event()
        stopped = threading.Event()
        channel = ReplayBrokerChannel(MappingProxyType({BROKER_FD_ENV: str(client.fileno())}), (client.fileno(),))
        process = context.Process(
            target=self._serve,
            args=(server, client, reader, writer, deadline, cancelled, dispatch_attempted),
            daemon=True,
            name="cops-web-api-replay-broker",
        )
        started = False

        def supervise() -> None:
            while not stopped.is_set():
                if monotonic() >= deadline or (cancellation_event is not None and cancellation_event.is_set()):
                    cancelled.set()
                    with suppress(OSError):
                        server.shutdown(socket.SHUT_RDWR)
                    return
                if reader.poll(0.02):
                    try:
                        result = json.loads(reader.recv_bytes(MAX_BROKER_RESPONSE_BYTES).decode("utf-8"))
                        if isinstance(result, dict):
                            channel.result = result
                    except (EOFError, OSError, ValueError, UnicodeError):
                        pass
                    return

        monitor = threading.Thread(target=supervise, name="cops-replay-supervisor", daemon=True)
        try:
            process.start()
            started = True
            writer.close()
            monitor.start()
            yield channel
        finally:
            client.close()
            cancelled.set()
            if started:
                process.join(timeout=0.2)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=0.2)
                if process.is_alive():
                    process.kill()
                    process.join()
                # The trusted output pipe is drained concurrently, including
                # outputs larger than the operating system pipe buffer. Once
                # the broker is reaped its writer is closed, so the monitor
                # can only finish a bounded JSON parse or observe EOF. Wait for
                # that immutable outcome before classifying dispatch state.
                monitor.join()
            stopped.set()
            if channel.result is not None:
                channel.dispatch_state = DISPATCH_COMPLETED
            elif dispatch_attempted.is_set():
                channel.dispatch_state = DISPATCH_ATTEMPTED_UNCERTAIN
            reader.close()
            writer.close()
            server.close()
            if started:
                process.close()

    def _serve(
        self,
        server: socket.socket,
        client: socket.socket,
        reader: Any,
        writer: Any,
        deadline: float,
        cancelled: Any,
        dispatch_attempted: Any,
    ) -> None:
        client.close()
        reader.close()
        try:
            server.settimeout(max(0.001, deadline - monotonic()))
            request = b""
            while b"\n" not in request:
                chunk = server.recv(len(DISPATCH_TRIGGER) + 1 - len(request))
                if not chunk:
                    raise WebApiReplayError("incomplete dispatch trigger")
                request += chunk
                if len(request) > len(DISPATCH_TRIGGER):
                    raise WebApiReplayError("invalid dispatch trigger")
            if request != DISPATCH_TRIGGER:
                raise WebApiReplayError("invalid dispatch trigger")
            # No child-controlled data enters the mediator call.
            result = self._mediator.dispatch(
                self._mediator.envelope.to_dict(),
                plan_digest=self._mediator.plan_digest,
                approval_digest=self._mediator.approval_digest,
                cancellation_event=cancelled,
                dispatch_observer=dispatch_attempted.set,
            )
            payload = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            if len(payload) + 1 > MAX_BROKER_RESPONSE_BYTES:
                raise WebApiReplayError("replay broker output budget exceeded")
            server.settimeout(max(0.001, deadline - monotonic()))
            writer.send_bytes(payload)
            # The isolated child receives completion metadata only. Response
            # bodies remain on the supervisor's trusted result pipe.
            server.sendall(b'{"status":"completed"}\n')
        except Exception:
            with suppress(OSError):
                server.sendall(b'{"error":"replay_denied"}\n')
        finally:
            writer.close()
            server.close()
