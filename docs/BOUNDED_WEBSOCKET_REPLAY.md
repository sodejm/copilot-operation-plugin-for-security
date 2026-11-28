# Bounded WebSocket replay

The [Web API workbench guide](../plugins/offensive-security/web-api-assessment-workbench/docs/BOUNDED_WEBSOCKET_REPLAY.md)
ships with the portable package and defines the supported WS/WSS text subset,
exact-plan approval, session separation, frame/byte/time budgets, cancellation,
partial evidence and recovery. The approved Python integration reuses the HTTP
connector's scope checks, numeric-address pinning and original-host TLS validation.

The CLI remains preview/offline-only. Binary frames, fragmentation, compression,
extensions, subprotocols and WebSocket redirects are unsupported. Local loopback
tests do not qualify OS/network isolation, independently administered approval
providers or production interoperability. Issue #100 remains open until its
remaining acceptance and delivery gates have current evidence.
