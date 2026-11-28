# Bounded WebSocket replay

The approved Python replay integration supports a narrow RFC 6455 version 13
text exchange over `ws` and `wss`. The package CLI still supports only preview
and offline synthetic replay. An imported URL is not authorization to contact it.

## Supported exchange

Each `ReplayRequest(protocol="websocket")` opens a fresh connection with its
approved isolated session headers. It sends exactly `websocket_messages`, reads
one unfragmented UTF-8 text reply per message, sends close 1000 and requires a
valid peer close. An empty list performs handshake and close without inventing
an application message. Ping frames receive masked pongs; unsolicited pongs are
bounded but are not application evidence. No cookies or connections are shared.

Binary data, fragments, compression, extensions, subprotocols and redirects are
unsupported. Invalid handshake acceptance, framing, UTF-8 or close codes fail the
exchange. A successful protocol exchange does not prove authorization correctness
at a real target; inspect the actual authorized evidence separately.

## Plan and approve

Use the existing `build_replay_action_plan` and
`execute_authorized_replay_session` functions, not a separate execution path.
The WebSocket operation is `cops.web_api.bounded-websocket-replayer`, version `1`,
action `replay_websocket_session`. It binds exact messages, source and effective
requests, isolated sessions, allowlist and budgets to one-use approval. Changes
require a new exact plan and authorization.

For example, prepare the request and budget without dispatching:

```python
from cops.web_api.models import ReplayBudget, ReplayRequest, SessionContext
from cops.web_api.replay import build_replay_action_plan, preview_replay_session

request = ReplayRequest(
    request_id="ws-owner", endpoint_id="object-stream", method="GET",
    url="wss://example.test/socket", protocol="websocket",
    session_id="owner-session", role_id="owner",
    websocket_messages=['{"object_id":"reviewed-canary"}'],
)
sessions = [SessionContext(session_id="owner-session", role_id="owner")]
budget = ReplayBudget(
    max_requests=1, timeout_seconds=3, max_websocket_frames=10,
    max_websocket_message_bytes=4096, max_websocket_bytes=16384,
)
preview = preview_replay_session([request], ["example.test"], budget)
assert preview.total_dispatched == 0
```

Replace the example destination and credential-free session with the exact
operator-authorized inputs before plan construction. Supply the same sessions
to plan construction and execution. The existing approval authority must approve
that plan and worker; the integration must supply its consume-only
`ApprovalControl` and `ScopeGuard`. The library cannot provision or independently
qualify those deployment boundaries. Never put raw credentials in report inputs.
The runtime scope must explicitly enable `egress_allowed`; including a target
does not override a disabled WebSocket egress policy.

## Budgets and stopping

| Limit | Meaning | Default / maximum |
| --- | --- | --- |
| `max_requests` | Connections admitted by the replay batch | Existing request limit |
| `max_websocket_frames` | All sent and received data/control/close frames per connection | 10 / 10,000 |
| `max_websocket_message_bytes` | UTF-8 bytes per text frame | 65,536 / 65,536 |
| `max_websocket_bytes` | Encoded frame bytes admitted for sending/reading, both directions | 1,048,576 / 1,048,576 |
| `timeout_seconds` | One deadline for DNS, TCP, TLS, handshake, pacing, messages and close | Existing request timeout |

The known message sequence must fit at least two frames per message and two for
close before approval consumption or DNS. Control traffic can exhaust the remaining
budget; it never silently expands it. Peer frame lengths are checked before payload
allocation/read. Separate caps limit the request handshake to 8,192 bytes and the
response handshake to 16,384 bytes. `rate_limit_rps` paces connection dispatch and
successive text sends; pacing consumes the same deadline.

Pass an optional `threading.Event` as `cancellation_event` to the approved replay
entrypoint and set it to stop. Cancellation before consumption dispatches nothing.
Timeout/cancellation interrupts the attached TCP or TLS socket with kernel
shutdown and permits a bounded 200 ms worker-cleanup join. The worker alone
mutates SSL state and closes its descriptor, avoiding a cross-thread close race
with an in-flight TLS handshake. A synchronous resolver may finish later, but cannot
connect or dispatch after stopping. These are local stopping controls, not proof
that a server rolled back an already received message.

## Evidence and recovery

Saved messages and replies are opaque digests. Reports retain canonical handshake
fields and optional `websocket_metrics`: completed frame counts, completed
send/read byte counts and a validated peer close code. Incomplete I/O may have
uncertain effects not represented by those completed counters; they are not an
independent wire meter. Peers can send more bytes into network buffers than the
client admits for parsing. Close reasons and arbitrary server headers are not saved.

Failure stops the batch. Completed replies remain partial evidence with
`replay_success: false`; do not promote them into a completed successful assessment.
Review uncertain remote effects and collect a new authorization before retry.
No error cleanup frame may exceed the approved budget.

HTTP operations keep their version `2` identity and previous canonical budget
digest. The two new byte fields affect WebSockets only and are excluded from
HTTP-only operation budget digests. Existing saved HTTP budgets remain readable;
WebSocket reports and previews explicitly expose the effective byte defaults.

## Local validation and limits

Run `make check-web-api-acceptance` in the prepared contributor environment.
The mandatory gate requires REST/GraphQL/rate cases and both vulnerable/corrected
WebSocket role-session cases. Run focused transport regressions with:

```bash
python3 -m pytest -q tests/test_web_api_websocket.py
```

These tests use disposable loopback listeners, exact signed persisted approvals,
malformed peers, real TLS trust/hostname checks, cancellation and verified local
socket/server cleanup. They do not establish OS/network isolation, an independently
administered approval provider, production interoperability or issue #100 closure.
