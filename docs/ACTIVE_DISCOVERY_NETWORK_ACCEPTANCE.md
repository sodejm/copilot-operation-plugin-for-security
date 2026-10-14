# Active discovery disposable-network acceptance

The active discovery acceptance harness exercises real TCP listeners, a local
UDP DNS responder, and bounded UDP probes in a disposable Linux network namespace. It fails if the
namespace has an interface other than loopback. Use it to verify scanner behavior
without scanning an engagement target or exposing a host port.

## Run

From the repository root, start Docker with a locally cached `python:3.12-slim`
image. The command deliberately uses `--pull never` and `--network none`. It
streams the Python source into a temporary in-container filesystem because some
Docker Desktop installations cannot bind-mount a host worktree under `/private/tmp`.

```sh
tar -cf - cops scripts/active_discovery_network_acceptance.py | \
  docker run --rm --pull never -i --network none --read-only \
    --security-opt no-new-privileges --cap-drop ALL --pids-limit 64 \
    --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --tmpfs /workspace:rw,nosuid,nodev,size=64m \
    -w /workspace -e PYTHONDONTWRITEBYTECODE=1 \
    python:3.12-slim python -B -c \
    'import runpy,sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer,mode="r|").extractall("/workspace",filter="data"); runpy.run_module("scripts.active_discovery_network_acceptance",run_name="__main__")'
```

The script exits nonzero if any case fails and prints a JSON record on success.
The container is removed by `--rm`; listeners, the DNS responder, and the
checkpoint are closed or deleted by the script. No host ports, credentials, or
external network route are needed.

## Cases and observed evidence

The run on 2026-10-11 used the cached Linux arm64 `python:3.12-slim` image
(`sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`).
These measurements are one run's evidence, not fixed timing expectations:

| Case | Positive and negative controls | Observed result |
| --- | --- | --- |
| Rate limit | Two open loopback TCP listeners at five probes per second | Both accepted exactly one connection; probe starts were 210.3 ms apart against a 200 ms minimum. |
| Unreachable | No-route `198.51.100.1` and a closed loopback port | Kernel error `ENETUNREACH` (101) was `unreachable`; the closed control was `closed`. |
| DNS shift | Local UDP DNS responder returned `127.0.0.1`, then `127.0.0.2`; a direct connection proved the second address's listener was reachable | Two DNS answers, one scanner TCP probe, `dns_rebind_detected` quarantine, and zero scanner connections to the shifted listener. |
| Partial results | Two open listeners; time budget stops after the first probe | Checkpoint reported `budget_exhausted` with one probe; resume completed two probes total, with one connection per listener. |
| Remediated exposure | Two listeners open at baseline, then one closed for retest | Retest returned one `open` and one `closed`; delta reported one persistent, one remediated, zero unverified, and 50% remediation. |

The local DNS responder supplies an A record over UDP with a zero-second TTL. It
tests an address change between probes; it does not test an operating system's
DNS cache or a production resolver. The no-route case tests a namespace with no
external interface, not a firewall timeout. Filtered retests and missing retests
are covered by the focused simulated tests and remain `unverified_exposures`, not
confirmed remediation. That initial harness run only exercised TCP connection assessment;
it does not prove behavior across an external network, TLS, or a production
engagement.

The 2026-10-14 run passed again after adding a mandatory live duration and
durable side-effect reservations. It observed 214.0 ms between two five-per-second
probes, one accepted connection per listener after an interrupted run resumed,
two DNS answers with no probe to the shifted address, and one confirmed remediated
exposure out of two. The interruption checkpoint was `in_progress` with one
completed probe and no pending probe; the resumed checkpoint was `completed` with
two probes. These results cover this isolated Linux harness only. The focused
tests exercise uncertain pending operations and rejected plan/scope changes;
native Windows and macOS scanning remain unverified.
The checkpoint format now permits up to 256 MiB, with bounded reads, so a
checkpoint above the ordinary 1 MiB JSON limit can resume. A full 65,535-port
TCP run has not been measured for duration, memory use, or checkpoint size.

A later 2026-10-14 run passed with one live UDP reply and one silent UDP socket.
The responder observed exactly one empty datagram per approved port. The scanner
reported the responding port as `open` with a response length and SHA-256 digest;
it reported the silent port as `unknown` because silence cannot distinguish open
from filtered. Neither result claimed a DNS or other application protocol from
the port number. This verifies basic bounded UDP behavior in the isolated Linux
environment. External networks, native Windows and macOS operation, and
full-range scan performance remain unverified.

A subsequent 2026-10-14 isolated Linux run exercised the explicitly selected
DNS probe on seven UDP loopback ports. Each responder received exactly one
nonrecursive root NS query. All replied, so all ports were `open`. Matching
complete and truncated responses were identified as `dns`, with truncation
recorded; wrong transaction ID, question count, question bytes, reserved header
bit, and short responses remained unidentified. None claimed a product or
version. The same run passed the earlier rate-limit, DNS-shift, interruption,
retest, generic UDP, and server-first banner controls. This establishes bounded
DNS response identification in this disposable namespace. Other UDP services,
other malformed-response variants, external networks, and native Windows/macOS
operation remain unverified.

TCP fingerprint tests also reject a generic `220` greeting on conventional SMTP
and FTP ports as insufficient to identify the service. A protocol-specific banner
can identify SMTP or FTP on a nonstandard port. The 2026-10-14 isolated Linux run
also observed a live SSH listener sending `SSH-2.0-OpenSSH_9.2p1 test-build` on
an ephemeral port. The scanner made one connection, sent no application payload,
preserved the original banner bytes, and reported SSH version `9.2p1` with medium
confidence. For non-TLS TCP ports, this optional server-first read waits at most
50 ms and stores at most 512 received bytes per probe. The local probe record has
a SHA-256 reference for traceability; it does not authenticate the remote service
or attest the scanner environment. Banner text and product/version claims are
self-reported and may be hostile or misleading. The run did not establish
request-driven HTTP service identification, TLS peer authentication, native
Windows or macOS operation, or full-range scan performance.

Run `python3 -m pytest tests/test_active_discovery.py -q` for the simulated
edge cases and `make check` for the repository baseline.
