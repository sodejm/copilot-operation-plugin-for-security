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
It requires Docker, the cached image, and a Python 3.12 image whose `tarfile`
module supports the `data` extraction filter.

```sh
tar -cf - cops scripts/active_discovery_network_acceptance.py | \
  docker run --name cops-issue-284-acceptance --rm --pull never -i \
    --network none --read-only \
    --security-opt no-new-privileges --cap-drop ALL --pids-limit 64 \
    --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --tmpfs /workspace:rw,nosuid,nodev,size=64m \
    -w /workspace -e PYTHONDONTWRITEBYTECODE=1 \
    python:3.12-slim python -B -c \
    'import runpy,sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer,mode="r|").extractall("/workspace",filter="data"); runpy.run_module("scripts.active_discovery_network_acceptance",run_name="__main__")'
```

After a successful or failed run, verify that `--rm` removed the container:

```sh
docker container inspect cops-issue-284-acceptance
```

The expected result is `No such container`. The harness also verifies that its
TCP and UDP listener file descriptors are closed and its temporary checkpoint
directory is deleted before it reports success.

The script exits nonzero if any case fails and prints a JSON record on success.
The container is removed by `--rm`; listeners, the DNS responder, and the
checkpoint are closed or deleted by the script. No host ports, credentials, or
external network route are needed.

### Full TCP range

This separate practitioner command runs outside pytest and measures every TCP
port on one explicitly allowed loopback address. The session has a 120-second
duration budget and a 65,535-probe cap. It asserts complete attempted and
completed coverage, zero skipped, pending, and unassessed probes, checkpoint
reload equality, journal retirement, and temporary-directory cleanup.

```sh
tar -cf - cops scripts/active_discovery_full_tcp_acceptance.py | \
  docker run --name cops-issue-284-full-tcp --rm --pull never -i \
    --network none --read-only \
    --security-opt no-new-privileges --cap-drop ALL --pids-limit 64 \
    --memory 512m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --tmpfs /workspace:rw,nosuid,nodev,size=64m \
    -w /workspace -e PYTHONDONTWRITEBYTECODE=1 \
    python:3.12-slim python -B -c \
    'import runpy,sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer,mode="r|").extractall("/workspace",filter="data"); runpy.run_module("scripts.active_discovery_full_tcp_acceptance",run_name="__main__")'
```

After the run, `docker container inspect cops-issue-284-full-tcp` must return
`No such container` because `--rm` performed the final container cleanup.

An isolated Linux loopback run on 2026-10-14 completed all 65,535 TCP probes
in 24.618 seconds (30.9 seconds including container startup). Planned,
attempted, and completed counts were each 65,535; pending, skipped, timed-out,
and unassessed counts were zero. All ports were closed in that run. The final
checkpoint was 53,771,855 bytes, reloaded equal to the in-memory session, and
the journal was retired. The script reported complete temporary-directory
cleanup, and the container inspection returned `No such container`. This is
one loopback measurement, not a timing guarantee or evidence about routed
network performance.

Plans accept explicit host/IP lists and IPv4 or IPv6 CIDRs. CIDRs expand
deterministically before execution and fail closed when the result exceeds
`--max-targets`; overlap with another entry is rejected as a duplicate. For
example, `--targets 192.0.2.0/31,2001:db8::/127 --max-targets 4` produces four
destinations. Live execution still validates every resolved destination against
the engagement allowlist. Large or routed ranges require a separately authorized
vantage, scope, rate, probe, and duration budget.

### Opt-in controlled packet-drop case

The default command remains unprivileged. To exercise a controlled TCP packet
drop on Linux, build a disposable image with `iptables` and opt in to the
`CAP_NET_ADMIN` case. The build needs package-network access; the acceptance run
itself still uses `--network none`, loopback only, a read-only root filesystem,
and drops every capability except `NET_ADMIN`.

```sh
build_dir="$(mktemp -d)"
cat >"$build_dir/Dockerfile" <<'EOF'
FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
EOF

docker build --pull=false -t cops-issue-284-netadmin:local "$build_dir"
tar -cf - cops scripts/active_discovery_network_acceptance.py | \
  docker run --name cops-issue-284-netadmin --rm --pull never -i \
    --network none --read-only --security-opt no-new-privileges \
    --cap-drop ALL --cap-add NET_ADMIN --pids-limit 64 \
    --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --tmpfs /workspace:rw,nosuid,nodev,size=64m \
    -w /workspace -e PYTHONDONTWRITEBYTECODE=1 \
    -e COPS_ACCEPTANCE_FILTERED=1 \
    cops-issue-284-netadmin:local python -B -c \
    'import runpy,sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer,mode="r|").extractall("/workspace",filter="data"); runpy.run_module("scripts.active_discovery_network_acceptance",run_name="__main__")'

docker container inspect cops-issue-284-netadmin
docker image rm cops-issue-284-netadmin:local
rm -rf "$build_dir"
```

The expected container-inspect result is `No such container`. The opt-in case
checks an unused TCP port before, during, and after one narrow loopback `OUTPUT`
drop rule. It requires `closed` before the rule, `filtered` with reachability
`filtered`, a socket timeout, and one timed-out coverage item while the rule is
active, then `closed` after the rule is deleted in a `finally` block. The image
removal command and build-directory removal complete the disposable lab cleanup.
Do not set `COPS_ACCEPTANCE_FILTERED=1` outside an isolated Linux environment
where granting `NET_ADMIN` is authorized.

## Cases and observed evidence

The run on 2026-10-11 used the cached Linux arm64 `python:3.12-slim` image
(`sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`).
These measurements are one run's evidence, not fixed timing expectations:

| Case | Positive and negative controls | Observed result |
| --- | --- | --- |
| Rate limit | Two open loopback TCP listeners at five probes per second | Both accepted exactly one connection; probe starts were 210.3 ms apart against a 200 ms minimum. |
| Unreachable | No-route `198.51.100.1` and a closed loopback port | Kernel error `ENETUNREACH` (101) was `unreachable`; the closed control was `closed`. |
| DNS shift | Local UDP DNS responder returned `127.0.0.1`, then `127.0.0.2`; a direct connection proved the second address's listener was reachable | Two DNS answers, one scanner TCP probe, `dns_rebind_detected` quarantine, and zero scanner connections to the shifted listener. |
| Cancellation and resume | Two open listeners; a cancellation callback becomes true after the first durable result | Checkpoint reported `cancelled`, planned 2, attempted/completed 1, pending 0, and unassessed 1. Resume dispatched only the remaining probe and completed both, with one connection per listener. |
| Remediated exposure | Two listeners open at baseline, then one closed for retest | Retest returned one `open` and one `closed`; delta reported one persistent, one remediated, zero unverified, and 50% remediation. |

The local DNS responder supplies an A record over UDP with a zero-second TTL. It
tests an address change between probes; it does not test an operating system's
DNS cache or a production resolver. The no-route case tests a namespace with no
external interface, not a firewall timeout. The default container has an effective
capability mask of zero because the command uses `--cap-drop ALL`; creating a
controlled packet-drop rule would require `CAP_NET_ADMIN`. The harness therefore
records the default filtered-network case as unavailable and does not relabel a
closed, unreachable, or silent UDP observation as filtered. The opt-in command
above supplies the separate controlled packet-drop proof. Filtered retests and
missing retests remain `unverified_exposures`, not confirmed remediation. That initial
harness run only exercised TCP connection assessment;
it does not prove behavior across an external network, TLS, or a production
engagement.

The 2026-10-14 run passed again after adding a mandatory live duration and
durable side-effect reservations. It observed 214.0 ms between two five-per-second
probes, one accepted connection per listener after an interrupted run resumed,
two DNS answers with no probe to the shifted address, and one confirmed remediated
exposure out of two. The interruption checkpoint was `cancelled` with one
completed probe and no pending probe; the resumed checkpoint was `completed` with
two probes. These results cover this isolated Linux harness only. The focused
tests exercise uncertain pending operations and rejected plan/scope changes;
this run did not verify native Windows or macOS scanning. Later native CI
evidence is described below.
The checkpoint format now permits up to 256 MiB, with bounded reads. An
append-only attempt/result journal preserves pre-dispatch reservations without
rewriting the growing session after each probe, then compacts to the final
checkpoint and retires the journal after successful completion.

A later 2026-10-14 run passed with one live UDP reply and one silent UDP socket.
The responder observed exactly one empty datagram per approved port. The scanner
reported the responding port as `open` with a response length and SHA-256 digest;
it reported the silent port as `unknown` because silence cannot distinguish open
from filtered. Neither result claimed a DNS or other application protocol from
the port number. This verifies basic bounded UDP behavior in the isolated Linux
environment. This run did not test external networks, native Windows or macOS
operation, or full-range scan performance.

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
operation were outside this run.

Another 2026-10-14 run exercised the actual scanner against `::1/128` in the
same disposable network namespace. A live TCP listener was `open`, a closed TCP
port was `closed`, a responding UDP listener was `open`, and a silent UDP
listener was `unknown`. The TCP listener accepted one connection and each UDP
listener received one empty datagram. All four assessments retained `::1` as
the resolved address. The harness reports `unavailable` if IPv6 loopback is
disabled. This verifies bounded IPv6 loopback probes on this Linux image; it
does not establish IPv6 behavior across a routed network or native Windows and
macOS scanning; the separate native CI checks below cover loopback only.

On commit `600637c1e99b77e938a8308b4ad24a73606e57ff`, the repository's
[Linux, macOS, and Windows operator-smoke jobs](https://github.com/sodejm/copilot-operation-plugin-for-security/actions/runs/38561789826) passed. They run the
scanner against local TCP and UDP listeners. They check an IPv4 UDP reply and
silence, validated and rejected DNS replies, a server-first SSH banner, and
IPv6 TCP and UDP behavior when the runner exposes `::1`. An unavailable IPv6
loopback is reported as a skip, not evidence that IPv6 scanning passed. These
checks require a closed control on Linux and macOS. A Windows runner returned a
TCP connection timeout for an unbound IPv6 loopback port; the scanner correctly
reported `filtered`, since that observation cannot establish `closed`. The
Windows check accepts this state only with the recorded timeout and still
requires the open TCP and both UDP controls to pass. These
native checks do not establish routed-network reachability or full-range scan
performance. A developer sandbox that denies local socket binds skips the local
test; CI requires live socket access and fails if binds are denied.

The Issue 284 acceptance run on 2026-10-14 used the same cached arm64 image and
the exact command above. IPv4 TCP observations distinguished `open`, `closed`,
and kernel `ENETUNREACH`; IPv6 loopback reported TCP `open`/`closed` and UDP
`open`/`unknown`; generic UDP recorded one reply and one silent datagram; DNS
validation accepted matching complete and truncated responses while rejecting
five malformed controls. A nonstandard-port SSH banner produced a medium-confidence
SSH identification without sending application payload. Cancellation persisted
planned 2, attempted/completed 1, pending 0, and unassessed 1; resume dispatched
exactly the remaining probe. Cleanup checks reported closed TCP and UDP file
descriptors and a removed temporary directory, and a subsequent container inspect
returned `No such container`. The effective capability mask was `0x0`, so the
packet-drop case was recorded as unavailable for the reason described above.
This default run proves loopback behavior only. It does not prove routed IPv6 or
controlled firewall-drop behavior; the opt-in run supplies the separate
packet-drop proof.

The opt-in packet-drop run on 2026-10-14 used the command above with only
`CAP_NET_ADMIN` effective (`0x1000`). The unused TCP port was `closed` before the
rule, `filtered` with reachability `filtered`, error `Socket connection timed out`,
and coverage `timed_out: 1` while the loopback `OUTPUT` drop rule was active. It
returned to `closed` after rule removal. The rest of the same run passed IPv4
TCP open/closed/unreachable, IPv4 UDP open/unknown, nonstandard-port SSH banner
validation, DNS controls, IPv6 loopback TCP and UDP, cancellation/resume, and
cleanup. `--rm` removed the container. This result establishes the filtered
distinction in this isolated Linux namespace; it does not establish behavior
through a production firewall or across a routed network.

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
self-reported and may be hostile or misleading. That Linux banner run did not
establish request-driven HTTP service identification, TLS peer authentication,
or full-range scan performance.

Run `python3 -m pytest tests/test_active_discovery.py -q` for the simulated
edge cases and `make check` for the repository baseline.

The scan-delta unit cases require a retest of the same resolved address and
vantage before reporting a closed port as remediated. A changed address or
vantage leaves the original exposure unverified; conflicting observations of
one service cannot confirm remediation. These comparisons rely on recorded
vantage labels and do not independently attest where a scanner ran. The
disposable-network harness above supplies a same-identity open/closed control;
the changed-identity and conflicting-observation cases use synthetic records.
