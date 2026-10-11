# Active discovery disposable-network acceptance

The active discovery acceptance harness exercises real TCP listeners and a local
UDP DNS responder in a disposable Linux network namespace. It fails if the
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
confirmed remediation. This harness only exercises TCP connection assessment;
it does not prove behavior across an external network, TLS, or a production
engagement.

Run `python3 -m pytest tests/test_active_discovery.py -q` for the simulated
edge cases and `make check` for the repository baseline.
