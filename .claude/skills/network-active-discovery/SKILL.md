---
name: network-active-discovery
description: Execute bounded active port, protocol, and TLS assessment with explicit scan vantage, rate limits, resumable checkpoints, and visible fingerprint uncertainty.
---

# Network Active Discovery and Service Identification

Execute authorized, bounded active network assessment across approved hosts, ports, protocols, and TLS configurations under explicit Rules of Engagement and operational constraints.

## Core Capabilities

1. **Approved Assessment Configuration**:
   - Explicit scan vantages: `external` (perimeter), `internal` (VPC/LAN), `egress_point`, `cloud_tenant`.
   - Explicit rate limits: `rate_limit_pps` with automated probe spacing to prevent denial of service or perimeter disruption.
   - Resource and execution budgets: per-probe timeouts (`timeout_seconds`), mandatory live execution duration (`max_total_seconds`), cumulative probe cap (`max_probes`), and target caps (`max_targets`).
   - Execution is explicitly serial (`max_concurrency: 1`). Plans that request higher concurrency are rejected before any network side effect.

2. **Resumable Execution & Side-Effect Checkpoints**:
   - A live checkpoint binds the plan, scope, cumulative time, completed probes, and uncertain pending probes. Keep its path durable and protected from unrelated local writers.
   - Resumption rejects a changed plan or scope and skips completed probes (`completed_probe_keys`) without repeating network side effects.
   - A probe reserved before dispatch but lacking a result requires reconciliation; it is never retried automatically.
   - The checkpoint includes normalized coverage counts for planned, attempted, completed, pending, quarantined, unassessed, timed-out, and observed port-state outcomes.

3. **Grounded Service Identification with Visible Uncertainty**:
   - Clearly separates **Observed Configuration** from **Inferred Fingerprints**. The built-in live dispatcher checks TCP reachability; on ports 443/8443 it records TLS version and cipher without peer authentication. On other TCP ports it may read up to 512 bytes of an unsolicited server-first banner. A UDP reply is recorded by length and digest; an opted-in DNS query can identify a matching DNS response. It does not send HTTP requests, collect HTTP headers or certificates, or retain UDP response bodies. Banner-based product and version claims are untrusted self-reports.
   - Calibrates confidence (`high`, `medium`, `low`, `uncertain`, `provisional`).
   - Explicitly records `uncertainty_reasons` (e.g. reverse proxy fronting, CDN masking, certificate hostname mismatch, or empty banner responses).

4. **Scope Quarantine & DNS Rebind Defense**:
   - Requires explicit approved IP ranges for live scans and checks target addresses against them before dispatch.
   - Resolves target hostnames and validates that the resolved IP address remains within authorized CIDR boundaries.
   - Detects dynamic DNS shifts or DNS rebind conditions, immediately quarantining the target and halting outbound probes.

5. **Remediated Exposure Verification (Scan Delta)**:
   - Compares baseline active assessment against subsequent re-test sessions.
   - Computes remediated exposures, newly opened ports, persistent services, and version drift with a remediation percentage. A closed retest counts as remediated only for the same host, resolved address, protocol, port, and vantage, with no conflicting observation. Changed identity, missing probes, and inconclusive retests remain `unverified_exposures`.

## CLI Usage

### 1. Plan Active Assessment
```bash
python3 -m cops discovery active plan \
  --targets "198.51.100.10,app.corp.internal" \
  --ports 80,443,22 \
  --vantage external \
  --rate-limit 10.0 \
  --timeout 2.0 \
  --max-total-seconds 120 \
  --max-probes 6 \
  --max-concurrency 1 \
  --scope-ref "ROE-2026-001" \
  --output session_plan.json
```

For all TCP ports, use `--ports all --allow-full-tcp` and set `--max-probes`
to at least the selected target count times 65,535. UDP is a separate scope;
this command does not scan it. `--scope-ref` is a reference, not proof of
authorization; verify the engagement scope before live execution.

Every plan is limited to 131,070 materialized target/protocol/port probe keys,
and `--max-probes` must cover the full Cartesian plan. This limits in-memory
ledger growth; it does not guarantee that a completed checkpoint will fit the
256 MiB canonical document limit because recorded evidence has variable size.

### 2. Execute Bounded Scan with Scope Enforcement
```bash
python3 -m cops discovery active scan session_plan.json \
  --mode live \
  --scope engagement_scope.json \
  --checkpoint session_checkpoint.json \
  --cancel-file stop-active-scan \
  --output scan_results.json
```

### 3. Resume Interrupted or Partial Session
```bash
python3 -m cops discovery active resume session_checkpoint.json \
  --mode live \
  --scope engagement_scope.json \
  --output scan_completed.json
```

An incomplete result returns exit status 2. Inspect its status and checkpoint:
an uncertain pending probe requires an operator to reconcile the external effect
before any new plan. Creating the optional cancel file stops execution between
durably recorded serial probes, writes status `cancelled`, and leaves unattempted
coverage visible for resume. Remove the file before resuming. The default mode is
synthetic and performs no network scan.

### 4. Compare Baseline and Re-test for Exposure Remediation
```bash
python3 -m cops discovery active diff baseline_scan.json retest_scan.json \
  --output remediation_delta.json
```

### 5. Import Third-Party Tool Results
```bash
# Masscan JSON export
python3 -m cops discovery active import masscan_output.json --tool masscan --output masscan_session.json

# Nmap XML export
python3 -m cops discovery active import nmap_output.xml --tool nmap --output nmap_session.json
```

Masscan and Nmap imports accept only TCP and UDP observations and keep those
port ledgers separate. A Nmap service name without product or version remains a
low-confidence service-name observation rather than an invented product.

Offline synthetic fixtures should key port entries under `ports.tcp` or
`ports.udp`; legacy numeric port keys apply only to TCP. A missing UDP fixture
or UDP timeout remains unknown. A positive DNS fixture must bind the selected
`probe_payload` and explicitly set `dns_response_validated` to `true`.
