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
   - Resource and execution budgets: per-probe timeouts (`timeout_seconds`), overall execution budget (`max_total_seconds`), and target caps (`max_targets`).

2. **Resumable Execution & Side-Effect Checkpoints**:
   - Checkpoints probe execution state after every probe or upon budget exhaustion.
   - Resumption verifies that the approved target set has not been altered or expanded.
   - Skips previously completed probes (`completed_probe_keys`) without repeating network side effects.

3. **Grounded Service Identification with Visible Uncertainty**:
   - Clearly separates **Observed Configuration** (verbatim banners, HTTP status, raw response headers, TLS cipher suites, X.509 certificates) from **Inferred Fingerprints** (deduced product names, versions, operating systems).
   - Calibrates confidence (`high`, `medium`, `low`, `uncertain`, `provisional`).
   - Explicitly records `uncertainty_reasons` (e.g. reverse proxy fronting, CDN masking, certificate hostname mismatch, or empty banner responses).

4. **Scope Quarantine & DNS Rebind Defense**:
   - Enforces scope boundary checks prior to each probe.
   - Resolves target hostnames and validates that the resolved IP address remains within authorized CIDR boundaries.
   - Detects dynamic DNS shifts or DNS rebind conditions, immediately quarantining the target and halting outbound probes.

5. **Remediated Exposure Verification (Scan Delta)**:
   - Compares baseline active assessment against subsequent re-test sessions.
   - Computes remediated exposures, newly opened ports, persistent services, and version drift with an exact remediation percentage.

## CLI Usage

### 1. Plan Active Assessment
```bash
python3 -m cops discovery active plan \
  --targets "198.51.100.10,app.corp.internal" \
  --ports 80,443,22 \
  --vantage external \
  --rate-limit 10.0 \
  --timeout 2.0 \
  --scope-ref "ROE-2026-001" \
  --output session_plan.json
```

### 2. Execute Bounded Scan with Scope Enforcement
```bash
python3 -m cops discovery active scan session_plan.json \
  --scope engagement_scope.json \
  --checkpoint session_checkpoint.json \
  --output scan_results.json
```

### 3. Resume Interrupted or Partial Session
```bash
python3 -m cops discovery active resume session_checkpoint.json \
  --scope engagement_scope.json \
  --output scan_completed.json
```

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
