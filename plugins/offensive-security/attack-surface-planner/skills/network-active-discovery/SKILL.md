---
name: network-active-discovery
description: Execute bounded active port, protocol, and TLS assessment with explicit scan vantage, rate limits, resumable checkpoints, and visible fingerprint uncertainty.
---

# Network active discovery

1. **Plan Authorized Assessment**:
   - Define bounded host, port, protocol, and TLS assessment targets with explicit scan vantage (`external`, `internal`, `egress_point`, `cloud_tenant`).
   - Configure strict rate limits (`rate_limit_pps`) and execution budgets (`timeout_seconds`, `max_total_seconds`, `max_targets`).

2. **Execute Resumable Probes**:
   - Checkpoint session state after probe completion or upon budget exhaustion.
   - Resume partial or interrupted sessions without repeating completed side effects or exceeding approved targets.

3. **Calibrate Fingerprint Uncertainty**:
   - Separate verbatim observed configurations (raw banners, HTTP headers, TLS certificate attributes) from inferred fingerprints (product, version, OS).
   - Assign explicit confidence levels (`high`, `medium`, `low`, `uncertain`, `provisional`) with visible uncertainty reasons.

4. **Enforce Boundary and DNS Rebind Quarantine**:
   - Enforce scope boundaries prior to probe dispatch; detect shifted resolution or DNS rebind conditions and quarantine immediately.

5. **Verify Remediated Exposures**:
   - Compare baseline assessment against current scan to compute remediated, new, and persistent exposures with exact remediation rate.

6. **CLI Invocation**:
   ```bash
   python3 -m cops discovery active plan --targets targets.txt --ports 80,443,22 --output session.json
   python3 -m cops discovery active scan session.json --scope scope.json --checkpoint checkpoint.json
   python3 -m cops discovery active resume checkpoint.json --output completed.json
   python3 -m cops discovery active diff baseline.json current.json --output delta.json
   python3 -m cops discovery active import masscan.json --tool masscan --output masscan_session.json
   ```
