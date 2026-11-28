---
name: network-active-discovery
description: "Use for requests to plan an authorized network service scan. Execute bounded active port, protocol, and TLS assessment with explicit scan vantage, rate limits, resumable checkpoints, and visible fingerprint uncertainty."
---

# Network active discovery

1. **Plan Authorized Assessment**:
   - Define bounded host, TCP port, and separately approved UDP port targets with explicit scan vantage (`external`, `internal`, `egress_point`, `cloud_tenant`). Select DNS queries explicitly with `udp_dns_probe_ports`, limited to approved UDP ports.
   - Configure strict rate limits (`rate_limit_pps`) and execution budgets (`timeout_seconds`, `max_total_seconds`, `max_targets`).

2. **Execute Resumable Probes**:
   - Checkpoint session state after probe completion or upon budget exhaustion.
   - Resume partial or interrupted sessions without repeating completed side effects or exceeding approved targets.

3. **Calibrate Fingerprint Uncertainty**:
   - Separate observed probe results from inferred fingerprints (product, version, OS). The built-in scanner may retain up to 512 bytes of a server-first TCP banner, TLS version and cipher on ports 443/8443 without peer authentication, and the length and digest of a UDP reply. It does not collect HTTP headers, certificates, or UDP response bodies. Treat banner-based claims as untrusted self-reports.
   - Do not assign a service from its port number alone. A TLS handshake without HTTP evidence identifies only TLS. By default, an empty UDP datagram reply shows a responding port and silence is inconclusive. An opted-in DNS query identifies DNS only when its transaction ID and question match the response; other UDP replies remain unidentified.
   - Assign explicit confidence levels (`high`, `medium`, `low`, `uncertain`, `provisional`) with visible uncertainty reasons.

4. **Enforce Boundary and DNS Rebind Quarantine**:
   - Enforce scope boundaries prior to probe dispatch; detect shifted resolution or DNS rebind conditions and quarantine immediately.

5. **Verify Remediated Exposures**:
   - Compare baseline assessment against current scan to compute remediated, new, and persistent exposures with a remediation rate. Require the same host, resolved address, protocol, port, and vantage and no conflicting observation before a closed retest confirms remediation; otherwise report an unverified retest.

6. **CLI Invocation**:
   ```bash
   python3 -m cops discovery active plan --targets targets.txt --ports 80,443,22 --udp-ports 53 --udp-dns-probe-ports 53 --output session.json
   python3 -m cops discovery active scan session.json --scope scope.json --checkpoint checkpoint.json
   python3 -m cops discovery active resume checkpoint.json --output completed.json
   python3 -m cops discovery active diff baseline.json current.json --output delta.json
   python3 -m cops discovery active import masscan.json --tool masscan --output masscan_session.json
   ```
