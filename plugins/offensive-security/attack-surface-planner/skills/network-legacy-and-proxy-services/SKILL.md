---
name: network-legacy-and-proxy-services
description: Assess legacy enterprise storage, hardware out-of-band management, network appliance interfaces, VPN tunneling, and proxy egress services (NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKE, PPTP, SOCKS, Squid) with proxy egress restriction testing, non-destructive canary verification, cleanup receipts, and legacy privilege candidate routing.
---

# Legacy Enterprise, Management, and Proxy Services

1. **Protocol-Specific Coverage Across 9 Legacy & Proxy Protocols**:
   - Assess exposure of enterprise storage (NDMP, iSCSI), hardware out-of-band management (IPMI 2.0 / RMCP+), network appliance management (Cisco Smart Install, TACACS+), legacy VPN tunneling (IKEv1 Aggressive Mode, PPTP), and proxy egress services (SOCKS, Squid) across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Proxy Egress Restriction Testing**:
   - For all proxy and egress services (SOCKS, Squid), test and record destination egress policy restrictions (`proxy_egress_tested`, `proxy_egress_restricted`) to evaluate internal network pivoting or SSRF risks.

3. **Execution Effect Classification & Plan Binding**:
   - Explicitly declare `ExecutionEffect`: `read_only`, `non_destructive`, `state_change`, `code_execution`.
   - Require explicit authorization flags (`--allow-code-execution`, `--allow-state-change`) bound to the approved action plan before attempting intrusive probes.

4. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

5. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate access controls using benign canary identifiers (`canary_legacy_artifact`, `canary_proxy_probe`) without disrupting production workflows.
   - Emit verified `CleanupReceipt` records confirming rollback and artifact removal (`verified_removed`).

6. **CLI Invocation**:
   ```bash
   python3 -m cops legacy-services assess --targets storage01.corp.internal --canary-id "canary_legacy_probe" --output leg_report.json
   python3 -m cops legacy-services candidates leg_report.json --output leg_candidates.json
   python3 -m cops legacy-services cleanup leg_report.json --output cleanup_receipts.json
   python3 -m cops legacy-services inspect leg_report.json
   ```
