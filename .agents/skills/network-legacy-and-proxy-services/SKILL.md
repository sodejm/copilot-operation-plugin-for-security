---
name: network-legacy-and-proxy-services
description: Model legacy enterprise, management, VPN, and proxy exposure for nine services using offline fixtures, and record the limits of socket reachability observations.
---

# Legacy Enterprise, Management, and Proxy Services Assessment

Use deterministic offline fixtures to exercise nine legacy service models. The standard socket collector only checks TCP connection or UDP send reachability; it does not perform a protocol exchange, prove authentication or a vulnerability, test proxy egress, execute code, validate a canary, or remove an artifact. Its reachable results are `unconfirmed`. See [protocol topic reconciliation](../../../docs/PROTOCOL_TOPIC_RECONCILIATION.md) for the pinned 70-topic inventory and limits.

## Core Capabilities

1. **Offline Models Across 9 Legacy & Proxy Services**:
   - **Enterprise Storage & Data Management**:
     - **NDMP Network Data Management Protocol (10000/tcp)**: Models unauthenticated backup-interface access.
     - **iSCSI Internet Small Computer Systems Interface (3260/tcp)**: Models target discovery without CHAP.
   - **Out-of-Band & Hardware Management**:
     - **IPMI 2.0 / RMCP+ (623/udp)**: Models Cipher Suite 0 and RAKP exposure flags.
   - **Network Device & Appliance Management**:
     - **Cisco Smart Install / SMI (4786/tcp)**: Models an active Smart Install flag and its potential operation effect.
     - **TACACS+ AAA (49/tcp)**: Models authentication and transport flags.
   - **VPN & Tunneling Services**:
     - **IPsec / IKEv1 (500/udp)**: Models IKEv1 Aggressive Mode configuration; broader IPsec operation is outside this fixture.
     - **PPTP Point-to-Point Tunneling Protocol (1723/tcp)**: Models MS-CHAPv2 exposure.
   - **Proxy & Egress Services**:
     - **SOCKS Proxy (1080/tcp)**: Models unauthenticated relaying and destination restrictions.
     - **Squid HTTP Proxy (3128/tcp)**: Models client ACLs and destination restrictions.

2. **Proxy Egress Fixture Results**:
   - The offline collector records fixture-defined `proxy_egress_tested` and `proxy_egress_restricted` values for exposed and protected SOCKS/Squid examples. These values do not establish any real destination policy. The socket collector leaves egress untested and restriction unknown.

3. **Explicit Execution Effect Classification & Plan Binding**:
   - Operations declare their operational effect using `ExecutionEffect`:
     - `read_only`, `non_destructive`, `state_change`, `code_execution`: Classifications of possible operations in the offline model, not proof an operation ran.
   - Fixture branches that set `can_execute_code` or `can_change_state` require the corresponding authorization flags. The socket collector never sets these capabilities from reachability alone.

4. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If an interface times out, is connection-refused, or is filtered, it is recorded as `inaccessible` with `auth_prerequisite: unknown` and uncertainty notes.
   - A reachable socket is `unconfirmed`. `protected` and `remediated` are available in the offline fixture when its configuration states those conditions; they are not inferred from a failed connection.

5. **Synthetic Canary and Cleanup Records**:
   - Offline fixtures can emit hashed `CleanupReceipt` records for a canary identifier. They exercise serialization and reporting; no remote artifact is created or removed. The socket collector does not emit a cleanup receipt.

6. **Legacy Privilege Candidate Routing**:
   - Fixture-defined misconfigurations are exported as `LegacyPrivilegeCandidate` records:
     - `ndmp_unauthenticated_access`: NAS backup interface traversal without authentication.
     - `iscsi_unauthenticated_target`: iSCSI storage target discovery and LUN attachment without CHAP.
     - `ipmi_cipher_zero_bypass`: IPMI 2.0 Cipher Suite 0 authentication bypass on hardware BMC.
     - `ipmi_rakp_hash_dump`: IPMI 2.0 RAKP HMAC-SHA1 password hash exposure for offline cracking.
     - `cisco_smart_install_rce`: Cisco Smart Install active daemon allowing arbitrary switch takeover.
     - `tacacs_unauthenticated_daemon`: TACACS+ daemon exposed with weak/default shared secret.
     - `ike_aggressive_mode_psk`: IKEv1 Aggressive Mode PSK hash capture for offline cracking.
     - `pptp_mschapv2_exposure`: Legacy PPTP VPN service exposed with crackable MS-CHAPv2 auth.
     - `socks_open_proxy`: SOCKS proxy allowing unauthenticated open network relaying.
     - `squid_open_proxy`: Squid forward proxy allowing unrestricted internal/external SSRF pivoting.
   - Candidate hashes cover model data, not captured protocol traffic or verified impact. Confirm each finding in an authorized environment before operational handoff.

## CLI Usage

### 1. Check Socket Reachability for Legacy Services
```bash
python3 -m cops legacy-services assess \
  --targets "198.51.100.50,storage01.corp.internal" \
  --mode live \
  --vantage internal \
  --canary-id "canary_legacy_probe" \
  --output legacy_assessment.json
```

The `--allow-code-execution` flag controls a synthetic fixture branch; it does not cause the socket collector to execute code. Supply fixture data with `--offline-targets` when exercising this branch:
```bash
python3 -m cops legacy-services assess \
  --targets "198.51.100.50" \
  --services "ipmi,cisco_smart_install" \
  --mode synthetic \
  --offline-targets mock_targets.json \
  --allow-code-execution \
  --canary-id "canary_smi_probe" \
  --output legacy_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery legacy assess \
  --targets "198.51.100.50" \
  --mode live \
  --output legacy_assessment.json
```

### 2. Export Legacy Privilege Candidates
```bash
python3 -m cops legacy-services candidates legacy_assessment.json \
  --output legacy_candidates.json
```

### 3. Export Cleanup Records Present in a Report
```bash
python3 -m cops legacy-services cleanup legacy_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Assessment Report
```bash
python3 -m cops legacy-services inspect legacy_assessment.json
```
