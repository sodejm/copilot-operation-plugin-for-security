---
name: network-legacy-and-proxy-services
description: Assess legacy enterprise storage, hardware out-of-band management, network appliance interfaces, VPN tunneling, and proxy egress services (NDMP, iSCSI, IPMI, Cisco Smart Install, TACACS+, IKE, PPTP, SOCKS, Squid) with proxy egress restriction testing, non-destructive canary verification, cleanup receipts, and legacy privilege candidate routing.
---

# Legacy Enterprise, Management, and Proxy Services Assessment

Execute authorized, bounded exposure and configuration assessments across legacy enterprise storage protocols, hardware out-of-band management interfaces, network device appliance management, legacy VPN tunneling protocols, and forward proxy egress services under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Coverage Across 9 Legacy & Proxy Protocols**:
   - **Enterprise Storage & Data Management**:
     - **NDMP Network Data Management Protocol (10000/tcp)**: Assesses unauthenticated access to network-attached storage (NAS) backup interfaces, testing for unauthenticated backup stream traversal, directory browsing, and unauthorized tape/disk storage access.
     - **iSCSI Internet Small Computer Systems Interface (3260/tcp)**: Probes unauthenticated SendTargets discovery, anonymous target listing, and LUN volume attachment where mutual CHAP authentication is unenforced.
   - **Out-of-Band & Hardware Management**:
     - **IPMI 2.0 / RMCP+ (623/udp)**: Evaluates Baseboard Management Controller (BMC) interfaces for IPMI 2.0 Cipher Suite 0 authentication bypass (granting unauthenticated root access to lights-out management) and RAKP HMAC-SHA1 password hash retrieval for offline dictionary cracking.
   - **Network Device & Appliance Management**:
     - **Cisco Smart Install / SMI (4786/tcp)**: Detects active Cisco Smart Install client daemons (`vstack`) on network switches, verifying missing authentication allowing unauthorized configuration download/replacement and arbitrary code execution.
     - **TACACS+ AAA (49/tcp)**: Probes Terminal Access Controller Access-Control System Plus authentication daemons, evaluating daemon exposure, weak pre-shared obfuscation keys, and lack of TLS encapsulation (RFC 8907).
   - **VPN & Tunneling Services**:
     - **IPsec / IKEv1 (500/udp)**: Evaluates Internet Key Exchange daemons for IKEv1 Aggressive Mode support returning pre-shared key (PSK) negotiation hashes subject to offline dictionary cracking.
     - **PPTP Point-to-Point Tunneling Protocol (1723/tcp)**: Probes legacy PPTP VPN endpoints relying on vulnerable MS-CHAPv2 challenge-response authentication susceptible to DES key reduction and offline hash cracking.
   - **Proxy & Egress Services**:
     - **SOCKS Proxy (1080/tcp)**: Tests SOCKS4 and SOCKS5 proxy endpoints for open network relaying without RFC 1929 authentication, evaluating unauthorized internal network pivoting.
     - **Squid HTTP Proxy (3128/tcp)**: Evaluates caching and forward HTTP proxy daemons for unrestricted client access control lists (ACLs) permitting open web relaying and internal cloud metadata/loopback SSRF pivoting.

2. **Proxy Egress Restriction Testing**:
   - For all proxy and egress services (SOCKS, Squid), explicitly tests and records whether destination egress is unrestricted or governed by strict network boundaries:
     - `proxy_egress_tested`: Boolean flag confirming active egress policy verification.
     - `proxy_egress_restricted`: Boolean indicating whether outbound access to internal loopback, metadata addresses (`169.254.169.254`), or arbitrary external subnets is denied.

3. **Explicit Execution Effect Classification & Plan Binding**:
   - Operations declare their operational effect using `ExecutionEffect`:
     - `read_only`: Passive banner checking, SendTargets enumeration, RAKP hash retrieval.
     - `non_destructive`: Benign connection handshakes, proxy relay ping probes.
     - `state_change`: Initiating a temporary storage session or proxy circuit.
     - `code_execution`: Verifying Cisco Smart Install config replacement or IPMI Cipher 0 BMC command execution.
   - Probes that can execute code (`can_execute_code`) or modify state (`can_change_state`) MUST be explicitly authorized via `--allow-code-execution` or `--allow-state-change` and bound to the approved action plan. Unauthorized code execution attempts are blocked by default.

4. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If an interface times out, is connection-refused, or is filtered by network firewalls, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** reported as `protected` or `hardened` merely because it failed to respond. Only affirmative proof of authentication enforcement (e.g. CHAP rejection, RAKP authentication failure, disabled cipher 0, strict proxy ACL deny) warrants a `protected` or `remediated` status.

5. **Non-Destructive Canary Testing with Cryptographic Cleanup Receipts**:
   - When non-destructive canary identifiers (e.g. `canary_legacy_artifact`, `canary_proxy_probe`) are used, all created test entities are tracked.
   - Every assessment generates a cryptographically hashed `CleanupReceipt` confirming that temporary artifacts were verified removed (`action_taken="verified_removed"`).

6. **Legacy Privilege Candidate Routing**:
   - Discovered misconfigurations and exposure findings are exported as `LegacyPrivilegeCandidate` records:
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
   - Binds cryptographic evidence hashes, auth prerequisites, and privilege impact ratings for handoff to penetration testers and remediators.

## CLI Usage

### 1. Assess Legacy Enterprise, Management, and Proxy Services
```bash
python3 -m cops legacy-services assess \
  --targets "198.51.100.50,storage01.corp.internal" \
  --vantage internal \
  --canary-id "canary_legacy_probe" \
  --output legacy_assessment.json
```

With authorized non-destructive code execution verification:
```bash
python3 -m cops legacy-services assess \
  --targets "198.51.100.50" \
  --services "ipmi,cisco_smart_install" \
  --allow-code-execution \
  --canary-id "canary_smi_probe" \
  --output legacy_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery legacy assess \
  --targets "198.51.100.50" \
  --output legacy_assessment.json
```

### 2. Export Legacy Privilege Candidates
```bash
python3 -m cops legacy-services candidates legacy_assessment.json \
  --output legacy_candidates.json
```

### 3. Export Verified Cleanup Receipts
```bash
python3 -m cops legacy-services cleanup legacy_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Assessment Report
```bash
python3 -m cops legacy-services inspect legacy_assessment.json
```
