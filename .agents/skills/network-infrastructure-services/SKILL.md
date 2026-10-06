---
name: network-infrastructure-services
description: Assess DNS/mDNS, SNMP, NTP, discovery utilities, RPC, LDAP, and Kerberos service exposure with protocol-specific collectors, explicit authentication prerequisites, canary verification, and Active Directory attack-path handoff.
---

# Network Infrastructure & Identity-Facing Services Assessment

Execute authorized, protocol-specific assessments across infrastructure and identity-facing services (DNS, mDNS, SNMP, NTP, discovery utilities, RPC, LDAP, Kerberos) under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Bounded Collectors**:
   - **DNS**: Assesses open recursion and zone exposure using benign query probing.
   - **mDNS / Multicast Discovery**: Evaluates local multicast discovery protocol leakage.
   - **SNMP**: Probes for default community strings (`public`, `private`) and configuration disclosures.
   - **NTP**: Evaluates monlist/Mode 6 query amplification exposure.
   - **RPC Endpoint Mapper**: Enumerates registered RPC interfaces (e.g. MS-RPC port 135) to identify service endpoints.
   - **LDAP**: Tests anonymous or unauthenticated `rootDSE` queries to disclose domain naming contexts, supported SASL mechanisms, and forest topology without pulling directory objects.
   - **Kerberos**: Evaluates Kerberos realm visibility and AS-REP roasting vulnerability by checking pre-authentication requirements for designated accounts.

2. **Strict Inaccessible != Secure Grounding**:
   - If an infrastructure service is timed out, connection-refused, filtered, or unreachable from the current assessment vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** marked as `protected` or `hardened` merely because it failed to respond. Only positive verification of explicit authentication enforcement or authorization rejection warrants a `protected` status.

3. **Canary Records and Controlled Identities**:
   - Uses canary domain lookups (`canary.corp.internal`) and synthetic controlled identity accounts (`canary-user@CORP.INTERNAL`) to validate boundary conditions and authentication barriers without interacting with real user credentials or directory records.

4. **Identity Attack-Path Candidates & AD Inventory Handoff**:
   - Extracts structured `IdentityAttackPathCandidate` records from discovered infrastructure findings:
     - Anonymous LDAP rootDSE disclosure (`ldap_anonymous_reconnaissance`)
     - Kerberos pre-authentication disabled accounts (`asrep_roasting`)
     - Unauthenticated RPC interfaces (`rpc_endpoint_enumeration`)
     - Default community strings leaking system information (`snmp_credential_leak`)
     - Open recursive DNS (`open_dns_recursion`)
     - Monlist amplification (`ntp_mode6_amplification`)
   - Binds concrete evidence hashes and prerequisites for handoff to Active Directory specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

## CLI Usage

### 1. Assess Infrastructure and Identity Services
```bash
python3 -m cops discovery infrastructure assess \
  --targets "198.51.100.10,dc01.corp.internal" \
  --vantage internal \
  --output infra_assessment.json
```

### 2. Extract Identity Attack-Path Candidates for AD Inventory
```bash
python3 -m cops discovery infrastructure candidates infra_assessment.json \
  --output identity_candidates.json
```

### 3. Inspect Assessment Summary and Truth-in-Advertising Metrics
```bash
python3 -m cops discovery infrastructure inspect infra_assessment.json
```
