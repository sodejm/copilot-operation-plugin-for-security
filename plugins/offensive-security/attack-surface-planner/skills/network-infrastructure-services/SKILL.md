---
name: network-infrastructure-services
description: Assess DNS/mDNS, SNMP, NTP, discovery utilities, RPC, LDAP, and Kerberos service exposure with protocol-specific collectors, explicit authentication prerequisites, canary verification, and Active Directory attack-path handoff.
---

# Network infrastructure services

1. **Protocol-Specific Infrastructure Probes**:
   - Assess exposure of DNS, mDNS, SNMP, NTP, RPC endpoint mapper, LDAP, and Kerberos services across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Authentication Prerequisites & Identity Attack-Paths**:
   - Determine whether services require authentication (`none`, `default_credentials`, `domain_user`, `kerberos_preauth_disabled`, `elevated_user`).
   - Extract `IdentityAttackPathCandidate` entries for lateral movement and Active Directory inventory handoffs.

3. **Canary Records and Boundary Validation**:
   - Validate access controls using benign canary identifiers (`canary.corp.internal`, `canary-user`) without touching production directory data or credentials.

4. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

5. **CLI Invocation**:
   ```bash
   python3 -m cops discovery infrastructure assess --targets dc01.corp.internal --output infra_report.json
   python3 -m cops discovery infrastructure candidates infra_report.json --output ad_candidates.json
   python3 -m cops discovery infrastructure inspect infra_report.json
   ```
