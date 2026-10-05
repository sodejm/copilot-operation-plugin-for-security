---
name: network-remote-and-file-services
description: Assess remote administration (SSH, Telnet, RDP, VNC, WinRM, X11), file sharing (SMB, NFS, FTP/TFTP, rsync, AFP), and printing services (LPD, IPP, Raw/JetDirect) with canary verification, cleanup receipts, legacy version tracking, and host privilege candidate routing.
---

# Remote Administration, File Sharing, and Printing Services Assessment

Execute authorized, protocol-specific assessments across remote administration, file sharing, and network printing services under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Coverage**:
   - **Remote Administration**:
     - **SSH (22)**: Evaluates publickey vs password authentication, banner versions, and deprecated ciphers.
     - **Telnet (23)**: Detects plaintext administration interfaces and credential exposure risks.
     - **RDP (3389)**: Checks Network Level Authentication (NLA) enforcement, pre-auth screen exposure, and RDP/SSL encryption layers.
     - **VNC (5900)**: Probes RFB protocol handshake for missing or weak authentication.
     - **WinRM (5985/5986)**: Detects unencrypted HTTP management endpoints vs TLS-enforced HTTPS endpoints.
     - **X11 (6000)**: Identifies open, unauthenticated remote X11 display server access.
   - **File Sharing Services**:
     - **SMB (445)**: Audits SMBv1 legacy protocol enablement, mandatory SMB message signing, and anonymous/guest share access.
     - **NFS (2049)**: Detects world-readable exports and `no_root_squash` configurations enabling privilege escalation.
     - **FTP (21) / TFTP (69)**: Probes anonymous FTP read/write permissions and unencrypted file transmission.
     - **rsync (873)**: Identifies unauthenticated rsync daemon modules exposing local file structures.
     - **AFP (548)**: Assesses Apple Filing Protocol guest logins and share exposure.
   - **Printing Services**:
     - **LPD (515), IPP (631), Raw/JetDirect (9100)**: Evaluates unauthenticated print queue submissions and printer reconnaissance.

2. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If a remote administration, file sharing, or printing service is timed out, connection-refused, filtered, or unreachable from the current assessment vantage, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** reported as `protected` or `hardened` merely because it failed to respond. Only positive verification of explicit authentication enforcement (e.g. NLA enforced, SSH public key required, SMB signing required) or authorization rejection warrants a `protected` status.

3. **Canary Validation and Verifiable Cleanup Receipts**:
   - Uses non-destructive canary artifacts (e.g. `canary_share/audit.tmp` or synthetic print jobs `canary_print_job_probe`) to confirm access controls and write boundaries.
   - Every assessment that touches a canary artifact generates a cryptographically hashed `CleanupReceipt` confirming that test artifacts were removed and the system state was restored (`verified_removed`).

4. **Host Privilege Candidate Routing**:
   - Discovered misconfigurations and weak boundaries are structured as `HostPrivilegeCandidate` records:
     - `smb_legacy_smbv1`: SMBv1 enabled (vulnerable to EternalBlue / lateral movement).
     - `smb_signing_disabled`: Missing packet signing (vulnerable to NTLM relay attacks).
     - `smb_unauthenticated_share`: Null/guest share access.
     - `telnet_plaintext_exposure`: Plaintext administration credentials.
     - `rdp_nla_disabled`: Pre-auth RDP login screen without NLA.
     - `vnc_no_auth`: Unauthenticated RFB access to graphical desktop.
     - `winrm_http_unencrypted`: Unencrypted WinRM HTTP management.
     - `x11_open_display`: Unauthenticated X11 remote client control.
     - `nfs_no_root_squash`: NFS root squash disabled (privilege escalation).
     - `ftp_anonymous_login`: Anonymous FTP access.
     - `rsync_open_module`: Open rsync modules without credentials.
     - `unauthenticated_printer_queue`: Open printer submission queues.
   - Binds cryptographic evidence hashes, auth prerequisites, and lateral movement impact ratings (`command_execution`, `credential_harvesting`, `data_exfiltration`, `privilege_escalation`, `unauthorized_printing`) for handoff to host and lateral movement specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

## CLI Usage

### 1. Assess Remote, File, and Print Services
```bash
python3 -m cops remote-services assess \
  --targets "198.51.100.20,fileserver01.corp.internal" \
  --vantage internal \
  --canary-id "canary_share/audit.tmp" \
  --output remote_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery remote assess \
  --targets "198.51.100.20,fileserver01.corp.internal" \
  --vantage internal \
  --output remote_assessment.json
```

### 2. Export Host Privilege Candidates for Specialist Workflows
```bash
python3 -m cops remote-services candidates remote_assessment.json \
  --output host_candidates.json
```

### 3. Export Verified Cleanup Receipts
```bash
python3 -m cops remote-services cleanup remote_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Summary, Privilege Candidates, and Truth-in-Advertising Metrics
```bash
python3 -m cops remote-services inspect remote_assessment.json
```
