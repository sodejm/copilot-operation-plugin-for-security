---
name: network-remote-and-file-services
description: Assess remote administration (SSH, Telnet, RDP, VNC, WinRM, X11), file sharing (SMB, NFS, FTP/TFTP, rsync, AFP), and printing services (LPD, IPP, Raw/JetDirect) with canary verification, cleanup receipts, legacy version tracking, and host privilege candidate routing.
---

# Remote administration, file sharing, and printing services

1. **Protocol-Specific Remote, File, and Printing Probes**:
   - Assess exposure of remote admin (SSH, Telnet, RDP, VNC, WinRM, X11), file sharing (SMB, NFS, FTP/TFTP, rsync, AFP), and printing services (LPD, IPP, Raw/JetDirect) across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Authentication Prerequisites & Host Privilege Routing**:
   - Determine whether services require authentication (`none`, `anonymous`, `default_credentials`, `user_password`, `public_key`, `nla_required`, `kerberos`, `unknown`).
   - Extract `HostPrivilegeCandidate` entries for lateral movement and host privilege escalation workflows.

3. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate access controls using benign canary identifiers (`canary_share/audit.tmp`, `canary_print_job_probe`) without touching sensitive host files.
   - Emit verified `CleanupReceipt` records confirming rollback and artifact removal.

4. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

5. **CLI Invocation**:
   ```bash
   python3 -m cops remote-services assess --targets fileserver01.corp.internal --canary-id "canary_share/audit.tmp" --output remote_report.json
   python3 -m cops remote-services candidates remote_report.json --output host_candidates.json
   python3 -m cops remote-services cleanup remote_report.json --output cleanup_receipts.json
   python3 -m cops remote-services inspect remote_report.json
   ```
