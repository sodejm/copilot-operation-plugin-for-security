---
name: network-developer-interfaces
description: Assess developer and runtime interfaces (Docker, Docker Registry, RMI, JDWP, Erlang EPMD, ADB, distcc, SVN, AJP, FastCGI) with execution effect classification, canary verification, cleanup receipts, and developer privilege candidate routing.
---

# Developer and Runtime Interfaces

1. **Protocol-Specific Developer & Debugging Interface Probes**:
   - Assess exposure of container runtimes (Docker API, Docker Registry), debugging ports (Java RMI, JDWP, Erlang EPMD, ADB), distributed build tools (distcc, SVN), and gateway interfaces (AJP, FastCGI) across approved targets.
   - Ground assessments in observed protocol responses, versions, and configurations.

2. **Execution Effect Classification & Plan Binding**:
   - Explicitly declare `ExecutionEffect`: `read_only`, `non_destructive`, `state_change`, `code_execution`.
   - Require explicit authorization flags (`--allow-code-execution`, `--allow-state-change`) bound to the approved action plan before attempting intrusive probes.

3. **Application vs Infrastructure Specialist Routing**:
   - Route application behavior to web/API workflows and cluster paths to Kubernetes context establishment (`cops-web-specialist`, `cops-cloud-specialist`, `cops-pentest-specialist`).

4. **Inaccessible != Secure Truth Boundary**:
   - Strictly mark unreachable, filtered, or connection-refused services as `inaccessible` (with `auth_prerequisite: unknown`). Never claim unverified services are protected or secure.

5. **Canary Validation and Verifiable Cleanup Receipts**:
   - Validate access controls using benign canary identifiers (`canary_docker_probe`, `canary_debug_probe`) without disrupting production workflows.
   - Emit verified `CleanupReceipt` records confirming rollback and artifact removal (`verified_removed`).

6. **CLI Invocation**:
   ```bash
   python3 -m cops developer-services assess --targets dev01.corp.internal --canary-id "canary_docker_probe" --output dev_report.json
   python3 -m cops developer-services candidates dev_report.json --output dev_candidates.json
   python3 -m cops developer-services cleanup dev_report.json --output cleanup_receipts.json
   python3 -m cops developer-services inspect dev_report.json
   ```
