---
name: network-developer-interfaces
description: Assess developer and runtime interfaces (Docker, Docker Registry, RMI, JDWP, Erlang EPMD, ADB, distcc, SVN, AJP, FastCGI) with execution effect classification, canary verification, cleanup receipts, and developer privilege candidate routing.
---

# Developer and Runtime Interfaces Assessment

Execute authorized, bounded exposure and configuration assessments across developer tooling, debugging endpoints, distributed build systems, and application gateway interfaces under strict Rules of Engagement and operational boundaries.

## Core Capabilities

1. **Protocol-Specific Coverage**:
   - **Container & Orchestration Runtimes**:
     - **Docker Engine API (2375, 2376)**: Evaluates unauthenticated TCP socket access (port 2375) allowing container breakout and host root takeover; checks mutual TLS client certificate verification on port 2376.
     - **Docker Registry v2 (5000)**: Evaluates anonymous catalog enumeration (`/v2/_catalog`), unauthorized image pulling, and manifest tampering without token authentication or TLS.
   - **Language & Debugging Runtimes**:
     - **Java RMI Registry (1099)**: Probes unauthenticated Java Remote Method Invocation registry, object binding enumeration, and remote codebase deserialization exploitability.
     - **Java Debug Wire Protocol / JDWP (8000, 5005)**: Detects raw JDWP handshake handshake response, verifying active debugging agent exposure without authentication permitting remote class loading and arbitrary command execution.
     - **Erlang Port Mapper Daemon / EPMD (4369)**: Probes node name enumeration, node port discovery, and Erlang cookie authentication enforcement on distributed nodes.
     - **Android Debug Bridge / ADB (5555)**: Detects open wireless ADB network daemon, testing whether authentication is bypassed to allow interactive root shell access and APK installation.
   - **Distributed Build & SCM**:
     - **distcc Distributed Compiler (3632)**: Evaluates unauthenticated compilation daemon, detecting missing `--allow` CIDR IP restriction that permits arbitrary shell command execution via crafted compilation tasks.
     - **Subversion svnserve / SVN (3690)**: Probes repository checkout without credentials (`anon-access = read/write`), source code leakage, and SASL authentication posture.
   - **Application Server & Gateway Interfaces**:
     - **Apache JServ Protocol / AJP (8009)**: Detects exposed AJP13 connectors, evaluating Ghostcat (CVE-2020-1938) arbitrary file read / RCE and missing `secretRequired` configuration.
     - **FastCGI / PHP-FPM (9000)**: Probes exposed FastCGI daemon on external interfaces, testing for unauthenticated FastCGI protocol execution permitting remote code execution.

2. **Explicit Execution Effect Classification & Plan Binding**:
   - Every operation explicitly classifies its operational effect using `ExecutionEffect`:
     - `read_only`: Passive banner checking, catalog listing, node mapping without state change.
     - `non_destructive`: Benign version probes, authenticated handshake verification.
     - `state_change`: Spawning a temporary test container or registering a test branch.
     - `code_execution`: Verifying JDWP, distcc, or Docker API command invocation.
   - Probes that can execute code (`can_execute_code`) or modify state (`can_change_state`) MUST be explicitly authorized via `--allow-code-execution` or `--allow-state-change` and bound to the approved action plan. Unauthorized code execution attempts are blocked by default.

3. **Routing Application Behavior vs Infrastructure & Cluster Paths**:
   - Application-layer findings (e.g. AJP servlet exposure, Docker registry manifest contents) route to web and application specialists (`cops-web-specialist`, `cops-appsec-engineer`).
   - Container cluster and cloud control-plane interfaces route to cloud infrastructure specialists (`cops-cloud-specialist`).
   - Host breakout and remote code execution findings route to penetration testing specialists (`cops-pentest-specialist`, `cops-redteam-operator`).

4. **Crucial Truth Boundary: Inaccessible != Secure**:
   - If an interface times out, is connection-refused, or is filtered by network controls, it is strictly recorded as `inaccessible` with `auth_prerequisite: unknown` and explicit uncertainty notes.
   - A service is **NEVER** reported as `protected` or `hardened` merely because it failed to respond. Only affirmative proof of authentication enforcement (e.g. mTLS challenge, htpasswd prompt, SASL rejection) warrants a `protected` status.

5. **Canary Validation and Verifiable Cleanup Receipts**:
   - When non-destructive canary identifiers (e.g. `canary_docker_container`, `canary_debug_probe`) are used, all created test entities are tracked.
   - Every assessment generates a cryptographically hashed `CleanupReceipt` confirming that temporary artifacts were verified removed (`verified_removed`).

6. **Developer Privilege Candidate Routing**:
   - Discovered misconfigurations and code execution interfaces are exported as `DeveloperPrivilegeCandidate` records:
     - `docker_socket_rce`: Unauthenticated Docker daemon socket enabling root container breakout.
     - `docker_registry_leak`: Anonymous Docker registry catalog and private image pull.
     - `rmi_code_execution`: Unauthenticated Java RMI registry allowing remote code execution.
     - `jdwp_code_execution`: Exposed JDWP debugging port enabling arbitrary Java bytecode execution.
     - `erlang_epmd_rce`: Exposed Erlang node distribution with weak/default cookie.
     - `adb_shell_rce`: Unauthenticated wireless ADB daemon granting interactive device shell.
     - `distcc_rce`: Unrestricted distcc compilation daemon allowing arbitrary commands.
     - `svn_anonymous_checkout`: Anonymous Subversion repository access leaking proprietary source.
     - `ajp_ghostcat_rce`: Exposed Apache Tomcat AJP connector vulnerable to Ghostcat.
     - `fastcgi_rce`: Exposed FastCGI network port allowing arbitrary PHP execution.
   - Binds cryptographic evidence hashes, auth prerequisites, and privilege impact ratings for handoff to lateral movement and exploit specialists.

## CLI Usage

### 1. Assess Developer and Runtime Interface Services
```bash
python3 -m cops developer-services assess \
  --targets "198.51.100.50,dev-runner01.corp.internal" \
  --vantage internal \
  --canary-id "canary_debug_probe" \
  --output developer_assessment.json
```

With authorized non-destructive code execution verification:
```bash
python3 -m cops developer-services assess \
  --targets "198.51.100.50" \
  --services "docker,jdwp,distcc" \
  --allow-code-execution \
  --canary-id "canary_docker_probe" \
  --output developer_assessment.json
```

Or via the discovery namespace:
```bash
python3 -m cops discovery developer assess \
  --targets "198.51.100.50" \
  --output developer_assessment.json
```

### 2. Export Developer Privilege Candidates
```bash
python3 -m cops developer-services candidates developer_assessment.json \
  --output developer_candidates.json
```

### 3. Export Verified Cleanup Receipts
```bash
python3 -m cops developer-services cleanup developer_assessment.json \
  --output cleanup_receipts.json
```

### 4. Inspect Summary and Metrics
```bash
python3 -m cops developer-services inspect developer_assessment.json
```
