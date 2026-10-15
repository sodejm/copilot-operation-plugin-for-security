# COPS Web API Assessment Workbench

The **Web API Assessment Workbench** enables security engineers, penetration testers, and application security reviewers to build structured API inventories, model endpoints and bounded session contexts, and prepare controlled request replays under strict destination allowlists.

Modern web applications and APIs span RESTful microservices, GraphQL gateways, and real-time WebSocket channels. Probing these endpoints during authorized security assessments requires strict discipline: captured traffic can contain plaintext credentials, unconstrained clients can trigger denial of service or out-of-scope egress, and session bleeding between roles can distort authorization findings.

The Web API Assessment Workbench provides **structured intake, deterministic token redaction, and bounded replay gates**:
- **Multi-Format Traffic & Schema Ingestion**: Import HTTP captures (HAR 1.2), API schemas (OpenAPI 3.x, Swagger 2.0), Postman collections (v2.0, v2.1), and raw HTTP request transcripts.
- **Deterministic Credential Redaction**: Tokenizes and redacts sensitive credentials (Authorization headers, session cookies, API tokens, passwords) using irreversible SHA-256 hashes (`[REDACTED:<hash>]`) before they enter stored inventory and replay evidence.
- **Endpoint & Session Modeling**: Organizes endpoints by method, protocol (HTTP, GraphQL, WebSocket), path, and authorization requirements, isolating distinct role sessions.
- **DestinationGuard & Budget Boundaries**: Bounded replay strictly enforces allowed target hosts/IPs, maximum request counts, rate limits (RPS), timeout limits, and redirect hop ceilings.
- **Evidence-Based Authorization Assessment**: Classifies owner, other-user, and anonymous REST and GraphQL observations as `pass`, `fail`, or `insufficient_evidence` without treating missing cases as success.
- **Rate-Limit Assessment**: Distinguishes an enforced `429` with retry guidance from an unbounded success sequence or inconclusive transport/server evidence.
- **Protocol Transparency**: Transparently models unsupported protocol features (such as binary streaming or Server-Sent Events) to prevent silent execution anomalies.

---

## When to Use & Security Engineer Playbook

For the operating workflow, see the [Web API Assessment Playbook](docs/PLAYBOOK.md). For repeatable qualification and evidence requirements, see [Web API Assessment Verification](docs/VERIFICATION.md).

Use this workbench when:
- **Auditing Web Application & API Surfaces**: Consolidating diverse API definitions and observed HTTP traffic into a normalized, sanitized asset inventory.
- **Validating Authorization & Session Boundaries**: Testing endpoint accessibility across isolated user roles without session bleeding.
- **Executing Controlled API Replays**: Replaying request sequences against authorized targets with strict rate limits, redirect bounds, and egress guards.
- **Testing REST and GraphQL Controls**: Verifying object authorization and request-rate controls across owner, other-user, and anonymous sessions.

---

## Usage

Run the three package entry points independently from the repository root:

```bash
python3 -m cops info web-api-assessment-workbench
```

```bash
python3 -m cops demo web-api-assessment-workbench
```

```bash
python3 -m cops check web-api-assessment-workbench
```

The demo is offline and synthetic. The check runs the package-owned validation; its result does not qualify a production target or provider.

### Quick Test Drive (Offline Demo)

Execute the offline demonstration showing OpenAPI schema ingestion, automatic token redaction, and synthetic bounded request replay:

```bash
python3 -m cops demo web-api-assessment-workbench

# Or run the demo directly:
python3 plugins/offensive-security/web-api-assessment-workbench/scripts/demo.py
```

### Expected Output
The demo verifies zero network egress (`network_requests: 0`), imports endpoints, applies deterministic redaction, and executes an offline replay session bounded by budget and destination allowlists:
```json
{
  "inventory": {
    "credentials_redacted": true,
    "endpoints_count": 4,
    "name": "OpenAPI Spec: Secure Vault API",
    "target_hosts": [
      "api.vault.internal"
    ]
  },
  "mode": "offline",
  "network_requests": 0,
  "replay_summary": {
    "destination_violations": 0,
    "session_id": "rep-sess-f061a1e7d1e1",
    "total_dispatched": 4,
    "total_failed": 0,
    "total_successful": 4
  },
  "status": "passed"
}
```

---

### Inventory and replay commands

The workbench is exposed via the unified `cops web-api` command:

```bash
# 1. Import API traffic / definitions into a sanitized inventory
python3 -m cops web-api inventory --openapi spec.json --output inventory.json
python3 -m cops web-api inventory --har traffic.har --source-id ENG-01 -o inventory.json
python3 -m cops web-api inventory --postman collection.json -o inventory.json

# 2. Inspect an existing inventory or replay session report
python3 -m cops web-api inspect inventory.json

# 3. Preview a bounded replay without dispatching requests or writing output
python3 -m cops web-api replay \
  -i inventory.json \
  --allow-destination api.target.internal \
  --max-requests 25 \
  --rate-limit 5.0 \
  --mode live \
  --dry-run \
  --json

# 4. Execute an offline synthetic replay with destination guard
python3 -m cops web-api replay \
  -i inventory.json \
  --allow-destination api.target.internal \
  --max-requests 25 \
  --rate-limit 5.0 \
  --mode offline \
  -o replay_report.json
```

The package CLI intentionally supports offline replay only. Live HTTP replay is a Python integration surface that requires a matching `ActionPlan`, approval verification, a ready worker boundary, and a `ScopeGuard` before dispatch:

```python
from cops.web_api import build_replay_action_plan, execute_authorized_replay_session
```

Production-provider validation remains incomplete. Live WebSocket replay is unsupported; WebSocket entries remain inventory and offline-modeling data. Binary streaming and Server-Sent Events are also unsupported.

## Design and data flow

Importers normalize HAR 1.2, OpenAPI 3.x, Swagger 2.0, Postman 2.0/2.1, and raw HTTP into the same redacted inventory without rewriting the source artifact. Replay preparation converts inventory endpoints into bounded requests, checks exact destinations and limits, and produces a side-effect-free preview. Offline replay uses synthetic responses. Live HTTP replay is available only through the approved Python integration described above; no provider adapter is claimed.

| Artifact | Purpose | Producer | Consumer | Validation |
| :--- | :--- | :--- | :--- | :--- |
| Sanitized API inventory | Normalized endpoints, protocols, parameters, target hosts, and source references | HAR 1.2, OpenAPI 3.x/Swagger 2.0, Postman 2.0/2.1, or raw HTTP importer | Inspect, preview, and replay preparation | Schema construction, credential redaction, source-format tests, and inventory inspection |
| Replay preview | Exact request URLs, allowed and target destinations, budget, sanitized evidence, zero effects, and unresolved live observations | `cops web-api replay --dry-run` or `--explain` | Operator and approval planning | Destination and budget validation; tests assert no dispatch, worker, authorization, session, file, or state effects |
| Replay report | Sanitized response observations and bounded execution totals | Offline synthetic replayer or approved live HTTP Python entry point | Authorization and rate-limit assessors | Request budget, destination guard, redirect bounds, response redaction, and report-schema tests |
| Authorization/rate assessment | `pass`, `fail`, or `insufficient_evidence` verdict with case evidence | Object-authorization and rate-limit assessors | Reviewer and evidence record | Owner, other-user, and anonymous REST/GraphQL cases plus bounded `429`, all-success, and incomplete sequences |

## Local Acceptance Fixture

`WebApiAssessmentLaboratory` starts disposable loopback HTTP services in either `vulnerable` or `corrected` mode. Focused tests send real requests through the ActionPlan, approval, worker-readiness, and scope boundaries and verify REST BOLA/IDOR, GraphQL object authorization, and rate-limit failures, fixes, and insufficient evidence. The worker boundary does not provide OS or network isolation, so isolation is still blocked. These local results do not establish behavior for a production provider.

---

## Package Validation

Validate the package integrity, unit tests, and reproducibility gates:

```bash
python3 -m cops check web-api-assessment-workbench
```

Follow [Web API Assessment Verification](docs/VERIFICATION.md) to record the baseline, local-service evidence, failure recovery, and remaining qualification gaps.
