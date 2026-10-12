# Local agent and MCP laboratories (E16.01)

## Scope

The Foundry Agent Harness gains a reproducible local laboratory for synthetic agent and MCP boundary cases. It uses a deterministic proposal fixture and a separate MCP stdio server. It does not connect to Microsoft Foundry, Semantic Kernel, a hosted model, a live MCP server, or a network endpoint. Results establish behavior of these fixtures and their independent authorization gate only.

This laboratory complements the existing scenario simulator. The original `lab` workflow remains distinct from the signed operator scenario laboratory in `cops/laboratory/`. The issue #236 authorization extension below reuses COPS Action Plan, signed execution authorization, engagement, and approval-store contracts for its separate batch workflow.

## Inputs and provenance

- A case is a versioned JSON object conforming to `schemas/lab-case.schema.json`. Unknown fields, arbitrary commands, unsupported tools, tenants, resources, destinations, or control profiles fail closed.
- The bundled cases cover retrieval, tool response, cross-tenant, peer message, state change, data exfiltration, memory, context, and tool-permission surfaces, plus authorized controls.
- The source family is `COPS-E16.01 (provisional)`. The pinned S01 and S02 source inventories are contextual provenance only; per-file source-to-case mapping is deferred to E01.1. The cases are synthetic and do not claim a finding from those inventories.
- The only tenant IDs, accounts, resources, and canary are synthetic. Case text is data, and the runtime never takes a process command or network target from it.

## Execution and observations

1. Start fresh fixed local Python fixture processes in a temporary directory, with bounded stdio responses and deadlines. Complete the MCP protocol handshake and verify the advertised tool inventory.
2. Read the MCP fixture state. In the tool-response case, obtain the injected text through an actual MCP lookup before presenting it to the agent fixture.
3. Capture fixture text and the proposed call separately. An independent gate checks tool permission, tenant, exact argument shape, fixed resource and destination allowlists, and, under the strict profile, equality to the trusted approved call.
4. Record denied calls without forwarding them. Record permitted calls only after MCP execution. Read state again and derive effects exclusively from the difference in observed fixture state. A tool response or model text alone is never evidence of an effect.
5. Reset fixture state and verify the reset before reporting the case expectation. Each case uses fresh processes and temporary storage.

A `permission_only` profile intentionally demonstrates the consequence of checking tool and tenant permission without binding a proposed call to the trusted task approval. A paired `strict` case must deny the same injected proposal. The baseline is a controlled local example, not a real agent compromise.

Reports separate `model_text`, `attempted_calls`, `denied_calls`, `executed_calls`, `executed_effects`, before/after state, fixture verification, and cleanup verification. An unmet expected outcome or failed cleanup makes the command fail. Malformed protocol or unverifiable state is an error.

## Acceptance

- Bundled cases run through the local agent and MCP fixture processes, including an observed effect in the permissive baseline and no effect in the strict paired case.
- Foreign tenant, unauthorized tool, and non-local destination proposals are denied before execution.
- A permitted read is an executed call with no state effect; a permitted mutation or canary export has an observed state effect.
- The CLI emits a versioned JSON run report and a concise human summary, with a nonzero status for unmet expectations.
- Focused tests, the package validator, `python3 -m cops check foundry-agent-harness`, and `make check` pass.

## Threat and abuse cases

Untrusted content can claim higher priority, impersonate a peer, request cross-tenant access, or supply a tool call marker. The proposal fixture deliberately parses that marker so the gate can be exercised. It has no tool access. The MCP fixture accepts only fixed synthetic operations over stdio. The gate's allowlists prevent the proposal from selecting a process, tenant, resource, or network destination. This is process and data isolation within the local fixture design, not an operating-system network sandbox; run it only with synthetic case data and do not interpret its result as live-model resistance.

## Agent delegation and MCP authorization boundary extension (issue 236)

The extension is a separate local synthetic pack. Its versioned case, adapter, evidence, and run contracts record a redacted principal, agent or service, downstream audience, tenant, resource, operation, caller-presented scopes, decision, and independently observed effect. Only fixed synthetic aliases and grants are accepted; case input never selects a process, network destination, credential, or arbitrary tool. No bearer token is stored or printed. The fixture speaks MCP 2025-11-25 over stdio, which is a local transport demonstration and makes no OAuth or HTTP authorization compliance claim.

The fixture checks the pinned server name, version, protocol, capability, and exact tool inventory before testing. It separates authentication of the synthetic grant and actor from authorization of audience, tenant, operation, scope, tool permission, and delegation depth. A normal reusable bearer grant may be used twice; a grant explicitly marked one-time rejects a second use. Logical expiry and revocation are checked at the attempt time. The revocation case records a synthetic zero-tick decision window; it does not measure provider propagation.

Each case starts a separate peer that forwards the approved request or a declared hostile mutation, plus a fresh target server. Request, decision, and effect records bind plan digest, test identity, and attempt, request, and canary IDs. The runner reads a side-effect ledger directly from its private temporary directory; tool replies cannot establish execution. Missing tenant context or malformed observer data, failed setup, or failed cleanup yields inconclusive evidence. A `finally` path terminates both processes and independently checks removal of temporary storage on errors, timeouts, and cancellation. Positive delegated and autonomous controls require an observed canary effect; denied cases require none. Expected inconclusive tests can match their expectation without supplying complete boundary evidence.

`auth-plan` binds the entire selected batch, both fixture identities, runtime source hashes, requests, expectations, and aggregate limits in one immutable Action Plan. `auth-lab` verifies the signed receipt against that plan, active engagement, trust store, and worker identity, then atomically consumes it before any process starts. Approved cases execute without further prompts. Expiry, cancellation, output or duration exhaustion stops admission and reports partial results, pending cases, and the next action. Eight seconds of duration are reserved for cleanup. Retrying pending cases requires a new approved plan; this command has no durable crash-resume checkpoint. A COPS receipt never replaces the target's independently checked grant.

Acceptance includes competing uses of one receipt, mutation of approved inputs, aggregate accounting across cases, bounded response timeouts, hostile peer forwarding, independent effects, and cleanup. The approval store uses POSIX ownership checks; fixtures do not establish native Windows acceptance or OS-enforced denied egress. The v1 contracts describe only the fixed synthetic fixture. An external adapter requires separate versioning, provider-specific identity and permission pins, and an independent effect observer; this issue claims no provider behavior or live-service coverage.
