# Local agent and MCP laboratories (E16.01)

## Scope

The Foundry Agent Harness gains a reproducible local laboratory for synthetic agent and MCP boundary cases. It uses a deterministic proposal fixture and a separate MCP stdio server. It does not connect to Microsoft Foundry, Semantic Kernel, a hosted model, a live MCP server, or a network endpoint. Results establish behavior of these fixtures and their independent authorization gate only.

This laboratory complements the existing scenario simulator. It is also distinct from the signed operator scenario laboratory in `cops/laboratory/`, whose engagement and worker contracts do not apply to this fixed offline fixture.

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
- The manifest playback invokes the actual legacy `evaluate` command over the six
  pinned scenarios, requires one attempted and denied call per scenario with no
  mock effects or model execution, compares normalized reruns, and proves that a
  copied scenario without environment approval is rejected.

## Threat and abuse cases

Untrusted content can claim higher priority, impersonate a peer, request cross-tenant access, or supply a tool call marker. The proposal fixture deliberately parses that marker so the gate can be exercised. It has no tool access. The MCP fixture accepts only fixed synthetic operations over stdio. The gate's allowlists prevent the proposal from selecting a process, tenant, resource, or network destination. This is process and data isolation within the local fixture design, not an operating-system network sandbox; run it only with synthetic case data and do not interpret its result as live-model resistance.
