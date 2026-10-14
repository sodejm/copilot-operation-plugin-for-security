# Offline AI provider assessment contract (E16.02)

## Scope

The Foundry Agent Harness imports fixed, synthetic response fixtures for OpenAI Responses, Azure OpenAI Responses, AWS Bedrock Converse, and GCP Vertex generateContent. It applies one versioned plan, exact request binding, provider-specific terminal-state normalization, and the shared assessment budget ledger. No provider request, credential lookup, tool call, or network connection is made. Source family `COPS-E16.02` is provisional; per-file source mappings await E01.1.

## Inputs and decision order

- A plan names each provider environment's account or tenant, project or subscription, region, endpoint, model, allowed tool names, canary IDs, and approved canonical request digests. Its execution mode is `offline_fixture` and paid opt-in is false. It carries an engagement-scoped budget policy and pinned synthetic price metadata.
- Each case identifies one environment, exact scope and endpoint, requested tool names, a synthetic canary request, an estimate, and an inline provider-shaped response fixture. Strict bounded JSON parsing rejects duplicate keys, non-finite JSON constants, excessive nesting, unknown fields, oversized input, and non-synthetic canary strings, including in a case whose response would not be processed.
- Validate the case against the plan before budget reservation. Exact environment, scope, endpoint, model, canary, tool allowlist, and request digest must match. A denied case must not consume an attempt or process its response fixture.
- Reserve each approved case in the durable budget ledger before processing its fixture. Budget refusal does not process the response. Only after authorization and budget admission, validate the response against the strict provider-specific envelope schema; a malformed or cross-provider envelope fails the assessment instead of being normalized. A proposed tool name must appear in the approved request's tool set. Reported output tokens must not exceed the approved request cap, even for partial responses. Missing or ambiguous usage retains the reservation as `usage_unknown`; a known terminal fixture reconciles fixture-reported token counts with a synthetic cost receipt. Costs are fixture values, not provider billing evidence.

## Evidence and exit status

The report contains deterministic SHA-256 case references produced by `report_case_id`, provider family, gate decision, normalized outcome, response and usage classification, ledger state, expectation result, budget snapshot, and temporary-ledger cleanup verification. It does not contain the source case IDs, prompts, response text, endpoint URLs, account identifiers, canary values, or credentials. The hashes are stable pseudonymous correlators, not secrecy or anonymity controls. Provider tool calls are proposals only; this importer never executes them. Unknown provider status and partial output do not become findings or effects. An unmet expectation, cleanup failure, malformed admitted envelope, or `budget.over_budget: true` exits nonzero; the JSON report is still emitted for a completed run so reviewers can inspect the overrun and cleanup state. If temporary-ledger deletion raises a filesystem error, the runner reports `cleanup_verified: false` and exits nonzero.

## Acceptance

- Bundled fixtures cover all four families, a wrong environment binding, an unapproved tool, a denied endpoint, budget exhaustion, a partial response with unknown usage, and a remediated denial with no effect.
- The same synthetic plan and report contract applies to every provider family. After admission, strict envelopes require OpenAI or Azure `status` and `output`, AWS `stopReason` and `output.message.content` with a tool-use item when applicable, or one GCP candidate with `content.parts` and `finishReason`; unknown properties and unsupported shapes fail validation before normalization into the common outcome vocabulary.
- The runner rejects any `live` or paid plan and offers no live switch. A real provider adapter requires separately authorized isolated worker egress capable of exact POST origin, path, request body, and identity binding. The current shared egress broker permits only GET and HEAD.
- Focused tests, the package validator, `python -m cops check foundry-agent-harness`, and `make check` run in a virtual environment.

## Threat and abuse cases

An attacker can substitute another tenant, model, endpoint, request body, tool, or canary; forge a successful response; omit usage; or place sensitive strings in nested provider output. Exact binding, conservative budget accounting, and allowlisted report fields limit the offline consequence. The importer cannot authenticate a provider response or prove remote billing, cleanup, content filtering, or any real model behavior. Live execution remains blocked until the execution boundary and independent security review are complete.
