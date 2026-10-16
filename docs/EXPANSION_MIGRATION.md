# Routing, capability, and workflow migration

This expansion preserves existing plugin IDs and adds six experimental packages,
six specialist profiles, and the existing API workbench. The catalog contains 25
packages, 27 specialist profiles, and 37 canonical scenarios. No production
integration receives `live-validated` status from fixture or laboratory results.

## Routing clients

Use `symptom_triggers`, `artifact_triggers`, `anti_triggers`, and
`example_prompts` when authoring catalog entries. Each package provides five
published examples; held-out routing evaluations live separately under
`tests/fixtures/`. Regenerate host marketplace indexes after catalog changes.

Consumers must inspect the versioned routing result's `status` before selecting
a specialist. Unresolved requests now request clarification instead of silently
selecting SOC investigation. Confidence below 0.65 requests clarification; a
leading-candidate margin below 0.15 presents competing purposes and permission
requirements. Artifact extraction and lexical matching are deterministic.

Model-assisted classification requires explicit configuration and opt-in. Only
redacted features and registered candidate IDs enter that path. An unavailable
model, exceeded deadline or budget, or invalid response leaves the request in
clarification. Classification never grants execution authorization.

Use `python -m cops explain "<request>" --json` for a machine-readable preview.
Execution previews describe proposed effects, exact destinations, required
authorization, evidence, budgets, and unknown estimates without consuming
approvals, starting workers, or invoking action connectors. Context collection
is bounded to supported repository files; it excludes credentials, Terraform
state, history files, and unrelated directories.

## Workflows and evidence

Scenario entries reference versioned definitions in `catalog/workflows/`.
Workflow stages compile into the existing ActionPlan contract. Existing approval
verification remains authoritative. A discovered target or changed action
requires a new validated plan and authorization. Persisted results are bound to
the plan and output digests; resume must reject changed inputs or evidence.

The six integrated examples have offline playback profiles. Some profiles model
the evidence required for a later active operation. A modeled result cannot
establish that containment, consent revocation, cluster enforcement, or cleanup
occurred. See [integrated workflows](INTEGRATED_WORKFLOWS.md) for each boundary.
Five additional service chains now execute disposable HTTP operations with typed
stage inputs and exact, single-use ActionPlan approvals. Their synthetic consent,
advisory, event-rule, and numeric-address models retain explicit production limits;
Kubernetes enforcement now has a separate registered, pinned K3s fixture. The
strict Docker gate requires its image prerequisites and real containment,
restoration and cleanup evidence. See [the Kubernetes runbook](KUBERNETES_LABORATORY.md)
before provisioning the privileged disposable node.
The credential chain now scans actual disposable Git history before revoking the
same synthetic credential. Standalone Git scanning requires `--git-sha256` from a
reviewed local executable; the isolated runtime records that prerequisite during
its image build. Runtime images without the root-owned pin fail this case.

Purple-team consumers should adopt the versioned handoff contract, correlation
IDs, time window, source reference, telemetry, detection result, and evidence
references. Preserve its four outcomes: `instrumentation_gap`, `detection_gap`,
`verified_detection`, and `indeterminate`. Missing evidence cannot become a
verified finding or a passing test. Both logs and alerts must satisfy every
expected telemetry predicate as well as correlation and time bounds. Clients
that previously relied on an unrelated alert sharing those bounds must supply
the expected alert evidence or retain a detection gap.

## Packages and portable exports

The new governance category covers control mapping and evidence sufficiency.
Cloud, supply-chain, segmentation, and TLS packages remain under vulnerability
management; provider and runtime names are tags. Secrets remediation is under
identity and access. Existing primary categories and package IDs stay stable.

Each package includes machine-readable `playbooks/` material, a `walkthroughs/`
guide, and its existing `docs/PLAYBOOK.md` entrypoint. Use the portable exporter
to retain these assets and pinned runtime dependencies together. Heavy parsers
and acquisition tools remain registered adapters with explicit prerequisites;
unsupported formats return limitations rather than successful assessments.

## Reports and readiness

`python -m cops report export --format sarif|junit|pr-markdown` exports review
artifacts. The portable gate now requires offline conformance to the bundled,
hash-pinned official SARIF 2.1.0 schema and the GitHub-supported subset checks;
`COPS_SARIF_SCHEMA_PATH` is no longer used. Markdown suggestions require a verified source
revision and valid file/line anchors. Export does not post to a hosted service.

Run `make check` and `make check-docs` in the declared contributor environment.
Run `make check-laboratory` separately for laboratory readiness; `make check`
remains portable. A blocked isolation prerequisite or unavailable required
platform leaves the corresponding capability incomplete. Preserve native
filesystem and worker CI. Record revision, input digests, commands, outcomes,
and limitations using the [acceptance report](EXPANSION_ACCEPTANCE.md).

## EVTX imports

Existing normalized JSON playback formats remain valid. Binary EVTX now has a
separate `cops telemetry import-evtx` command and `cops.evtx-import/v1` result.
Install the exact optional `evtx` prerequisites on Linux or use the hash-locked
[laboratory runtime](../laboratories/service-runtime/README.md). Other platforms
return `unsupported_parser_platform`. Supply a trusted expected SHA-256; an import
cannot authenticate its operator-supplied digest. Partial imports are indeterminate
for detection coverage. This does not promote native Windows acquisition readiness.

## Raw forensic copies

Existing in-memory artifact envelopes remain supported. The new `cops forensic
import` command accepts a separate versioned manifest and a relative raw-file
path below an explicit root. It returns integrity evidence without promoting
analysis readiness. POSIX no-follow APIs are required, all ancestor symlinks are
rejected, and the default image limit is 128 MiB. E01/AFF4, device capture, native
collection, and filesystem/memory interpretation remain separate adapter work.


## Typed network inputs

The legacy `segmentation_model` remains an allow-graph format. Use new versioned
`firewall_policy`, `kubernetes_network_policy`, `flow_evidence` and `dns_evidence`
artifacts for ordered rules and timestamped observations. They require explicit
completeness and expected paths/address sets. A malformed legacy action now yields
unknown coverage. Neither format establishes actual firewall or CNI enforcement.

## Cryptographic verification

Legacy `tls_config`, `jwt` and `jwks` metadata artifacts remain compatible.
New `certificate_chain` and `jwt_verification` artifacts use the optional pinned
`crypto` extra and explicit local trust. Reports add `verification_results` with
accepted, rejected or unknown outcomes. A rejection is a local observation,
not a remote vulnerability. Missing dependencies or trust remain unknown.
See the [typed contract](../plugins/vulnerability-management/tls-crypto-workbench/docs/CRYPTO_INPUTS.md).

## Credential pattern coverage

The Git scanner keeps schema `cops.git-history-scan/v1` and adds registered potential
credential patterns. Complete empty-match scans now use `no_supported_match_observed`;
the assessor still reads legacy `no_synthetic_match_observed` results. Synthetic
fingerprints retain their original domain for laboratory correlation; other values
use `cops.credential/v1`. Consumers must retain pattern IDs and coverage limitations.
Pattern matches cannot establish provider validity or revocation.

## CVE component binding

CVE playback now requires complete dependency inventories with exact name,
ecosystem, version and source digest identities. Replace loose module-name
lists with timestamped, referenced invocation records bound to those components.
Unbound controls cannot lower priority. The added corrected profile reports
`known_corrected_component`; absent or malformed evidence stays insufficient.
No profile establishes general non-exploitability.

## Consent export binding

Consent workflow inputs now require `service_principals` and `coverage` alongside
`grants` and `signins`. Supply explicit collection completeness, tenant, observation
window, record timestamps and evidence references. Grant `client_id` is a service
principal object ID; sign-in `app_id` is the application ID reached through that
principal. Principal-specific grants also require a matching user. Older loose
risk arrays cannot establish a target. The added `limited` profile remains
insufficient; corrected assertions produce only a bounded negative observation.

## Exposure observation binding

Exposure workflow scope now lists exact `scheme`, `host`, `port` and `route`
endpoints plus a timezone-aware `window`. DNS, connection and authentication
sections require `complete: true`, timestamped references and matching addresses.
Loose host lists or anonymous status arrays no longer establish coverage. Supply
authorized status 200 and an observed anonymous status for every endpoint. The
new `limited` fixture demonstrates insufficient coverage; a clean result remains
restricted to the supplied endpoints and window.
