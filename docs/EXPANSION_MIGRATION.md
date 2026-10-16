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
Kubernetes enforcement still requires a registered isolated cluster adapter.
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
artifacts. SARIF validation requires the official SARIF 2.1.0 schema and the
GitHub-supported subset checks. Markdown suggestions require a verified source
revision and valid file/line anchors. Export does not post to a hosted service.

Run `make check` and `make check-docs` in the declared contributor environment.
Run `make check-laboratory` separately for laboratory readiness; `make check`
remains portable. A blocked isolation prerequisite or unavailable required
platform leaves the corresponding capability incomplete. Preserve native
filesystem and worker CI. Record revision, input digests, commands, outcomes,
and limitations using the [acceptance report](EXPANSION_ACCEPTANCE.md).
