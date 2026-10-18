# COPS changelog

## Unreleased

- Associate Actions checkout inputs with their owning step regardless of key
  order. Exclude adjacent steps, environment mappings and block scalars; report
  duplicate or unsupported input mappings as partial evidence.

- Keep conditional IAM Allow statements unresolved across AWS and Terraform
  inputs. Conditional public principals and wildcard actions no longer become
  verified exposure observations without policy evaluation evidence.

- Keep workflow discovery, validation, and unsigned fixture playback usable
  without optional site packages. Ed25519 evidence signing now loads the
  `crypto` extra only when requested and fails explicitly when unavailable.
- Bind API replay approvals to exact requests, session contexts and complete
  budgets, pin scoped DNS connections, enforce redirect and deadline boundaries, and preserve HTTP
  error responses as evidence. Exercise actual services with signed, persisted
  approvals, use owned execution snapshots, and reject malformed framing,
  post-approval drift, unverified TLS and cross-origin retained bodies or credentials.
- Bound the executable SQL laboratory to its reviewed attack seed, parameterize
  other submitted values, and separate static scanner examples from runtime
  component evidence. Preserve real SQLite/HTTP correction and hash binding.

- Hash exact API import bytes, reject conflicting provenance and raw HTTP
  authorities, and redact URL credentials and query values throughout persisted
  inventory and replay evidence while binding approvals to lossless requests.

- Record revision-bound expansion acceptance, including 13 passing isolated
  laboratory cases, held-out routing results, fixture digests and capability
  limits. Keep unavailable native-platform and production validation incomplete.

- Install hash-pinned synthetic dependency wheels offline, verify installed source,
  and exercise vulnerable/corrected behavior through actual HTTP requests. Require
  tampered-wheel rejection, insufficient-evidence handling and cleanup in the
  isolated laboratory gate; keep installer and platform limitations explicit.

- Require offline SARIF conformance in the portable gate using the unmodified,
  hash-pinned official schema and OASIS notices. Verify vulnerable, corrected and
  inconclusive exports and reject malformed reports without optional test skips.

- Bind exposure audits to exact endpoints, collection windows, DNS addresses and
  authentication evidence. Add actual isolated DNS playback, vulnerable/corrected
  HTTP checks and insufficient-evidence cases; DNS failures verify cleanup.

- Bind consent remediation to complete tenant-scoped exports and exact grant,
  client and application identities. Verify actual synthetic grant revocation
  without interrupting unrelated access; incomplete evidence remains unresolved.

- Bind CVE workflow evidence to exact component versions and source digests,
  record actual laboratory invocations, reject unrelated or malformed evidence,
  and add a distinct corrected-component profile.

- Add pinned, air-gapped Kubernetes containment acceptance with real pod traffic,
  metadata audit logs, plan-bound approvals, and restoration after success,
  failure and cancellation. Require its evidence alongside all twelve service
  cases in the strict laboratory gate.

- Extend pinned Git-history scanning to bounded potential GitHub PAT, AWS identifier,
  Bearer and PEM private-key patterns with redacted provenance, correction cases,
  and explicit validity and coverage limits. Preserve synthetic revocation correlation.

- Add pinned offline certificate-chain and RS256 verification with explicit local
  trust, bounded inputs, content-free outcomes and unknown prerequisite handling.
  Exercise mTLS client authorization and compare offline verification with actual
  ephemeral TLS/JWT service acceptance; production trust and revocation remain separate.

- Add bounded typed firewall and Kubernetes NetworkPolicy predictions, explicit
  flow observations and TTL-bound DNS evidence with correction playback. Unknown,
  stale or contradictory inputs cannot establish effective segmentation.

- Add POSIX raw disk/memory integrity import with bounded streaming, digest-bound
  custody assertions, explicit permission references, and no-follow file access.
  Laboratory acceptance imports actual acquired copies and rejects tampering;
  filesystem/memory analysis and native acquisition remain unsupported.

- Add a registered Linux EVTX importer with pinned parser prerequisites, source
  checksums, resource limits, redacted Sysmon records, and binary correction fixtures.
  Native Windows acquisition remains unvalidated.

- Add centralized Specialist Cybersecurity Agent Profiles directory (`agents/`) with 27
  callable agent profiles across offensive security, defensive operations, incident
  response, digital forensics, identity governance, and compliance.
- Implement deterministic artifact and plain-language routing (`cops.routing` and
  `python3 -m cops route`) with calibrated scores, clarification, skill recommendations,
  and direct mentions. An explicitly configured classifier can assist uncertain routes.
- Propose Triad handoffs for critical operations (Primary Specialist, Domain Skeptic,
  Evidence Auditor). Routing does not start agents or authorize execution.
- Implement Interactive Authorization Gate (`cops.authorization`) with terminal prompts,
  signed execution authorizations bound to concrete plans, a one-use approval store,
  and fail-closed non-interactive behavior. Legacy checksum receipts are rejected.
- Add contributor skill `route-security-specialist` synchronized across agent platforms.
- Add CLI commands `cops route` and `cops specialists`.
- Add context-aware `cops explain`, execution previews, SARIF/JUnit/revision-bound
  Markdown report exports, typed workflows, and purple-team evidence handoffs.
- Add compliance, cloud posture, supply-chain CI/CD, secrets remediation, network
  segmentation, and TLS/crypto packages, and integrate the API inventory/replay
  workbench without replacing its formats. Extend existing packages with bounded
  offline artifact assessments and documented unsupported inputs.
- Add machine-readable playbooks and walkthroughs for all 25 packages, six integrated
  workflow definitions, synthetic fixtures, and portable runtime/asset synchronization.
- Execute five integrated service chains with typed prior outputs, exact action and
  destination approval binding, one-use authorization, signed redacted credential
  evidence, actual service activity, and verified restoration. Preserve synthetic
  emulator and production-integration limits in every report.
- Require every expected telemetry predicate on purple-team alerts. Verify all
  four outcomes using labeled views of captured service activity and execute the
  generated Sigma/KQL subsets against attack and benign events.
- Reject equal and conflicting duplicate expected telemetry field paths with a
  stable error before purple-team handoff output, evidence classification, or
  Sigma/KQL proposal generation. Preserve unique-field handoff digests and rule
  semantics.
- Add `make check-laboratory` as a separate required readiness gate. Functional
  loopback tests alone leave laboratory readiness incomplete. The Docker path uses
  a preinstalled immutable image, inspected isolation, real service activity,
  correlated telemetry, and verified restoration; live production validation remains
  separate. See [migration](docs/EXPANSION_MIGRATION.md) and
  [acceptance](docs/EXPANSION_ACCEPTANCE.md).

- Add COPS SOC Investigation Workbench with two Codex skills, a local case planner,
  evidence and scope checks, branching next-step selection, and tested Sentinel
  vendoring. Canonical Sentinel skills/catalog integration is pending and blocks
  query handoffs and release validation.

- Position COPS as a cybersecurity project for plugins, agents, and skills; document the included capabilities and focused GitHub topics.

- Adopt PARK's portable repository contract, contributor skills, generated Claude
  adapters, documentation, GitHub templates, and validation workflow.
- Integrate plugin validation, unit tests and BDD scenarios into `make check`.
- Rename project documentation and plugin display names to COPS (Copilot
  Operations Plugins for Security), preserving package and marketplace IDs.
- Add the COPS shield and copilot logo, naming guidance and template provenance.
- Correct stale scanner paths and unsupported setup, model and release claims.

Plugin release history remains in
[plugins/logging-telemetry/security-logging-advisor/CHANGELOG.md](plugins/logging-telemetry/security-logging-advisor/CHANGELOG.md).
