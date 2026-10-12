# COPS AD Assessment Workbench: end-to-end verification

## Scope and prerequisites

Qualify local AD export validation, inventory, relationships, and candidate identity paths. An exported relationship or protected-group condition does not demonstrate a live privilege crossing.

Use a trusted repository checkout, Python 3.11 or newer, and the prerequisites
in [the package README](../README.md). Run the commands from the repository root
in Bash (Git Bash on Windows). Record actual tool/host versions and input digests.
Use only synthetic or authorized sanitized inputs; keep output evidence private.

## Baseline checks

```bash
python3 -m cops info ad-assessment-workbench
python3 -m cops demo ad-assessment-workbench
python3 -m cops check ad-assessment-workbench
```

Confirm discovery, inspect the demo result, and retain the complete package-gate
output. A passing gate does not substitute for the manual comparisons below.

## End-to-end exercise

```bash
P=plugins/identity-access/ad-assessment-workbench
python3 "$P/scripts/run_demo.py"
```

Use fixtures/synthetic-two-forest.json as the source oracle: independently enumerate forests, domain-qualified identities, cross-forest relationships, and protected groups. Compare them with the demo analysis. Repeat through the README's import workflow with a sanitized export and independently recorded expected relationships.

## Acceptance criteria

- Forest/domain identity stays attached to objects; same-name identities across forests do not collapse.
- Candidate paths retain their evidence references and prerequisites. Protected groups and incomplete imports do not imply successful escalation.
- Package tests cover malformed inventory and missing/ambiguous identity or relationship evidence. Source counts and coverage gaps reconcile with the imported export.
- The report states offline scope and leaves live collection, authorization, and privilege-boundary verification unqualified.

Compare observed results with an independently prepared expected answer. Record
each criterion separately; identify failures, unperformed steps, and blockers.

## Failure and recovery

Use a copied export with a missing relationship or ambiguous identity and check that the result rejects it or marks the path incomplete. Restore the valid export and repeat. Confirm no domain query or account/group mutation occurred and source fixture digests stayed fixed.

Repeat the complete exercise in a fresh environment with a second operator.
Retain the repeat record and compare semantic results, input digests, and
deterministic artifact digests. Explain expected timestamp/metadata differences.

## Host exercise

Install the documented adapter/export in each advertised host/OS using a clean
profile. Invoke **ad-inventory-and-paths** through that host's documented skill/agent mechanism.
Supply the same synthetic input and a private output destination with this task:

> Analyze this synthetic two-forest export. Produce a domain-qualified inventory and candidate relationship paths with protected-group constraints, source evidence, and incomplete coverage. Do not query a domain or claim a verified privilege crossing.

Check discovery, referenced-file/script resolution, output against the CLI and
independent oracle, refusal/uncertainty behavior, and test-installation cleanup.
Record unavailable hosts as blocked and failed installation/invocation as failed.
The host exercise itself supplies no live-service or offensive-action authority.

## Record and promote

Follow [the shared qualification and status-update guide](https://sodejm.github.io/copilot-operation-plugin-for-security/plugin-verification.html)
to save a sanitized run record, apply every intervening maturity gate, and request
independent review. After acceptance, update package.json maturity and all public
status labels together, link the accepted record here and in the README, and run
the repository checks. Keep unsupported integrations and remaining gaps explicit.
No status changes automatically when these commands finish.
