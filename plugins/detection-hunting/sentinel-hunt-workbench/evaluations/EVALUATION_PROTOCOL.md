# Evaluation protocol

This protocol governs claims about a release candidate. It prevents deterministic
offline checks from being presented as model-host, human, or live-service proof.

## Required evidence classes

1. **Deterministic package evidence** — validation, curated fixtures, seeded
   perturbations, semantic mutations, and adapter integrity for the exact package.
2. **Cross-platform model evidence** — recorded tasks, host and model versions,
   prompts, outcomes, thresholds, limitations, and a subject hash.
3. **Human review evidence** — two distinct qualified reviewers, their decisions,
   timestamps, scope, and the same subject hash.
4. **License evidence** — an explicit rights and redistribution decision.
5. **Release integrity evidence** — content hashes that bind every external record
   to the candidate being qualified.

## Procedure

1. Run `python3 scripts/huntwb.py validate library`.
2. Run `python3 scripts/huntwb.py test library --seed 20260916` and preserve its
   machine-readable result.
3. Run `python3 scripts/huntwb.py verify-adapters`.
4. Perform model-host evaluation using an approved external harness; do not infer
   a pass from manifest presence.
5. Obtain two independent human reviews of the same immutable subject.
6. Complete the license and integrity reviews.
7. Provide the evidence documents to `release-report` and inspect every pending or
   failed gate.

## Decision rule

All release-blocking gates must pass independently. Aggregation cannot compensate
for a failed security, contract, fixture, critical-mutation, adapter, model-host,
human, license, or integrity gate. Unavailable tooling is `not_available`; absent
evidence is `pending`; contradictory evidence fails closed.

Without all external evidence, the only valid result is
`qualification_withheld`. Offline qualification does not establish production
effectiveness, Microsoft service fidelity, precision, recall, latency, cost, or
safe autonomous response.
