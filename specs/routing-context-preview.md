# Routing, Repository Context, and Execution Preview Contract

## Routing

The router consumes the canonical `symptom_triggers`, `artifact_triggers`,
`anti_triggers`, and `example_prompts` fields from each registered specialist.
Legacy `intent_keywords` remain a compatibility input while registries migrate.
Routing is deterministic by default and combines exact phrases, extracted artifact
features, BM25 term relevance, and conservative fuzzy matching.

Every result uses schema version `cops.routing-decision/v2`, has either `routed` or
`clarification_required` status, and includes ranked candidates with reasons,
normalized confidence, purpose, permissions, and required authorization. A result
requires clarification when the leading confidence is below 0.65 or when the lead
over the next candidate is below 0.15. There is no implicit SOC fallback.

An optional classifier receives only redacted feature names and counts plus the
registered specialist identifiers. The caller must specify its model, deadline,
and token budget. An unavailable classifier, invalid response, exceeded deadline,
or exhausted budget produces a clarification result.

Published catalog examples and held-out evaluation prompts are separate data sets.
The held-out suite contains at least ten clear prompts per registered specialist
and at least one hundred ambiguous or negative prompts. Its acceptance threshold
is 95 percent overall and 90 percent for every specialist.

## Repository context

Repository context collection is local and bounded. It reports paths and artifact
categories for dependency manifests, rendered Kubernetes or Helm resources,
Terraform plan JSON, and CI workflows. It never returns file contents. Descriptor
reads are anchored to verified regular-file descriptors and checked before and
after each bounded read.

Credential files, Kubernetes Secret documents, raw Terraform state, VCS history,
dependency caches, build output, and unrelated directories are excluded. Network
collection is a separate operation and this collector never performs it.

## Execution preview

`build_execution_preview` is a pure function. It reports ordered specialists and
actions, read and write effects, exact destinations, authorization requirements,
expected evidence, budget, noise, and unknown values. It does not invoke a
connector or worker, consume approval, write state, or inspect the filesystem.

Unknown metadata is represented explicitly rather than inferred. Preview callers
provide concrete output destinations and action metadata when those values are
known.

## Threat and abuse considerations

Untrusted prompts can contain credentials, identifiers, or instructions designed
to force an unsafe specialist. Extraction retains only feature categories and
counts for optional classification. Anti-triggers and ambiguity thresholds prevent
weak or conflicting evidence from authorizing a route. Context traversal rejects
symlinks and special files and never includes sensitive artifact contents. A
preview is descriptive only and cannot satisfy an execution authorization gate.
