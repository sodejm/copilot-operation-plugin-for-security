# Specialist review contract

These are versioned prompt definitions for optional, bounded review. The offline CLI does not invoke a model. An orchestrator may supply only a packet assembled from the current run, approved local reference bundles, and user input. It must record the exact packet hash, prompt version, model settings, output, and human disposition using `attackpath.review/v1` in `schemas/records-v1.schema.json`.

All reviewers must cite evidence IDs for factual statements, distinguish a source assertion from independent validation, list alternatives, and abstain when required context is absent. They cannot create source facts, edit graph edges, assign business owners, or override gates. Conflicting opinions remain separate review records. A material objection from the claim auditor blocks publication until a human resolves it or removes the claim. Evaluation cases are illustrative, not real findings.
