# SOC Investigation Workbench

An analyst-led investigation planner packaged as a Codex plugin. It maintains
competing hypotheses, explicit evidence associations, a dependency graph, and an
explainable ranking of the next useful questions. Python 3.10+; no runtime
dependencies or credentials.

The plugin registers two skills: `soc-investigation-planning` and
`soc-investigation-review`. Hunt workflows belong to Sentinel Hunt Workbench and
are consumed through an unmodified vendor snapshot. See
[ownership and updates](docs/ownership.md).

**Integration status:** the local planner is implemented. The canonical Sentinel
skills and hunt catalog were not yet present at the implementation checkpoint,
so no vendor snapshot is included. Query handoffs and the release validation gate
remain blocked until those source files are available and verified. The planner
walkthrough below works independently.

From this directory:

```bash
python3 scripts/investigate.py validate examples/case.json
python3 scripts/investigate.py next examples/case.json
python3 scripts/investigate.py import examples/case.json examples/signin-result.json --out /tmp/soc-case-01.json
python3 scripts/investigate.py import /tmp/soc-case-01.json examples/consent-result.json --out /tmp/soc-case-02.json
python3 scripts/investigate.py import /tmp/soc-case-02.json examples/mailbox-gap.json --out /tmp/soc-case-03.json
python3 scripts/investigate.py report /tmp/soc-case-03.json
```

Choose fresh output paths for repeated walkthroughs. Snapshots never overwrite an
existing file and are created with mode `0600`. Examples are synthetic; the last
report preserves conflicting OAuth assessments and unavailable mailbox coverage.

After completing the vendor integration described in the ownership guide, use
`python3 scripts/investigate.py handoff examples/case.json --step signin` to get
the canonical skill paths and scoped hunt request. This command executes no query.

Load this directory as a local Codex plugin using its
`.codex-plugin/plugin.json`. Only `./skills/` is registered. Vendored skills are
loaded by explicit handoff, so installing Sentinel separately does not register
duplicate skill names. No marketplace registration is included.

See [workflow and JSON contracts](docs/workflow.md) for authoring cases and
[validation](docs/validation.md) for executable acceptance scenarios. Reports
show references and uncertainty, not raw evidence prose.

All query design, raw telemetry correlation, rendering, and qualification is
delegated to Sentinel. The case engine records analyst-supplied associations
between observations, entities, and hypotheses. Analysts execute queries in their
authorized tools and import redacted observations. This release does not provide
live connectors, autonomous response,
automatic verdicts, probabilistic confidence, or a globally optimal plan.

Copyright Justin Soderberg. [PolyForm Noncommercial 1.0.0](LICENSE).
