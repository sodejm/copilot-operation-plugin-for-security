# Validation and assurance limits

The case engine is tested independently of upstream hunt qualification. The
executable scenarios map one-to-one to AC01–AC10 in
`specs/soc-investigation-workbench.spec.md` at the repository root. They cover
scope and identity, replay and duplicate evidence, contradictions and coverage,
branching and ranking, DAG validity, budgets, resume/revision, vendor handoffs,
untrusted prose, and private output snapshots.

Additional tests exercise malformed input, historical evidence visibility,
reserved cost, deterministic ties, provenance collisions, exact vendor copying,
inherited licensing, source drift, missing skills, and malformed hunt contracts.
Vendor tests use clearly synthetic local fixtures; they do not assert that
Sentinel's real hunts pass qualification or that the host loads skills correctly.

From the repository root, using a development environment with `requirements.txt`:

```bash
python3 -m pytest tests/step_defs/ -q
python3 security-logging-advisor/scripts/validate-plugin.py
python3 soc-investigation-workbench/scripts/validate-package.py
```

The SOC package validator checks manifest identity and skill registration,
owned skill names/frontmatter, relative document links, license, executable case
validation, acceptance/scenario parity, and installed vendor integrity. It does
not execute the test suite or qualify upstream hunts. The repository command
requires the specs alongside the package; installing the plugin does not require
the specs or test dependencies.

During development only, while **both** the vendor directory and lock are absent:

```bash
python3 soc-investigation-workbench/scripts/validate-package.py --allow-pending-vendor
```

That mode prints `development_only` and `release_ready: false`. It never suppresses
a corrupt or partial snapshot. The default command exits with code 2 until the
Sentinel dependency verifies. An absent dependency is a release blocker, not a
passing skipped check. Both owned skills also pass Codex's external skill and
plugin validators when those tools and their PyYAML dependency are available.

This release has no live connector, tenant execution, automatic response, or
automatic verdict. The planner's score is a documented greedy heuristic based
on analyst estimates; it is not a calibrated information-gain metric or a proof
of optimality. A valid handoff requires explicit `supported` status on the
requested canonical hunt/surface. That status is upstream's contract and does
not itself establish live environment correctness.

The evidence-output test establishes that this deterministic CLI does not
interpret or reproduce hostile prose in its report. It is not a certification of
an LLM host's prompt-injection resistance. Input aliases, hashes, and prose must
already be redacted; no DLP or identity resolution is performed.
