# Cross-platform compatibility

Sentinel Hunt Workbench uses a canonical-content spine with generated discovery
layers. Behavioral equivalence is evaluated; identical prose or feature parity
is not assumed.

## Supported packaging surfaces

| Host | Generated integration | Important limitation |
|---|---|---|
| ChatGPT / Codex desktop and CLI | Agent Plugin metadata plus canonical skills | Codex IDE discovery is skill-based and is not identical to desktop plugin activation. |
| GitHub Copilot | Repository skills and a thin custom agent | GitHub repository customization is not an installable OpenAI or Claude plugin contract. |
| Claude Code | Claude plugin manifest, namespaced skills, and a thin agent | Claude namespacing and agent/tool rules remain host-specific. |

The generated files are listed in `adapters/manifest.json`. Each entry contains
its SHA-256 digest and the manifest embeds the canonical input hash. `huntwb
verify-adapters` regenerates an in-memory expectation and fails on changed,
missing, or unexpected adapter files.

## Portable behavior

All hosts receive the same defensive-use boundary and the same six workflows:

- plan a falsifiable hunt;
- author KQL for exactly one named surface;
- adapt a hunt while reporting semantic differences;
- validate contracts and compatibility;
- run curated, generated, mutation, and hostile-input tests; and
- review evidence, ambiguity, and causal overclaim.

The deterministic CLI, hunt registry, profiles, fixtures, and qualification
states are host-independent. A host model cannot override their results or award
live-service assurance.

## Host-specific verification

Release validation checks manifest syntax and discovery layout locally. A full
release also requires a separately captured model-evaluation corpus for all
three hosts: 144 tasks, five repetitions per task and host, or 2,160 runs. The
evidence must meet the exact schema, safety, no-fabrication, stage-preservation,
and required-field thresholds in the release qualifier.

Local manifest acceptance does not prove that a host installed, activated, or
executed the package. Host discovery smoke tests and model results must be
performed in the corresponding products and content-addressed to the same
release subject.

## Permissions

The intended host permission set is local read access to this package, local
write access for requested outputs, and optional execution of bundled Python
commands. Network, cloud, credential-store, tenant, MCP, and hook permissions
are not required. If a host cannot offer the intended local command permission,
the skills may still explain or author content, but deterministic validation is
pending and the artifact cannot be qualified.

## Updating adapters

Run `python3 scripts/huntwb.py build-adapters` after changing canonical skills,
agent routing text, or host metadata. Review the generated diff, then run
`python3 scripts/huntwb.py verify-adapters`. Do not patch generated adapter files
by hand.

