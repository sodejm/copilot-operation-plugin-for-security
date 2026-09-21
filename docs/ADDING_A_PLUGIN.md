# Adding a cybersecurity plugin

This is the implementation checklist for adding a portable COPS package. The
package is the ownership boundary: its skills, agent instructions, scripts,
examples, documentation, and validation stay together.

## 1. Select one primary category

Choose an existing ID from `catalog/categories.json`. Add a category only when the
capability cannot be found predictably under an existing one.

Create the package at:

```text
plugins/<primary-category>/<plugin-id>/
```

Acceptance criteria:

- `<plugin-id>` is lowercase kebab-case and stable;
- the directory is exactly two levels below `plugins/`;
- the package has one primary category even if its tags span several domains.

## 2. Create the portable package surface

At minimum, add:

```text
plugin.json
.codex-plugin/plugin.json
.claude-plugin/plugin.json
package.json
README.md
skills/<globally-unique-skill-id>/SKILL.md
scripts/<entry-point>.py
```

Use the root `plugin.json` for GitHub Copilot's Agent Plugin contract,
`.codex-plugin/plugin.json` for Codex package metadata and user-facing interface
metadata, and `.claude-plugin/plugin.json` for Claude identity metadata. These
host manifests may point to the same canonical skills and scripts, but must not
fork their behavior.

Acceptance criteria:

- all three manifests use the catalog ID and version;
- the Copilot manifest declares a schema and non-empty description;
- the Codex manifest references `./skills/` and declares its required interface
  metadata, capabilities, and one to three bounded default prompts;
- at least one skill exists;
- each `SKILL.md` starts with only `name` and `description` frontmatter;
- the skill name matches its directory and does not collide with another package.

## 3. Declare the runtime and evidence contract

Create `package.json` using `catalog/schemas/package.schema.json`. Declare:

- identity, maturity, summary, and explicit limitations;
- structural, offline, host-installation, and live-integration states separately;
- one safe offline demonstration;
- one or more deterministic validation commands.

Commands must be argument arrays beginning with `$PYTHON`, target a `.py` file
inside the package, and set a timeout from 1 to 900 seconds. Do not invoke a shell,
depend on ambient credentials, or make destructive changes in the demo.

Acceptance criteria:

- `python3 -m cops demo <plugin-id>` is safe on a clean clone;
- `python3 -m cops check <plugin-id>` is deterministic and exits nonzero on failure;
- offline fixtures are clearly labeled;
- host and live states remain `unverified` until separate evidence exists;
- limitations name important engines, services, permissions, or behaviors not tested.

## 4. Register the package once

Add one record to `catalog/plugins.json`, then regenerate derived indexes:

```bash
python3 -m cops generate
python3 -m cops generate --check
```

Do not hand-edit `.agents/plugins/marketplace.json`,
`.github/plugin/marketplace.json`, or `.claude-plugin/marketplace.json`.

Acceptance criteria:

- the catalog path is `plugins/<primary-category>/<plugin-id>`;
- the catalog and all three package manifests have the same ID and version;
- generated indexes are byte-current;
- no uncataloged or duplicate package exists.

## 5. Specify observable behavior

Add a focused Markdown specification under `specs/`, Gherkin acceptance scenarios
under `specs/features/`, and executable steps under `tests/step_defs/`. Cover the
happy path and at least one failure or misuse boundary.

For a security package, include tests for relevant cases such as malformed input,
path traversal, command injection, unsafe data handling, nondeterminism, or
unsupported evidence claims. Tests should validate behavior, not merely file
existence.

Acceptance criteria:

- scenarios state what an analyst can observe;
- expected counts and support boundaries are exact where practical;
- unsafe input fails closed with a stable error contract;
- fixture-backed success is not described as live-service success.

## 6. Validate the complete change

```bash
python3 -m cops doctor --contributor
python3 -m cops list
python3 -m cops info <plugin-id>
python3 -m cops demo <plugin-id>
python3 -m cops check <plugin-id>
python3 -m cops generate --check
make check
```

The change is acceptable when every command succeeds, the package is discoverable
from the root README path, generated files have no drift, the full suite passes on
supported Python versions and operating systems, and documentation distinguishes
repository evidence from host and live evidence.

## 7. Record stronger support only with evidence

A manifest or successful local test is not installation proof. Before promoting a
host or live state, record the host/service version, clean installation steps,
permissions, test inputs, expected and observed results, date, and reviewer. The
central validator deliberately rejects `validated` host or live claims until the
repository defines and accepts the corresponding evidence-record contract.
