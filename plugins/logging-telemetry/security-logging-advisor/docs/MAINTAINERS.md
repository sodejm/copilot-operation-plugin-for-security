# Maintain COPS Security Logging Advisor

Follow [CONTRIBUTING.md](../../../../CONTRIBUTING.md) and the root
[agent contract](../../../../AGENTS.md). Update specifications and executable scenarios
with behavior changes, review privacy implications, and run `make check`.

The aggregate gate validates contributor contracts and adapters, plugin manifests
and required assets, plugin unit tests, BDD scenarios and bundled skill tests.
Host discovery and model-assisted report quality require separate manual evidence.

For an authorized release:

1. Update the [plugin changelog](../CHANGELOG.md) and relevant root changelog entry.
2. Keep version fields aligned in `plugin.json`, `.claude-plugin/plugin.json`,
   `catalog/plugins.json`, and the three host marketplace indexes.
3. Preserve the `security-logging-advisor` IDs and paths unless the release includes
   an explicit migration. Use COPS Security Logging Advisor as its display name.
4. Run `make check` at the release revision and record supported-host smoke tests.
5. Create tags, releases or publish packages only when authorized, with exact
   artifact and destination evidence. No tag-triggered publication pipeline is
   currently included; a tag alone does not publish the plugin.

See [enterprise rollout](ENTERPRISE_ROLLOUT.md) and
[template maintenance](../../../../docs/MAINTENANCE.md).
