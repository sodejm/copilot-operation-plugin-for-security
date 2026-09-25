# COPS Security Logging Advisor

The Security Logging Advisor reviews a repository's logging configuration and
produces prioritized, evidence-linked recommendations for improving security
telemetry. It is the logging and telemetry package in the Copilot Operations
Plugin for Security (COPS) collection.

## Try it from the repository root

No package installation or third-party dependency is required for the operator
smoke test:

```bash
python3 -m cops demo security-logging-advisor
```

Run the package's complete declared validation gate with:

```bash
python3 -m cops check security-logging-advisor
```

A successful demo proves that the package can scan the included fixture and
produce its expected offline report. It does not prove installation in a
particular agent host or validate a production logging service.

## Use it in an agent host

Start with [Installation](docs/INSTALL.md), then review
[Security and privacy](docs/SECURITY_PRIVACY.md) before using the package with
a real repository. Teams planning a broader deployment should also read the
[Enterprise rollout guide](docs/ENTERPRISE_ROLLOUT.md).

The canonical portable package metadata is in [plugin.json](plugin.json).
Host-specific manifests and adapters are compatibility surfaces generated from
or checked against that package contract; they do not replace it.

## Maintainer workflow

From the repository root:

```bash
python3 -m cops validate
python3 -m cops generate --check
python3 -m cops check security-logging-advisor
```

See [Maintainers](docs/MAINTAINERS.md) for package-specific release and review
guidance. Repository-wide contribution and acceptance requirements are in
[`docs/ADDING_A_PLUGIN.md`](https://github.com/sodejm/copilot-operation-plugin-for-security/blob/main/docs/ADDING_A_PLUGIN.md).

## Evidence boundary

Outputs are advisory and require analyst review. Offline fixture results,
schema validation, and generated adapter checks are repository evidence only.
They do not establish that recommendations are correct for every environment,
that a host accepted the package, or that a live backend received the expected
telemetry.
