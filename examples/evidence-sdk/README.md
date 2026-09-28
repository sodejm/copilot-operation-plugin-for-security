# Shared evidence examples

From the repository root, using Python 3.11 or newer:

```bash
python3 -m cops.connectors.demo
```

This standard-library command uses invented Graph and Resource Graph responses,
in-memory placeholder authentication, and temporary private checkpoints. It makes
no network, environment, keychain, or tenant credential lookup. It interrupts each
adapter after its first committed page and resumes the second page, then prints
common assessments for complete, partial, unknown-freshness and stale evidence.
Acquisition IDs vary between runs; timestamps and source identifiers are synthetic.
The temporary checkpoints are deleted when the command exits.

`request-plans.json` contains four **design-only** examples for Log Analytics,
Sentinel, Splunk and Cribl. They describe scope, projection, finite acquisition
budgets, and continuation questions. They do not implement those connectors,
validate their current service APIs, grant permissions, or execute queries. The
two runnable adapters are described in the [SDK guide](../../docs/EVIDENCE_SDK.md).
