# COPS Attack Surface Planner

Plan a bounded review of **operator-supplied local exports** for an authorized
Microsoft/Azure assessment. The command makes no network or tenant API calls and
does not execute the proposed tests.

## When to use & offensive engineer playbook

See the complete [Offensive Engineer & Red Teamer Playbook](docs/PLAYBOOK.md) for detailed planning workflows.

Use this planner when:
- **Scoping authorized offensive engagements**: Mapping human-signed rules-of-engagement contracts to asset inventories.
- **Reconciling multi-tenant cloud boundaries**: Partitioning Azure/Entra exports into in-scope, excluded, and unresolved assets.
- **Planning passive reconnaissance**: Designing non-intrusive observation steps without executing unauthorized network calls.
- **Documenting engagement compliance**: Establishing verifiable audit trails and stop conditions before testing.

## Rules of engagement

Have the assessment owner sign off on tenant IDs, subscription IDs, DNS domains,
IP ranges, environments, owners, passive method, UTC windows, and explicit
exclusions. Record the approval reference, approver, and UTC time in a local
manifest. That record is an operator assertion; the planner cannot verify a
signature or authority. A discovered object never expands approved scope.

The synthetic example uses reserved names and addresses:

```bash
python3 -m cops demo attack-surface-planner
python3 plugins/offensive-security/attack-surface-planner/scripts/plan.py \
  plugins/offensive-security/attack-surface-planner/fixtures/synthetic/scope.json
python3 -m cops check attack-surface-planner
```

For your own review, copy the manifest and four export files into a private local
directory. Replace all synthetic approval and scope values. Export files are
JSON objects with a `records` array. Set each source's `kind`, relative `path`,
lowercase SHA-256, `collected_at` UTC timestamp, `source_ref` (a provenance
label or URL without credentials or query), and `record_count`. The four kinds
are `azure_resource_graph`, `entra`, `dns_ct`, and `public_endpoint`.
The source reference is recorded and never fetched. Keep records minimal and
redacted; the sample shows the supported field names.

The report prints to standard output as JSON. Redirect it only to an approved
private location. It contains asset identifiers, owner labels, source references,
and hashes, so review privacy and retention before sharing it with any model
provider or other service. Never put credentials or raw personal data in inputs.
The planner does not log raw records or URL query strings.

## Decisions and operator review

`surface_map` separates `in_scope`, `excluded`, and `unresolved`
discoveries. Outside domains, subscriptions, tenant IDs, IPs, environments,
and explicit exclusions have reasons. Missing or unapproved ownership remains
unresolved. Only `in_scope` discoveries get a `test_plan` entry. Each entry
is a passive review prompt with approval reference, allowed method, window,
expected observation, expected telemetry, stop condition, and cleanup.
Reviewers must confirm authorization, source freshness, attribution, and the
proposed method before using any separate tool. The ordering is for review,
not a vulnerability score.

An export can be stale, partial, misattributed, or forged. Its content is
untrusted data, and reported confidence only means the source reported it.
A public endpoint field or a permission name is a hypothesis trigger, not
evidence of reachability, exploitability, or risky effective consent. The
package does not authenticate, crawl, query DNS/CT, scan, harvest credentials,
persist, or run active tests. An active mode is rejected. Any future active
implementation requires separate approval plus exact allowlists, a rate and
request budget, a dry run, and an audit log.

## Input limits

The manifest is at most 128 KiB, each export at most 4 MiB, all input at most
12 MiB, and all sources together at most 1,000 records. JSON depth is capped
at 24. Source paths must stay below the manifest directory and cannot traverse
symlinks. Integrity and scope failures stop report production.
