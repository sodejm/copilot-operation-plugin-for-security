# COPS AD Assessment Workbench

The AD Assessment Workbench validates an explicitly scoped, offline Active Directory graph export and traces bounded candidate privilege paths across forests, domains, groups, hosts, and trust relationships. It preserves collection provenance and marks paths that depend on inferred edges, partial collection, protected identities, or trust boundaries.

The package does not collect from AD, LDAP, Kerberos, or hosts. A candidate path is a review lead based on supplied relationships; it does not prove the privileges are usable or exploitable. A missing path does not prove absence when collection is partial or unknown.

## Prerequisites and quick start

Run from the repository root with Python 3.11 or later:

```bash
python3 -m cops demo ad-assessment-workbench
```

The public command creates an owner-only temporary workspace, verifies both
runs and the expected rejection, and removes the workspace. Use the package
runner directly when you need to retain that evidence in a new directory:

```bash
python3 plugins/identity-access/ad-assessment-workbench/scripts/run_demo.py \
  --workspace /tmp/ad-playback-review
```

Analyze the bundled fixture without writing files:

```bash
python3 plugins/identity-access/ad-assessment-workbench/scripts/analyze.py \
  plugins/identity-access/ad-assessment-workbench/fixtures/synthetic-two-forest.json
```

Replace the fixture path with a separately authorized export only after reviewing
the input contract below. The analyzer reads one local file and does not collect
from a directory service.

## Design and data flow

1. `load_export` reads one regular local JSON file under a one-megabyte limit, rejects symlinks, duplicate keys, non-finite constants, excessive nesting, and malformed JSON.
2. `analyze` validates the declared scope, collections, nodes, edges, references, timestamps, and bounded queries.
3. Breadth-first traversal evaluates at most the configured node, edge, depth, path, and expansion limits.
4. The report keeps edge provenance and attaches review flags to every candidate path.

## Input and output contract

| Contract or artifact | Purpose | Key fields | Producer and consumer | Definition and validation |
| --- | --- | --- | --- | --- |
| AD export v1.0 | Declares scope, evidence, and questions in one opaque file | `scope`, `collections`, `nodes`, `edges`, `queries` | Approved export process → `load_export` and `analyze` | `adwb/inventory.py`; strict keys, IDs, references, timestamps, enums, sizes, and traversal bounds |
| Collection record | States where and when evidence was gathered | `source`, `forest`, `domain`, `host`, `collected_at`, `completeness` | Export process → coverage calculation | Must refer to in-scope objects and use `complete` or `partial` |
| Edge record | Connects graph objects to source evidence | `source`, `target`, `kind`, `collector_id`, `support` | Export process → path traversal | Reference and relation validation; `support` distinguishes observed from inferred evidence |
| Assessment report | Returns coverage and bounded query results | `assessment`, `coverage`, `queries` | Analyzer → reviewer | Deterministic output from a validated export |
| `playback-summary.json` | Records the demo's acceptance facts | query/path counts, rerun and failure checks | Demo → reviewer | Written only after semantic assertions pass |

The synthetic fixture returns one four-edge candidate path and one `not_found_in_collected_graph` query. The candidate includes all four review flags. Review the underlying edge evidence before acting.

See [the playback guide](docs/PLAYBOOK.md) and [verification notes](docs/VERIFICATION.md). Synthetic results validate the local contract only; they do not establish production coverage or live AD security.
