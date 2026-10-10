# COPS licensing and attribution

The existing COPS project license remains
[PolyForm Noncommercial License 1.0.0](../LICENSE). This template adoption does
not relicense the plugin or grant additional use rights. Consult the license text
for its terms.

The repository foundation imports material from PARK at revision
`bfc41923fb497b495e95dc7dee644313b51b368b`. That material retains its
[Apache License 2.0](../licenses/PARK-Apache-2.0.txt). See
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for provenance and the imported
paths. Preserve applicable notices when redistributing those files. Any later
license change is a separate maintainer decision.

## Provenance registry licensing review

Each source in `catalog/provenance.json` has a durable `licensing_review` record
with the reviewed source ID, reviewed license string, disposition, and rationale.
When adding or changing a source, update the record in
`scripts/build_scenario_registry.py`, regenerate the catalog, and confirm that
the review source and license match the enclosing source exactly.

`citation_only` permits the registry to retain source metadata and citations. It
does not authorize copying source material. `reuse_with_attribution` records that
reuse remains subject to the stated license and applicable attribution or notice
obligations. A maintainer must review the source terms and intended material
before reuse.

The review record is not legal advice, proof of authorship, proof that material
was or was not copied, or a replacement for authorization and evidence required
by an execution workflow.
