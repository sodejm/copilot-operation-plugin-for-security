# Microsoft 365 investigation acquisition (issue #27)

## Contract

An analyst selects one tenant and a reviewed source before requesting collection.
The workbench previews the exact read-only request without resolving credentials.
Collection uses `cops.evidence/v1` envelopes and the shared connector limits,
checkpoint, pagination, and receipt. Provider next links may change only the
allowlisted query fields of the selected fixed Graph path. A malformed next link
ends in a partial receipt and is never followed.

The first live slice covers Graph sign-in, directory audit, service principal,
and conditional access policy collections. These sources expose only bounded,
allowlisted projections. Offline correlation joins source-specific records by a
tenant-bound, explicit entity identifier; shared IPs are context, never identity.
Missing sources and partial receipts remain visible, and correlation is not a
verdict. No live mutation is in scope.

## Acceptance state

- [x] Synthetic offline projections, strict destination validation, bounded
  acquisition, and cross-domain correlation tests.
- [ ] Read-only live adapters for Defender XDR and Cloud, Purview, Exchange,
  SharePoint/OneDrive, Teams, authentication methods, and workload identity.
- [ ] Endpoint permissions, licenses, and retention verified for every source.
- [ ] Three cross-domain scenarios verified in an authorized test tenant.
- [ ] Portable installation includes or declares and verifies the shared SDK.

Keep issue #27 open until every named source and tenant acceptance criterion is
verified.
