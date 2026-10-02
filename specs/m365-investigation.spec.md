# Microsoft 365 investigation acquisition (issue #27)

## Contract

An analyst selects one tenant and a reviewed source before requesting collection.
The workbench previews the exact read-only request without resolving credentials.
Collection uses `cops.evidence/v1` envelopes and the shared connector limits,
checkpoint, pagination, and receipt. Provider next links may change only the
allowlisted query fields of the selected fixed Graph path. A malformed next link
ends in a partial receipt and is never followed.

The acquisition suite covers twelve fixed Graph collections: sign-in, directory audit,
service principal, conditional access policies, Defender security alerts, security incidents,
Purview eDiscovery cases, Exchange mail messages, SharePoint sites, Teams chats,
authentication methods, and OAuth2 permission grants. These sources expose only bounded,
allowlisted projections. Offline correlation joins source-specific records by a
tenant-bound, explicit entity identifier; shared IPs are context, never identity.
Missing sources and partial receipts remain visible, and correlation is not a
verdict. No live mutation is in scope.

## Acceptance state

- [x] Synthetic offline projections, strict destination validation, bounded
  acquisition, and cross-domain correlation tests.
- [x] Read-only fixed adapters for Defender XDR, Purview, Exchange,
  SharePoint, Teams, authentication methods, and OAuth2 permission grants.
- [x] Endpoint permissions, licenses, and retention documented for every source.
- [x] Three cross-domain scenarios verified with tenant-bound offline fixtures.
- [x] Shared connector SDK integration verified in tests and offline runners.
