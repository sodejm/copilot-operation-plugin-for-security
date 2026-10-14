# Service attack notices

The service attack notice registry is a versioned, offline research input for
prioritizing targeted defensive investigation. It is not a vulnerability
scanner, exploitability test, finding, or authorization to probe a system.
Source URLs are stored as data; the commands do not fetch them or execute any
input.

## Use the registry

The commands require Python 3.11 or newer and emit JSON for headless use:

```bash
python3 -m cops service-notices validate --json
python3 -m cops service-notices list --json
python3 -m cops service-notices assess --input asset.json --json
```

`assess` reads one regular UTF-8 JSON file, rejects duplicate keys and unknown
fields, and limits the file to 256 KiB and 32 levels of JSON nesting. It accepts
one asset context:

```json
{
  "asset_id": "asset-001",
  "operating_system": "Dell RecoverPoint for VMs appliance",
  "product": "Dell RecoverPoint for VMs",
  "version": "6.0.3",
  "services": [
    {
      "name": "Tomcat Manager",
      "transport": "tcp",
      "reachable": true,
      "configured": true
    }
  ],
  "evidence": ["tomcat_manager_hard_coded_credential_risk_context"]
}
```

Every result contains a status, `input_verification: "unverified"`, sources,
publication and review dates, an exact observation date when supported (otherwise
`null` with observation context), conditional ATT&CK mappings, defensive advice, limitations,
reasons, missing evidence, and a safe next action. The mappings are research
context with `mapping_application: "not_assessed"`; a candidate does not apply
them to the asset. Classification is conditional on the supplied asset claims;
the command cannot establish their truth. The statuses mean:

- `candidate`: the exact product and affected-version allowlists match, and the
  required service reachability, configuration, and contextual evidence are
  present. This status proposes a targeted investigation only. It does not
  establish vulnerability or exploitability.
- `fixed`: the supplied exact version is in the notice's fixed-version allowlist;
  verify the installed build before treating the asset as remediated.
- `not_applicable`: supplied product, operating-system, or service-state claims
  rule out the notice, or the notice has a terminal lifecycle. Verify negative
  asset claims before treating the asset as out of scope.
- `unknown`: the supplied evidence is absent, unlisted, ambiguous, or stale.

Missing versions are always `unknown`. A listening port alone cannot produce a
candidate. Product names, operating systems, versions, services, transports,
and prerequisite evidence use exact registry allowlists rather than inference.
The CLI always assesses freshness using the current date. Python acceptance
tests pass a fixed date to the pure assessor for deterministic historical cases;
those tests do not establish current source freshness.

Dell's [DSA-2026-079](https://www.dell.com/support/kbdoc/en-us/000426773/dsa-2026-079)
names affected RecoverPoint for VMs 5.3 and 6.0 releases and a remediation path
to 6.0.3.1 HF1 or a vendor remediation script. Its later
[DSA-2026-096](https://www.dell.com/support/kbdoc/en-us/000501664/dsa-2026-096-security-update-for-dell-recoverpoint-for-virtual-machines-multiple-vulnerabilities)
also lists 6.0.3 and 6.0.3.1 in the affected product table with 6.1 as a
remediated version. The registry matches only named version strings, not a
vendor-described range or evidence that a remediation script ran. Unlisted
versions remain `unknown`; even `fixed` requires independent build verification.
The [original Apple Screen Sharing research](https://calif.io/research/password-fiction)
reports CVE-2026-65400 in macOS Tahoe 26.5.2 and a working exploit against a
live 26.6 machine. [Apple's advisory](https://support.apple.com/en-us/148170)
identifies 26.6.1 as the Tahoe release containing the fix. Other versions
require their own source-backed applicability review.

The Storm-2570 notice deliberately has no affected-version allowlist. The cited
Microsoft research describes observed post-compromise RDP, SMB, RMM, NetScan,
and Nmap behavior but does not establish initial access or affected Windows
versions. Consequently, automated assessment cannot promote that notice to a
candidate. Its T1046 mapping applies only when NetScan or Nmap service discovery
is observed. The Dell and Apple T1210 mappings require independent evidence of
lateral exploitation of the scoped service. The registry does not apply a
mapping based on an affected version or reachable service alone.

## Review and lifecycle

Review the registry at least monthly and promptly after a high-impact vendor or
primary-research publication. Intake is a human review outside this offline
command:

1. Use primary vendor advisories, vendor security research, incident research,
   or original research. Do not derive scope from aggregators.
2. Confirm each source's `published_on` date, exact products and versions,
   service context, prerequisites, remediation, and the limits of the source.
   Set `publication_date` to the earliest cited source date. Record an exact
   `observation_date` only when a source supports it; otherwise use `null` and
   explain the observed period or missing observation in `observation_context`.
3. Add an ATT&CK mapping only when the source supports both the technique and a
   specific rationale. Record the evidence required for that mapping.
4. Update `review_date` after checking every source, set `review_due` no more
   than 31 days later, and bump `catalog_version` for a reviewed registry change.
5. Validate the registry and run the focused tests before relying on the update.

An active notice becomes stale after `review_due`; stale notices return
`unknown` and cannot produce candidates. A withdrawn or superseded notice is
terminal and returns `not_applicable`. A superseded record names its successor;
a withdrawn record explains why it was withdrawn. Never extend a notice's
product or version scope without new primary-source evidence.

## Offline fixture boundary and inventory handoff

The registry and asset document are fixture-only local inputs. The tool does not
scan a host, resolve a name, open a socket, authenticate, query a management
plane, refresh a source, or verify that supplied evidence is true. Keep asset
identifiers free of secrets and review the structured output before using it in
another workflow.

The scoped host and service inventory work in issue #284 can supply bounded
asset and service observations. Issue #285 can add validated product, version,
reachability, configuration, and contextual evidence. Map those local outputs
to the documented asset shape before assessment. That coordinator handoff is
planned in those issues; the current CLI requires a local asset JSON file.
Neither inventory nor a port observation alone is enough for a candidate, and
this registry does not expand the authorization or network scope established
by either workflow.
