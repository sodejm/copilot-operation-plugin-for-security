# COPS Host Assessment Workbench

Review sanitized Linux and Windows privilege-boundary exports and identify which observations
apply to the reported host context. On Windows, the package also provides a
bounded read-only collector and an independently validated, assessment-owned
cleanup receipt. It does not attempt privilege escalation or read credential values.

## Start here

Use Python 3.11 or newer and run from the repository root:

```bash
python3 -m cops info host-assessment-workbench
python3 -m cops demo host-assessment-workbench
python3 -m cops check host-assessment-workbench
```

The demo checks Linux positive, negative, fixed, unknown-context, and invalid-cleanup
inputs plus Windows vulnerable, protected, remediated, and unsupported exports
through the public importer. Follow the [practitioner playback](docs/PLAYBOOK.md)
for individual commands and result interpretation. Use the
[verification playbook](docs/VERIFICATION.md) to record qualification evidence.

## Design and evidence theory

A configuration observation can suggest a privilege boundary worth investigating,
but it does not prove that the boundary was crossed. The importer first compares
the observation's declared prerequisites with the reported host. Linux records use
kernel, distribution, namespace, and protection requirements; Windows records use
build, architecture, token, and protection requirements plus an explicit bridge
capability declaration. A known mismatch is `inapplicable`; an unknown prerequisite
is `unresolved`. Neither selects the observation for a canary conclusion.

A selected configuration can be a `configuration_candidate`,
`ordinary_configuration`, or `insufficient_evidence`. A canary record adds explicit
before/after access assertions, ownership, disposable-host status, evidence IDs,
and cleanup. A positive case requires denied-before/granted-after access; negative
and fixed cases require denied-before/denied-after. The resulting labels are
`reported_canary_crossing` and `reported_canary_blocked`: the importer checks the
contract but does not independently verify the source's claims.

## Data contracts

The Linux [positive](fixtures/synthetic/host_linux_positive_v1.json),
[negative](fixtures/synthetic/host_linux_negative_v1.json), and
[fixed](fixtures/synthetic/host_linux_fixed_v1.json) fixtures and the Windows
[vulnerable](fixtures/synthetic/host_windows_vulnerable_v1.json),
[protected](fixtures/synthetic/host_windows_protected_v1.json),
[remediated](fixtures/synthetic/host_windows_remediated_v1.json), and
[unsupported](fixtures/synthetic/host_windows_unsupported_v1.json) fixtures are
complete runnable inputs. The
[Linux privilege-boundary import contract](docs/IMPORT_CONTRACT.md) and
[Windows privilege-boundary contract](docs/WINDOWS_CONTRACT.md)
define the exact schemas.

| Record or field | Purpose and producer | Consumer and validation |
| --- | --- | --- |
| Input `schema_version` | Exporter selects Linux contract `1.0` or Windows contract `windows-1.0` | Importer rejects unknown versions or fields |
| `source_kind`, `source_id` | Exporter labels `synthetic_lab` or `operator_export` and an opaque provenance ID | Copied to report `source`; this is not independent provenance verification |
| `host` | Linux kernel/distribution/namespace or Windows build/architecture/token context | Compared with each observation's prerequisites; unknown values remain unresolved |
| `host.protections` | Linux SELinux/AppArmor/seccomp/no-new-privileges/user-namespace state or Windows UAC/VBS/Credential Guard/AppLocker/WDAC state | Required host context; selected requirements must agree |
| `bridge` | Windows exporter declares platform, `offline_windows_export` or `native_windows_bridge`, supported capabilities, and whether it supplied canary assertions | Importer rejects undeclared capabilities, contradictory assertions, and native privilege-crossing canaries |
| `coverage` | Status for eight Linux or seven Windows privilege-boundary surfaces | Each surface is `assessed`, `not_assessed`, `unsupported`, or `access_denied`; observations require assessed coverage |
| `observations[]` | ID, surface, configuration assertion, evidence IDs, requirements, optional canary | Importer rejects duplicate IDs, unsupported fields, and contradictory claims |
| `observations[].canary` | Case, resource ID, before/after access, evidence IDs, ownership and cleanup assertions | At least three evidence IDs; disposable host, assessment ownership, and cleanup must all be true |
| Report `mode`, `source`, `host`, `coverage` | Importer preserves import context | Analyst sees `offline_import` or `native_bridge_import` and explicit coverage limits |
| Report `observations`, `counts` | Importer supplies decisions, classifications, prerequisites, and totals | Analyst distinguishes candidates from reported crossings and unresolved observations |

The importer bounds input to 1 MiB, JSON depth 64, and 256 observations. Use opaque,
non-sensitive IDs. Credentials, free-form evidence, paths, duplicate JSON keys,
and non-finite numbers are rejected. Unassessed or denied coverage never establishes
that a host is safe.

## Operations and limits

Valid input produces deterministic JSON on stdout. Invalid input exits 2 with no
success report. Fix the input contract or preserve a missing-evidence outcome;
do not change assertions merely to obtain a selected result. See the playback for
repeatability and cleanup checks.

On Windows, `scripts/collect-windows.ps1` measures build, architecture, token,
UAC state, and seven bounded privilege-boundary surfaces. Service, task, and PATH
enumeration have fixed maximums; failures remain `access_denied` or
`not_assessed`. The collector creates and removes only a harmless directory and
marker beneath a caller-supplied empty canary root. Before deletion it confirms
the canonical root and child identities, rejects reparse points, and rehashes an
assessment-owned marker. The SHA-bound receipt records those identities and is
checked against the exact supplied root by `scripts/validate-windows-bridge.py`.
An identity or ownership mismatch fails closed without deleting the path. This
validates collector execution and assessment-owned cleanup; it does not validate
a privilege crossing or exploitability.

Run `scripts/exercise-windows-bridge.ps1` from PowerShell for the complete native
exercise used by CI. It executes the collector, importer, receipt validator, the
read-only versus writable ACL regression, and the final empty-root assertion.

Host installation and live integration remain unverified until the native
Windows workflow succeeds at the exact reviewed commit. Synthetic vulnerable,
protected, remediated, and unsupported fixtures remain the acceptance evidence
for result classification. The package-local [verification guide](docs/VERIFICATION.md)
defines the native acceptance procedure and the evidence it establishes.
