# Expansion acceptance record

The implemented offline and isolated-laboratory scopes passed the checks below.
Native worker/filesystem checks and production integrations have separate gaps;
they are not promoted by these results. An unavailable required check leaves its
capability incomplete.

## Tested revision and runtime

- Implementation revision: `1493640424c30c1cda5942b4dbc9b13c3d508da8`.
- Integration base: `5a40c2ecc99d6ce347a625d80f9c3b11e502d7fd`.
- Acceptance date: 2026-10-18. The acceptance record was initially added in a
  documentation-only change. A subsequent push-gate correction formats five
  canonical modules and their 28 packaged copies, then refreshes seven provenance
  manifests. All 33 Python syntax trees are unchanged; fixtures are unchanged.
  The strict run below remains bound to the implementation revision and source
  snapshot listed here. Hosted checks separately validate the final PR revision.
- Strict service image:
  `sha256:1091037480cdd8172ab3c942fbf88da9150ea07934b362d190867b9344e7204e`.
- Service source snapshot:
  `45e196dcaf590ad4104e061b836042145e6eda6048d27f9899fbb855dc114485`.
  Recomputing the snapshot at the clean implementation revision matched the run.
- Portable host: macOS arm64, Python 3.14.8. Strict runtime: Linux arm64,
  Python 3.14.6, Git 2.47.3, pip 26.1.2, cryptography 50.0.2,
  python-evtx 0.8.1 and hexdump 3.3.

Changes are committed on dedicated, dependency-ordered branches and integrated
with the base above on `codex/expansion-delivery`. The original API checkout
retains its branch and unfinished edits. This record captures local acceptance
before the authorized push and merge; the pull request records hosted checks and
delivery separately. It does not establish release or production deployment.

## Commands and check ledger

Run these from the contributor environment described in
[CONTRIBUTING.md](../CONTRIBUTING.md). The Docker context used for this acceptance
was Colima; `TMPDIR` pointed to a disposable directory shared with its VM. Image
prerequisites must be provisioned before the strict gate, as described in the
[runtime instructions](../laboratories/service-runtime/README.md) and
[Kubernetes runbook](KUBERNETES_LABORATORY.md).

```sh
.venv/bin/python -m pytest -q tests/test_cve_evidence_binding.py tests/test_integrated_workflows.py
PATH="$PWD/.venv/bin:$PATH" PYTEST_ADDOPTS='-ra' make check PYTHON=.venv/bin/python
make check-docs PYTHON=.venv/bin/python
DOCKER_CONTEXT=colima make check-laboratory PYTHON=.venv/bin/python LABORATORY_ARGS='--runtime docker --image sha256:1091037480cdd8172ab3c942fbf88da9150ea07934b362d190867b9344e7204e --kubernetes-timeout 480'
```

| Check | Observed result | Scope or limitation |
| --- | --- | --- |
| Latest focused correction tests | 60 passed | CVE advisory/source binding and integrated workflow correction, missing evidence, tampering and cleanup |
| `make check` | Passed, including all 25 package gates | Root suite passed with 24 platform skips; the quiet output does not report a passed-test count; skips are listed below |
| `make check-docs` | Passed, 58 pages | Documentation contract and local links |
| Strict `make check-laboratory` | 13/13 cases passed; no failures or blockers | Twelve service-container cases plus three Kubernetes lifecycle runs in one composite case |
| Held-out routing | 270/270 clear requests correct; 10/10 for each of 27 specialists | 100/100 ambiguous or negative requests clarified; published examples remain separate |
| Hosted/native CI | Not run for these local branches | Retained Linux worker and Windows filesystem jobs remain required |
| Production/provider integrations | Not run | Separate live validation required before support claims |

The initial integration portable run failed because the execution sandbox denied local
TCP, UDP and Unix socket creation. The command was rerun unchanged with local
socket permissions; no test was disabled or implementation changed for the retry.

The portable suite also covers threshold boundaries and conflicting artifacts,
classifier redaction/timeouts/unavailability, preview side-effect exclusion,
workflow type/graph validation, plan-bound approvals, scope and budget rejection,
tampered outputs, restart/cancellation/retries, duplicate-write prevention and
cleanup. Report checks validate the bundled official SARIF 2.1.0 schema and
GitHub subset, JUnit escaping and inconclusive statuses, revision-bound Markdown
anchors, redaction, portable assets, host manifests and generated marketplaces.

## Fixture identities

The service manifest pins the Entra, Kubernetes, Sysmon, advisory and service
profiles, with provenance, expected outcomes and reset instructions. The binary
EVTX counterparts additionally have the following digests.

| Fixture | SHA-256 |
| --- | --- |
| `cops/laboratory/service_fixtures/manifest.json` | `9dad6f3958f011263ef7580ecb05de580b4ee51c8f065c5ef02d28f5abbcf6fc` |
| Vulnerable Sysmon EVTX | `4dbd6c4f96c5adae0e2c1df9847ab03a76131ecc60136c227d35f0fde8c1c245` |
| Corrected Sysmon EVTX | `74e3ba983be16a897f515c12744f9f155876ed06f4eeb52fa790507cf339b8d2` |
| Insufficient Sysmon EVTX | `5023fa444889f6a5d54c524f6507dfffe3677f076fb0640132c69ec6f8bd5ff9` |
| `tests/fixtures/artifact_assessment_cases_v1.json` | `d54de2657404483aa15350390a8a25ee38f46d46263c91590a42479471a88284` |
| `tests/fixtures/routing-held-out-v1.json` | `2a235734f9eb8bd0fcb4d07a83e4a901fd9a335004629d0b9f67c07ee76271c0` |

The three pinned Kubernetes prerequisites were:

```text
rancher/k3s@sha256:c20f2c044a28cf217440464a810fb81715a48192716a5bc99eaf2c3113a9cfb4
rancher/mirrored-pause@sha256:a433214620b407678934ebd69690a9ed6066247231eacfba181fab20dbc3dbf1
python:3.14.6-slim@sha256:34bf30c914ac17d2a0f7ecf94866e54380669d618ae4673672445516603ad8d7
```

## Isolated execution evidence

The gate inspected Docker `none` networking, loopback-only interfaces/routes,
read-only service-container configuration and definitive IPv4/IPv6 egress
rejection. It observed actual activity, captured telemetry, verified restored
state and stopped listeners, and removed owned containers. The K3s node runs
privileged inside the disposable VM and shares its kernel; this is not evidence
of a production worker under a distinct OS identity.

| Strict case | Observed correction or lifecycle evidence |
| --- | --- |
| `offline-playback` | Four fixtures, eight telemetry records and four alerts |
| `binary-evtx` | Vulnerable: two normalized records and both expected indicators; corrected: two records and neither indicator; insufficient: zero normalized records and `partial` status |
| `service-vulnerable` | Ten API checks expose authorization/rate-limit failures; injection exposes another object; zero scope denials among seven gateway requests; lateral path returns 200 |
| `service-corrected` | Ten API checks pass; injection cannot expose the other object; four scope denials; forbidden lateral path returns 403 |
| `workflow-success` | Three consumed authorizations, five TCP requests, six telemetry records, four alerts; restored and stopped |
| `workflow-failure` | Two authorizations, three requests, three telemetry records, one alert; partial failure with restoration and stopped services |
| `workflow-cancellation` | One authorization, two requests, two telemetry records, no alert; cancelled with restoration and stopped services |
| `integrated-leaked-credential-blast-radius` | Six authorized stages, actual Git-history scan, three HTTP requests, four telemetry records, two alerts; revoked credential and verified signed bundle |
| `integrated-cve-reachability-triage` | Four authorized stages; actual component invocation and one bound telemetry record; no TCP request or alert claimed |
| `integrated-illicit-consent-remediation` | Five authorized stages and five requests; seven telemetry records and one alert; exact synthetic grant revoked while unrelated access remains available |
| `integrated-detection-rule-ci-validation` | Four authorized stages and five requests; six telemetry records and two alerts with attack/benign measurements |
| `integrated-pre-release-exposure-audit` | Four authorized stages, real scoped DNS and five HTTP requests; seven telemetry records and one alert |
| `integrated-kubernetes-compromise-containment` | Success, failure and cancellation after real policy application; required traffic preserved, forbidden traffic blocked, correlated audit/HTTP evidence and baseline restored |

Both service profiles also verified two actual raw acquisition imports,
permission/custody/tampering rejection, original preservation, post-revocation
HTTP 401, and nine JWT requests with eight rejection cases. Each installed a
hash-pinned synthetic wheel offline, made two runtime requests, rejected a
tampered wheel and verified cleanup. Advisory evidence changed from `matched`
to `clear` with the corrected installed component. An empty inventory remained
unknown. Both profiles restored their baseline.

All six integrated workflows have offline and isolated execution paths. Their
stages use typed prior outputs and exact, single-use ActionPlan approvals. The
IOC → hunt → containment example additionally exercises success, failure and
cancellation. CVE evidence binds a pinned synthetic advisory to component version,
source digest and observed invocation; absent reachability evidence never proves
non-exploitability. Consent uses an Entra-shaped application emulator. Exposure
uses actual DNS inside the isolated scope. These do not validate provider APIs.

## Readiness by capability

Offline families have vulnerable, corrected, benign and insufficient-evidence
cases in the assessment fixture; the API package has its own role/rate-limit
cases. Source identity, provenance and verification status survive reporting.
“Validated” below applies only to the stated scope. Packages remain experimental.

| Capability | Validated scope | Incomplete or unsupported scope |
| --- | --- | --- |
| Application security | Python AST, JavaScript/TypeScript, diff/scanner evidence; actual SQLite-backed HTTP injection and authorization corrections | Other languages/runtimes and production applications |
| AI adversary testing | Direct/indirect injection fixtures and seven actual tool-gateway requests per profile; corrected tool/scope boundaries | Provider-specific model resistance requires live evidence |
| Compliance posture | Versioned SOC 2/CIS/NIST subsets; missing or stale evidence cannot pass | Full-framework coverage and operating effectiveness |
| Forensic collection | Raw disk/memory copies with source/hash/time/custody/permission binding; disposable acquisition and unchanged originals | Native acquisition, E01/AFF4 and filesystem/memory interpretation require separate adapters |
| Malware triage | Bounded static binary inspection and safe PowerShell decoding of harmless synthetic samples | Unsupported binary formats or deep analysis; submitted content is never executed |
| Purple-team validation | All four outcomes, correlated captured telemetry/alerts, and generated Sigma/KQL subset execution against attack/benign events | Broader query engines and production SIEM ingestion |
| Adversary emulation | Allowlisted real lateral paths and cleanup after success, failure and cancellation | Other techniques, targets and production engagement |
| Cloud infrastructure | Typed Terraform, Kubernetes and AWS/Azure/GCP exports; actual K3s NetworkPolicy application and restoration | Provider enforcement and incomplete configuration exports |
| Supply chain and CI/CD | Lockfiles, SBOMs, Actions and pinned advisories; actual offline wheel installation, runtime correction and hash rejection | Arbitrary package builds, registry behavior and hosted CI integration |
| Secrets remediation | Redacted bounded Git history, identity/exposure assessment and actual ephemeral revocation returning 401; caller-signed evidence bundle | Provider validity/rotation and external signing-key trust |
| REST/GraphQL security | Existing inventory/replay formats preserved; ten actual HTTP checks per profile across owner, other-user, anonymous and rate-limit cases | Production targets and unsupported API semantics |
| Network segmentation | Typed firewall/NetworkPolicy/flow/DNS evidence; real allowed/denied service and pod connectivity | Native firewall enforcement and unobserved networks |
| TLS, mTLS and JWT | Typed chain/RS256 verification, ephemeral certificate/client acceptance and nine actual JWT requests | Production trust, revocation services and unsupported algorithms |

## Platform gaps and completion rule

The macOS portable run skipped 24 platform-dependent tests. Linux-specific
production approval sockets, `/proc` descriptor protections and bubblewrap worker
isolation require the retained native Linux jobs. Windows device/junction handling
and PowerShell assessment require the retained Windows jobs. Linux-only EVTX
parsing was exercised by the strict Linux gate; that does not validate native
Windows acquisition. No skipped check is counted as a pass.

The existing CI matrix retains Linux bubblewrap, Windows filesystem/PowerShell,
multi-version portable and isolated laboratory jobs. Hosted runs for these local
branches were not performed. Production/provider, native acquisition and the
unavailable platform checks above remain incomplete. Exported reports are review
artifacts; hosted posting and production integration remain separate transitions.

After a behavioral change, rerun the relevant corrections and all required gates
against its new revision and source snapshot. Documentation-only changes require
the documentation gate. Retain limitations and inconclusive states when reusing
this evidence; do not infer broader readiness from a passing synthetic fixture.
