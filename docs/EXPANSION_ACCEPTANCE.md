# Expansion acceptance record

The implemented offline and isolated-laboratory scopes passed the checks below.
Native worker/filesystem checks and production integrations have separate gaps;
they are not promoted by these results. An unavailable required check leaves its
capability incomplete.

## Tested revision and runtime

- Implementation revision: `19fa8df91184109b13f542e6e31fcefc0b9c7a28`.
- Integration base: `50e6d96c144f9d81d52c99403e5ceae8815d3e16`.
- Acceptance date: 2026-10-18. This documentation-only refresh records the
  integrated provenance (`38e091b`), authorized transport (`cda3255`), bounded SQL
  fixture (`b55c68d`), TLS minimum policy (`19fa8df`) and review corrections.
  The focused, portable, documentation and strict gates were rerun after the TLS
  correction. One subsequent test formatting change preserves its syntax tree;
  the runtime sources are unchanged. Hosted checks separately validate the final
  PR revision.
- Strict service image:
  `sha256:8d21dbed75b45e4198ef03e2bd1f802c894f5efb95e2477faa9782757fd67a12`.
- Service source snapshot:
  `2e75aabd6cb49f565e2cb9d9d1107bf462063b92afa7efa8b3b33803589fd2e5`.
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
.venv/bin/python -m pytest -q -ra \
  tests/test_web_api_replay_transport.py tests/test_web_api_import_safety.py \
  tests/test_boundary_query_safety.py tests/test_cve_evidence_binding.py \
  tests/test_integrated_workflows.py tests/test_network_policy_inputs.py \
  tests/test_workflow_optional_signing.py tests/test_cloud_corrections.py \
  tests/test_supply_chain_corrections.py tests/test_purple_team_workflows.py
make check PYTHON=.venv/bin/python
make check-docs PYTHON=.venv/bin/python
DOCKER_CONTEXT=colima make check-laboratory PYTHON=.venv/bin/python LABORATORY_ARGS='--runtime docker --image sha256:8d21dbed75b45e4198ef03e2bd1f802c894f5efb95e2477faa9782757fd67a12 --kubernetes-timeout 480'
```

| Check | Observed result | Scope or limitation |
| --- | --- | --- |
| Focused correction tests at `19fa8df` | 321 passed, no skips | API transport/import and TLS floor, SQL fixture, CVE/integrated workflows, network, optional signing, cloud, supply-chain and predicate corrections |
| `make check` | Passed, including all 25 package gates | Root suite passed with 24 platform skips; the quiet output does not report a passed-test count; skips are listed below |
| `make check-docs` | Passed, 58 pages | Documentation contract and local links |
| Strict `make check-laboratory` | 13/13 cases passed; no failures or blockers | Twelve service-container cases plus three Kubernetes lifecycle runs in one composite case |
| Held-out routing | 270/270 clear requests correct; 10/10 for each of 27 specialists | 100/100 ambiguous or negative requests clarified; published examples remain separate |
| Hosted/native CI | Pending for the final pushed revision | Retained Linux worker and Windows filesystem jobs remain required; earlier PR results do not validate this revision |
| Production/provider integrations | Not run | Separate live validation required before support claims |

The service image was rebuilt from the current runtime Dockerfile and pinned,
hash-verified offline dependencies before the strict run. The launcher verified
the fresh source manifest and inspected the container configuration before use;
old evidence and marker files were not accepted as readiness evidence.

Transport regressions exercise numeric-address DNS pinning, original-host TLS
verification (valid, wrong-host and untrusted certificates), TLS 1.2 minimum
without weakening stricter caller settings, rejection of a mutated TLS context
before DNS, redirect policy and credential removal, aggregate deadlines, HTTP
error responses and real signed,
persisted, single-use approvals. Request, session, destination and budget changes
cannot reuse an approval bound to the frozen transport plan.

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
| `cops/laboratory/service_fixtures/manifest.json` | `a2fb5f80ffe97409f91653f4574052665ed992da597e25cb472b1547ef3a7803` |
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

The vulnerable SQL runtime accepts one exact, reviewed injection seed and executes
a constant query for that seed. All other submitted values use bound SQLite
parameters; the corrected profile always uses parameters. The separate scanner
fixture retains explicit vulnerable/corrected source for static AST inspection
only. Descriptor hashes bind that fixture to the observed HTTP/SQLite outcome;
missing or inconsistent evidence remains inconclusive. Focused tests cover
arbitrary submitted input, both runtime outcomes and this evidence boundary.

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
| REST/GraphQL security | Lossless import provenance and redacted reports; approved frozen transport with DNS/TLS/redirect/deadline checks; ten actual HTTP checks per profile across owner, other-user, anonymous and rate-limit cases | Production targets and unsupported API semantics |
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
multi-version portable and isolated laboratory jobs. Results for the exact final
pushed revision must be verified on the pull request before merge. Until then,
the unavailable platform checks above remain incomplete. Production/provider and
native acquisition validation remain incomplete regardless of synthetic CI
results. Exported reports are review artifacts; hosted posting and production
integration remain separate transitions.

After a behavioral change, rerun the relevant corrections and all required gates
against its new revision and source snapshot. Documentation-only changes require
the documentation gate. Retain limitations and inconclusive states when reusing
this evidence; do not infer broader readiness from a passing synthetic fixture.
