# Engineering checkpoints, documentation, and human review

## Reversible operational checkpoints

Agents have standing authorization to create local commits for authorized work.
Create a commit after every substantial, coherent code change once its relevant
checks pass, before starting another independent change. Substantial changes
include behavior, refactors, dependencies, schemas, configuration, security
controls, and meaningful test or documentation changes. Keep each checkpoint
small enough to explain and revert independently; do not wait until the entire
task ends. Do not create a commit for every keystroke or split a working change
into broken checkpoints. If a check cannot run, record why and the remaining risk;
never label an unvalidated checkpoint as validated.

Inspect the staged diff and stage only task-owned files or hunks. Preserve other
people's dirty work and exclude credentials, private data, generated runtime
artifacts, and logs. Follow repository signing and hook requirements. Preserve
checkpoint history: do not amend, squash, rebase, or discard it without explicit
authorization. Local checkpoint permission does not authorize pushing, publishing,
merging, deploying, or other hosted mutations; obtain those transitions from the
user or the project's established workflow.

Use operational, imperative commit subjects describing the affected component and
observable change, for example `fix(auth): reject expired session grants` or
`docs(security): record provider credential boundaries`. Avoid `updates`, `WIP`,
or a bare issue number. For substantial commits, include the reason, checks
actually run and their outcomes, and recovery instructions or limitations in the
body. Reference related work where available. A Git revert restores code, not
external data, deployed state, secrets, or migrations; document those recovery
steps separately. Never execute a destructive rollback merely to prove it works.

## Documentation accompanies implementation

In the same coherent change, update affected user behavior, APIs, architecture,
configuration, data handling, deployment, operating procedures, migration and
recovery instructions, tests, and security assumptions. When documentation or the
threat model needs no update, give a specific no-impact rationale in the PR.
Keep examples synthetic and distinguish supported behavior from future plans.

## Independent human approval

Every change requires independent human review before merge or release. Automated
reviews and agent self-review provide evidence but never constitute human approval.
Use a draft PR until the required evidence and review are available. A human
reviewer must inspect the actual diff and affected existing code, tests and
negative cases, documentation, operational recovery, and threat-model changes.
Security-sensitive changes require a reviewer competent in that domain.

Record the reviewer's identity, date, exact reviewed commit SHA and scope,
validation evidence, findings and their disposition in the PR or a durable review
record. Changes after review require renewed review of the changed scope; approval
of an earlier revision is not approval of the current head. Track unresolved
findings with an owner and deadline. A blocking risk requires remediation or
explicit, scoped human risk acceptance with rationale, compensating controls and
expiry; an agent cannot accept risk on a human's behalf. Existing stricter merge,
signature, CI and release gates continue to apply. Do not claim readiness while
required human review is pending.

## Retroactive review of existing code

Maintain `docs/security/REVIEW_COVERAGE.md` as a baseline inventory of ALL existing
first-party code, infrastructure, CI, build/release scripts and agent/tool execution
surfaces. Imported third-party code needs a recorded provenance and dependency
review rather than a fabricated first-party approval. Initial entries are pending,
not evidence of a completed audit. Account for new directories and previously
omitted files before claiming full coverage.

Triage the inventory within 30 days of adopting this policy and assign human
owners and dates for completing the first pass within 90 days. Before an affected
release, review critical authentication, authorization, secrets, parsers, execution,
publishing and supply-chain paths. A new change also requires review of the
existing code on which its safety depends. Other legacy review can be scheduled
explicitly; do not imply that every PR re-audits the whole repository.

For each completed scope, record file paths, baseline and reviewed SHA, reviewer,
date, checks, findings, resolution or accepted residual risk, and next review
trigger. A review expires for changed behavior or assumptions; track the remaining
unreviewed scope. Missing review is a visible backlog item, never silently approved.

## Living threat model

Maintain a detailed project-specific model linked from `AGENTS.md`. The initial
model is a source-based baseline awaiting human confirmation, not a penetration
test or certification. Update it in the same change whenever assets, data flows,
trust boundaries, actors, authentication, authorization, provider/tool capabilities,
parsers, storage, dependencies, build pipelines or deployment assumptions change.
At every release and at least quarterly, reconcile the model and review coverage
against current code and operating evidence; record the revision and reviewer.

Include supported and unsupported operating modes; actors and goals; sensitive
assets and retention/deletion; components and data-flow diagrams; entry points,
trust boundaries and effective resource identities; abuse cases; STRIDE analysis;
privacy and availability threats; implementation evidence; likelihood and impact;
existing controls versus proposed mitigations; residual risk; human owner and due
date; and reproducible validation criteria. Track security-relevant unknowns.
Never present a planned control as implemented or an attack hypothesis as a
confirmed vulnerability. Include subprocess, filesystem, network destination,
credential recipient and privilege boundaries where applicable.

Apply relevant least privilege, deny-by-default authorization, secure secret
storage, input validation, output encoding, bounded resource use, isolation,
cryptographic transport, dependency provenance, reproducible build, monitoring,
incident response and recovery practices. Explain inapplicability rather than
copying an exhaustive compliance checklist. Map high-risk controls to tests and
human evidence. No document can establish compliance with every industry practice.

## Reference frameworks

Use the [OWASP threat modeling process](https://owasp.org/www-project-threat-modeling/)
and [threat modeling cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
for decomposition, threats, mitigations and validation; [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
for secure development and vulnerability response; [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0)
for applicable application controls; and [SLSA 1.2 threats](https://slsa.dev/spec/v1.2/threats)
for build and distribution analysis. These are references, not asserted certification
or an automatic change to existing project assurance requirements.
