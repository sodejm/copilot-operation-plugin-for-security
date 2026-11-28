# Plugin verification record

Template only. Replace every placeholder; no step has been performed by copying
this file. See [the qualification guide](https://sodejm.github.io/copilot-operation-plugin-for-security/plugin-verification.html)
for the required gates and documentation update process.

## Identity and scope

- Plugin ID and package version: TODO
- Tested commit and working-tree/patch state: TODO
- Run date/time in UTC, operator, and independent reviewer aliases: TODO
- Current maturity and proposed maturity: TODO
- Declared workflow, output contract, and scope being qualified: TODO
- Python/tool versions, OS, and installation prerequisites: TODO
- Synthetic input IDs/digests and sanitized representative-input digests: TODO
- Approved host/data handling context; separate live authorization if applicable: TODO
- Playbook revision and private evidence bundle alias/digest: TODO

## Results

Use `pass`, `fail`, `blocked`, or `not_applicable`. Fill expected/observed behavior
and a sanitized evidence reference for each result, including exit codes where
applicable. Explain any `not_applicable` and list every untested advertised host.

| Step | Result | Expected behavior | Observed behavior / exit code | Evidence alias or digest |
| :--- | :--- | :--- | :--- | :--- |
| Discovery and prerequisites | blocked | TODO | Not run | TODO |
| Synthetic demo and additional end-to-end exercise | blocked | TODO | Not run | TODO |
| Complete package checks | blocked | TODO | Not run | TODO |
| Representative input compared to independent expected answer | blocked | TODO | Not run | TODO |
| Invalid, partial, and out-of-scope input | blocked | TODO | Not run | TODO |
| Failure recovery and side-effect inspection | blocked | TODO | Not run | TODO |
| Fresh repeat run and second operator | blocked | TODO | Not run | TODO |
| Repository checks on review revision | blocked | TODO | Not run | TODO |
| Cleanup | blocked | TODO | Not run | TODO |

## Host matrix

Add a row for each host/OS advertised in the proposed stable scope, including
unavailable hosts. Record SDK dependencies and exports rather than assuming the
standalone package is sufficient. An empty matrix cannot qualify advertised hosts.

| Host / version / OS | Format / artifact digest / dependencies | Discovery and invocation | Output and boundary case | Cleanup / fresh repeat | Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| TODO | TODO | blocked | blocked | blocked | TODO |

## Review decision

- Decision: pending (accepted / changes required / blocked)
- Reviewer alias and review date: TODO
- Gates met, reviewed revision, and repeat-run record references: TODO
- Unresolved defects, excluded scope, unverified integrations, and owners: TODO
- Requalification triggers or review expiry: TODO
- Accepted record links and maturity/support documentation changes: TODO
- Documentation-only promotion revision and validation results, if applicable: TODO

Keep raw evidence private. Do not commit secrets, personal data, internal URLs,
or absolute machine paths. A passing offline result does not attest host or live
support. Approval assertions and fixture receipts do not authorize live actions.
