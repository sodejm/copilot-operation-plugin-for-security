# CodeQL evidence guards

The versioned `cops/evidence-guards` Python pack supplements the standard
`security-extended` suite. The CodeQL workflow retains the Python analysis category,
tests this pack before analysis, and runs a separate Actions extended analysis.

## Unredacted evidence writes

`cops/unredacted-evidence-write` follows `stdout`, `stderr`, `error`, `action`,
and `artifact_outputs` from `EvidenceRecorder.record_step_output` in
`cops/execution/evidence.py` to the content argument of its reserved artifact
writers. These writers persist both output bytes and canonical evidence envelopes.
The rule follows nested dictionaries and lists, `build_envelope(payload=...)`,
`canonical(...)`, and helper calls. Hashing preserves taint: evidence hashes must
describe redacted content, as required by the existing evidence metadata contract.

Only the returned value of the configured `self.redactor.redact`, `redact_string`,
or `redact_bytes` calls is a barrier. A discarded result does not sanitize the
original argument or another
field in the envelope. Review the rule when capture fields, redactors, serialization,
or store methods change. Its scope is the evidence recorder; arbitrary file writes
and similarly named methods on other classes are outside this guard.

The inert fixtures under `python/tests` are extracted by CodeQL and never executed.
The bad cases require alerts for raw bytes, discarded redactor results, raw hashes,
action metadata through a helper, artifact paths/content, and a mixed envelope.
The good cases require no alerts for returned redacted values through the same
serialization, fixed data, and unrelated writes. Expected results are committed;
review each result before updating them.

## Local verification

Check the workflow languages, production exclusions, and CI regression command
without running CodeQL or the inert fixtures:

```sh
python -m pytest tests/test_codeql_configuration.py -q
```

Use a CodeQL CLI bundle with Python libraries and extractors:

```sh
codeql pack install codeql/python
codeql test run codeql/python/tests
codeql database create /tmp/cops-python-db --language=python --source-root=. \
  --codescanning-config=.github/codeql/python.yml
codeql database analyze /tmp/cops-python-db codeql/python/queries \
  --format=sarif-latest --output=/tmp/cops-evidence.sarif
```

Fixtures are excluded from production analysis by `.github/codeql/python.yml`.
Keep database and cache output outside the checkout. A passing static guard does
not establish that redaction patterns remove every secret, qualify a live provider,
or replace evidence lifecycle and security review.
