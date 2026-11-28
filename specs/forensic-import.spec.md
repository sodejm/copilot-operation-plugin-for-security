# Raw disk and memory evidence import

`cops forensic import --root DIRECTORY --manifest FILE` verifies a raw disk or
memory image through the registered `raw-forensic-image/v1` adapter. The input
contract is `cops.forensic-import-input/v1`; output is `cops.forensic-import/v1`.
POSIX descriptor-relative no-follow file access is required. Every ancestor of
the root and source is checked. Sources must be nonempty regular files with a
pinned SHA-256 and stable identity throughout a bounded streaming read (128 MiB
maximum). Import opens no destination and never mounts or executes evidence.

Require opaque artifact, source and authorization references, explicit collection
permission, collection and assessment timestamps, and at most 128 custody events.
The first event must acquire the same source at its collection time; later events
may transfer or verify it. Every event has an opaque actor, the expected digest,
and an ordered timestamp between collection and assessment. Unknown fields,
unsupported formats, missing metadata, future times and changed bytes fail with
content-free errors. An authorization reference records the caller's assertion;
it does not establish authority or replace ActionPlan authorization for capture.

Report source and custody digests, byte count, adapter identity, and verification
limits. Verified integrity is distinct from authentic source identity, a trusted
custody chain, filesystem analysis, memory analysis or native acquisition. E01,
AFF4, compressed images, device files and native capture are explicitly unsupported.
The existing disposable acquisition adapter remains the only lab copy adapter.

Acceptance covers raw disk and memory files, corrected metadata, denied or
incomplete metadata, modified bytes, ordered custody, symlinks at every level,
FIFO rejection without blocking, reduced budgets, source immutability and output
redaction. The isolated service gate must acquire and import actual synthetic
files, including rejected tampering; marker files are not acceptance evidence.
