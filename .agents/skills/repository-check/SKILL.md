---
name: repository-check
description: Run the repository-owned validation path, capture exact evidence, and separate failures, skips, and environment blockers.
---

# Repository check

1. Read `AGENTS.md` and inspect current Git state.
2. Run the narrow test or check that matches the change during development.
3. Run `make check` before handoff unless the contract specifies a stronger gate.
4. Record exact commands, exit status, meaningful results, skipped coverage, and
   residual risk. Sanitize paths, credentials, private data, and internal URLs.
5. Classify each failure as a code failure, test failure, environment limitation,
   missing dependency, or hosted-service failure before proposing action.

Never report a pass from source inspection alone. Do not silently weaken checks or
change assertions merely to obtain a green result.
