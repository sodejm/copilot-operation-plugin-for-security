---
name: security-review
description: Perform a scoped defensive review of a repository change covering trust boundaries, secrets, input handling, permissions, dependencies, and abuse cases.
---

# Security review

1. Define the changed surface, assets, actors, trust boundaries, and attacker goals.
2. Trace untrusted inputs through parsing, authorization, storage, logs, network
   calls, command execution, rendering, and outputs.
3. Review secrets, least privilege, authentication and authorization, injection,
   path handling, unsafe deserialization, dependency provenance, denial of service,
   privacy, and failure behavior as relevant.
4. Validate plausible findings with concrete source-to-sink evidence or focused
   tests. Separate confirmed vulnerabilities, hardening opportunities, and unknowns.
5. Recommend the smallest effective remediation and a verification plan.

Do not expose exploit details publicly, access data beyond scope, or claim a clean
security result when important checks were unavailable.
