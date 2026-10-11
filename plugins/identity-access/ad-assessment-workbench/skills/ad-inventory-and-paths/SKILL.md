---
name: ad-inventory-and-paths
description: Analyze approved local Active Directory inventory exports for provenance-linked candidate relationship paths and coverage gaps.
---

# AD inventory and paths

Use this skill only for an explicitly scoped, approved local export. Verify the
forest, domain, and host scope with the requester before handling real data. Do
not request credentials or query AD, LDAP, Kerberos, or hosts. The input contract
is in `specs/ad-inventory-and-paths.md` at the repository root.

1. Run `python3 plugins/identity-access/ad-assessment-workbench/scripts/analyze.py <local-export.json>`.
2. Review `coverage` first. `unknown` or `partial` means collection cannot support
   a claim of absence. A missing path means only that a completed search of the
   collected graph lacks it; `search_incomplete` means the search hit a bound.
3. Trace each candidate path's directed edges to collector ID, UTC time,
   completeness, and observed/inferred support. Treat trust, protected identities,
   partial collection, and inferred edges as validation questions.
4. Report candidate structural relationships, uncertainty, and the additional
   evidence needed. Never describe an observed edge or graph path as proof of
   usable access, exploitation, or live validation.

The fixture and demo are synthetic. Keep imported data local and follow the
engagement's evidence handling rules. The analyzer rejects raw display names and
attributes; prepare opaque IDs before import.
