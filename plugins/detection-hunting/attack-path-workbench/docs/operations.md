# Offline operation

1. Supply a local manifest with relative source paths and expected SHA-256 values. Supply the crown-jewel IDs, scope, optional priority and service context. The executable profile is currently synthetic only.
2. Run `python3 scripts/attackpath.py analyze INPUT --output-dir NEW_DIRECTORY` from the plugin directory. The CLI makes no network calls and refuses an existing output directory.
3. Review `report.json` as canonical. `report.md` and `graph.json` are projections. Inspect quarantine, graph exclusions, partial routes, candidate gaps, source pointers, and G1–G8 statuses before using any action.
4. Review proposed actions in `remediation-ledger.json`. Supply owner and validation evidence in a separately governed follow-up process; do not edit the generated report to imply closure.
5. For an identical input and profile, compare canonical report bytes and run ID. Different source snapshots are separate runs and may be compared only within the same declared scope and compatible mapping rules.

The illustrative fixture includes one supported structural route, one candidate route, a rejected graph transition, and a quarantined undocumented row. All names and records are invented. The report is suitable for inspecting semantics, not for operational conclusions.
