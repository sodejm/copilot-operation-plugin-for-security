# Offline operation

1. Supply a local manifest with relative source paths and expected SHA-256 values. Supply the crown-jewel IDs, scope, optional priority and service context. The executable profile is currently synthetic only.
2. Run `python3 scripts/attackpath.py analyze INPUT --output-dir NEW_DIRECTORY` from the plugin directory. The CLI makes no network calls and refuses an existing output directory.
3. Verify `completion.json` before consuming the report set, then review `report.json` as canonical. `report.md` and `graph.json` are projections. Inspect the search receipt, quarantine, graph exclusions, partial routes, candidate gaps, source pointers, and G1–G8 statuses before using any action. If search stopped early, interpret ranking as the best discovered paths only; rerun with a higher budget within the hard ceilings if fuller coverage is needed.
4. Review proposed actions in `remediation-ledger.json`. Supply owner and validation evidence in a separately governed follow-up process; do not edit the generated report to imply closure.
5. For an identical input and profile, compare canonical report bytes and run ID. Different source snapshots are separate runs and may be compared only within the same declared scope and compatible mapping rules.

The illustrative fixture includes one supported structural route, one candidate route, a rejected graph transition, and a quarantined undocumented row. All names and records are invented. The report is suitable for inspecting semantics, not for operational conclusions.

## Filesystem permissions and output boundary

Report directories are created with owner-only permissions (`0700`) and individual report files (`report.json`, `graph.json`, `report.md`, `remediation-ledger.json`, `completion.json`) with mode `0600`.

Publish reports beneath an analyst-owned, private parent directory that untrusted accounts cannot mutate during a run. The CLI uses descriptor-anchored directory creation and file writes, then confirms that the requested path still names the opened directory. Existing paths, symlink redirections, and concurrent directory swaps fail without publishing a completion marker at the displaced path.

## Complete and partial report sets

The writer synchronizes the new output-directory entry, the four legacy report files, and their directory entries before it publishes `completion.json` without replacing an existing marker. Publication is bound to the open staging file, so replacing its temporary pathname cannot substitute different marker bytes. The writer immediately synchronizes the public marker before attempting staging cleanup. A consumer may treat a set as complete only when the marker validates against `schemas/completion-v1.schema.json`, its `run_id` equals `report.json`'s run ID, and its exact four SHA-256 digests match the stored report bytes. The marker's `status` concerns the durability of the four-report set; search coverage remains governed by `report.json`'s search receipt.

If a report write, report-directory synchronization, or final output-path check fails before marker publication, the CLI exits with status 2 and does not print success JSON. It preserves earlier report files as partial evidence and may leave an internal `.completion-*.tmp` staging file after a later failure. A staging file is never completion evidence. Do not publish or automate from a partial set; inspect it for failure diagnosis, then rerun to a fresh output directory.

Publication followed by the first successful directory synchronization is the report-set commit point. If that synchronization fails, `completion.json` may be visible but its durability is uncertain; the CLI exits with status 2, and consumers must treat the run as partial pending filesystem diagnosis. The writer never removes a public `completion.json` while handling an error because another invocation may own or have replaced that path. After the commit point, a valid marker remains authoritative if staging-name cleanup, its follow-up synchronization, or final path validation reports an error, although the CLI still exits with status 2 and does not print success JSON. A final path-validation failure can also mean the requested pathname no longer reaches the opened report directory. Diagnose the filesystem error before moving or deleting either location.
