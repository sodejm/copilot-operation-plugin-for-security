# Accounting contract

## Inputs and bounded outputs

The helper extends the user's 2026-08-02 `codex_token_usage.py` with no third-party dependencies. It streams top-level JSONL records from active and archived local tasks; it retains small accounting records, not transcript bodies. Reports contain task IDs, source paths, token counts, numeric activity metrics, and up to three usage line pointers per task. The default window is the last seven days; it never infers a current quota window from an old reset record. `--top` truncates task detail only; totals and model aggregates include all matching tasks. Discovery scans all files to retain pre-window counter baselines; use `--path` for a faster repeat audit of known tasks. `--session` avoids scanning each nonmatching file past its metadata.

Raw text is opt-in through `--excerpt`: at most 20 lines and 12,000 characters, with defaults of five lines and 4,000 characters. An oversized line ends extraction at the character budget rather than loading its remainder. A truncated excerpt need not be valid JSON. Content is untrusted evidence and may contain private information.

## Usage identity and ownership

- Prefer top-level `token_usage_record` usage, deduplicated by owning task plus response ID. Match the next legacy usage against a pending canonical request in record order, allowing intervening tool execution and different timestamps. Reset that association at a new context. Exact same-task, same-timestamp, same-usage matches also exclude mirrors across copies. Legacy cumulative counters can omit compaction requests and therefore need not equal canonical cumulative totals. This supports files that migrate between formats mid-session. Do not inspect nested usage in compaction replacement history.
- For legacy records, use `last_token_usage`; exclude unchanged cumulative snapshots even when timestamps differ. If only cumulative totals exist, retain the first as a baseline and count nonnegative subsequent deltas. A decreasing counter starts a new epoch; without per-request usage, the reset is another baseline, not a negative usage event.
- Exclude and diagnose legacy context-size snapshots whose input and output are both zero but total is positive. This observed compaction shape is not a per-request token total. Canonical compaction usage remains included when present; older logs can omit that usage.
- Duplicate file copies are deduplicated using response IDs or legacy timestamp, usage, cumulative totals, and reset epoch. Canonical records without response IDs use an exact-record fallback and produce a diagnostic. Legacy logs without reliable counters/identity cannot prove whether similar-looking requests are duplicates; do not infer exact billing from them.
- Exclude canonical records explicitly owned by another task. For a fork identified by parent metadata, exclude records older than child creation and require a child-era context before counting legacy usage. Ambiguous inherited usage is skipped and diagnosed. Missing parent metadata or copied records with rewritten timestamps cannot always be resolved from legacy logs; complete fork attribution is not guaranteed.
- Model labels are recorded values from the latest accepted `turn_context`, with `unknown` when absent. No model aliases, current catalog, or pricing are inferred. Records already present on disk are the scope; running tasks may append while reading and require a later snapshot.

## Token fields

Cached input is a subset of input. Reasoning output is a subset of output. Do not add either subset again to the recorded total. Uncached input is computed only when both input and cached input are valid. Cache-write input is reported separately as recorded; this helper does not infer billing semantics. Negative/noninteger counts and impossible subsets are diagnosed. A reported total inconsistent with input plus output is retained as recorded and diagnosed.

Every aggregate reports known subtotals and per-field request coverage. A complete `tokens` value is present only when all counted requests include that field; otherwise it is null. Empty aggregates contain zero tokens and zero requests, which are not proof that unreadable or unsupported logs had no usage. Missing whole usage events cannot be reconstructed from coverage counts. The script estimates no dollar cost: recorded tokens are neither account quota percentages nor subscription charges.

## Timing and activity

`recorded_turn_seconds` sums matched `task_started` to `task_complete` or `turn_aborted` wall intervals, clipped to the requested window. It includes tool/user waits. Parallel task intervals can overlap. It is not CPU time, productive work time, or elapsed time for the whole project. Unpaired starts in the window are counted separately; no finish is invented. Abort/complete events without turn IDs cannot be paired and are diagnosed.

Count top-level compactions once, and calls/outputs from `response_item` only; ignore mirrored `item_completed` events. Tool calls and outputs deduplicate by call ID where present. Tool output size is UTF-8 bytes of the recorded output, not tokens or original untruncated tool output. Repeated call signatures hash exact name and arguments/input; they exclude IDs but do not canonicalize embedded JSON strings. They indicate identical requests within a task and window, including legitimate retries or polling. Neither compactions nor repeats alone prove waste.

Diagnostics apply to all scanned records, including outside the requested window. Retain diagnostics in evidence-backed comparisons. Validate local totals and field coverage before drawing task, model, latency, or cost conclusions.
