# One request for a Detection Quality review

## In Copilot chat

Open this checkout as a trusted workspace with the COPS MCP server enabled and Python 3.14 or newer available to the host as `python3`. Ask in chat:

> Check whether our Sentinel and Splunk detections catch the bundled cases.

Copilot passes the original wording to `cops/request`. COPS selects the registered Detection Engineer, workbench and skill and returns a run ID. Copilot uses it in the same turn to run both suites and report the affected fixture cases. Copilot CLI and the Copilot harness in VS Code discover this tool from the workspace-root `.mcp.json`. The optional **COPS** custom agent gives a dedicated chat access to the same tool. [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)

If the review is interrupted after acceptance, reopen the same conversation in the same checkout and say:

> Resume my review.

Copilot uses the run ID already in the chat. If you start another chat, supply the original ID. If several reviews match, specify which one to continue. Checkpoints live under `$XDG_STATE_HOME/cops/copilot` (default `~/.local/state/cops/copilot`), grouped by checkout. Keep the same user, checkout path and state directory when resuming. A fresh request starts a separate review.

## From the command line

From the repository root, ask COPS to evaluate the packaged rules and explain the gaps. The command selects the registered Detection Engineer, its Detection Quality workbench and its `detection-quality-review` skill. It invokes the skill's local reference evaluator for both fixture sets. The checkpoint records every case outcome. The final result names each rule, its gaps and the digest of its verified receipt.

```sh
python3 -m cops ask "Check the bundled Sentinel and Splunk rules against their labeled fixtures and explain the coverage gaps." --run-dir ./quality-run
python3 -m cops ask --resume ./quality-run --json
```

Supply a **new directory** for a fresh run. Omitting `--run-dir` creates a private run directory beneath `$XDG_STATE_HOME/cops/detection-quality` (default `~/.local/state/cops/detection-quality`). The command prints the directory to standard error before evaluation, so an interrupted terminal run can be resumed from another process. Use `cops route` with the same request to preview the selected profile and skill.

The coordinator verifies the report against its schema, rule identity, ordered labeled cases, missing telemetry and aggregate counts. It commits each verified suite and its digest together. A resume rechecks both the saved evidence and the fingerprint of the packaged rules, fixtures, skill, evaluator and schema. Concurrent resumes serialize on the checkpoint. An interruption before a suite commits can repeat that local evaluation. An interruption after commit reuses its report. Treat the directory as trusted local state. These digests cannot authenticate evidence against someone who can replace the entire checkpoint.

The packaged Sentinel suite contains two cases with absent or null `IPAddress`. One Splunk case lacks `ScriptBlockText`. The report keeps all three cases visible and withholds fixture precision and recall when a suite has missing telemetry. A verified review establishes how the offline reference evaluator handled the synthetic fixtures. A native query engine and a production telemetry pipeline require their own evidence.

## Routing decisions

The general router on the pilot's starting revision scored the Sentinel/Splunk request as a three-way tie below its 0.65 confidence floor. The fixture operation now recognizes a complete positive request, resolves its registered owner and selects the exact skill. Its fixed rule and fixture inputs come from the package. The CLI preview uses the same selection. General specialist thresholds and model configuration are unchanged.

The recognizer accepts the pilot name, both platform names in either order and requests for both Detection Quality fixture sets. The tests pair these with negations, examples, a single platform, identifiers alone, external data and extra actions. A request outside the supported language returns clarification from `ask` before it creates a run. This deliberately finite vocabulary can miss reasonable paraphrases. The registered-owner match score is a selection signal. Measuring how people phrase this request requires a held-out corpus.

## Coordinator issue plan

COPS already uses Squad for contributor coordination. Squad gives each assignment a named owner, scoped context and expected return. Its coordinator combines the returns, while the Scribe preserves decisions for later sessions. For this operator workflow the reusable pattern is one accountable coordinator and a small, verifiable specialist return. The current specialist can produce that return with the local evaluator, without the cost or availability requirements of another model session. [Squad architecture](https://github.github.com/squad/docs/concepts/architecture/) · [Spawn templates](https://github.com/github/squad/blob/dev/templates/spawn-reference.md) · [Skills](https://github.github.com/squad/docs/features/skills/) · [COPS contributor workflow](SQUAD.md)

| Proposed work item | Owner and dependency | Acceptance evidence |
| --- | --- | --- |
| Register Detection Quality in the headless operation lifecycle | Coordinator owner, build on [#334](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/334). Use its operation ID, idempotency key and registry-owned handler. | A repeated create for the same request returns the same operation. Status, cancel, recover and resume honor the original binding. The final result identifies both suite receipts. The public API exposes an operation ID rather than a host path. |
| Specify a typed specialist handoff and return for offline fixture reviews | Workbench and evidence owners, after the #334 handler binding. Reuse the existing SpecialistHandoff evidence fields where they match. | An assignment identifies the request, stage, owner, skill, input digest, expected cases and completion condition. The return identifies that assignment and its report digest. The coordinator rejects a different owner, stale inputs, incomplete output or a return for another request. A duplicate return has one effect. |
| Calibrate selection and clarification | Routing owner, extend the held-out corpus in [#336](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/336) and the clarification work in [#337](https://github.com/sodejm/copilot-operation-plugin-for-security/issues/337). | Blind evaluation reports correct owner **and** skill, missed eligible requests, unwanted starts and unnecessary questions separately. Include negation, exclusions, quotation, novel paraphrases and two independent asks. Every unwanted start in the boundary suite fails the gate. One clarified answer can complete the original request. |
| Qualify long-running recovery for a second defensive artifact review | Coordinator and validation owners, after the lifecycle and handoff items. | Exercise termination before and after acceptance, two simultaneous resumes, cancellation during evaluation, a stale return, and exhausted time or step budgets. Accepted stages stay accepted. One terminal result contains evidence for every required stage, and no new assignment starts after cancellation. |

The pilot has one locally owned run and two durable suite receipts. These proposed issues extend that ownership across hosts and specialist boundaries. The pilot does not require a second scheduler, agent message bus, or global routing threshold change.
