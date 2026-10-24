---
name: model-effort-routing
description: "Use for requests to help me choose a model for this task. Suggest an available model and supported reasoning effort before issue implementation or security work using fresh host capability and access evidence."
---

# Model and effort routing

Use this skill for model selection, reasoning effort preflight or issue work that
may benefit from an available flagship cybersecurity model. Read the
[model routing guide](../../docs/MODEL_ROUTING.md) for the catalog contract and
result meanings. Daybreak, Fable, Mythos and Astra are examples of family labels,
not proof of capability or access.

## Prerequisites

- A COPS repository checkout and Python 3.11 or newer accessible to the host.
  Run the commands from that checkout's root. The portable plugin archive does
  not bundle the root `cops` runtime; if absent, report the prerequisite and pause.
- Fresh evidence of exact host IDs, per-model access, capabilities and supported
  efforts, recorded in `cops.model-catalog/v1`. Keep secrets out of the catalog.
- Current model and effort from the host, not inferred from the conversation.

## Workflow

1. Read the issue/request, its acceptance criteria and relevant context. Assess
   whether security specialization would materially benefit the work.
2. Obtain or refresh the host catalog. Never infer Red access from Blue, or model
   availability from a family name. Missing evidence stays unknown.
3. Run the shared deterministic advisor, using verified current settings:

   ```bash
   python3 -m cops route "<issue scope and acceptance criteria>" \
     --suggest-model --model-catalog ./host-models.json \
     --current-model <exact-current-id> --current-effort <supported-effort> --json
   ```

   If the current pair is unknown, omit it and report that verification is needed.
   Review `model_advice.task`; use `--task-kind` or `--complexity` to correct a
   classification when the issue's actual scope supports the correction.
4. Explain the required capability and effort, qualified recommendation and useful
   alternatives. Treat catalog evidence as operator assertions, not authenticated
   entitlement. `no_eligible_model`, stale/future/missing catalogs and
   `current.status: unverified` require verification before implementation.
5. If `current.status` is `change_recommended`, pause and suggest the exact model
   and effort. If a qualified option has `family: Daybreak` and would materially
   benefit this issue, explicitly recommend that option and pause for a required
   change. `adequate` means the current pair meets the stated requirements;
   model ranking alone does not prove a switch would improve results.
6. Have the host/operator select and verify the intended settings. Where the user
   authorizes subagents, the orchestrator may delegate bounded work with supported
   overrides after applying its routing/workboard policy. This skill does not
   launch agents or modify settings. A child setting never changes the parent.

Keep `xhigh`, `max` and `ultra` manual. Keep all existing security scope and
authorization gates. Report the recommendation as advice, never as a completed
model switch, granted entitlement or authorization to execute.
