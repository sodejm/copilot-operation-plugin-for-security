---
layout: documentation
title: "Model and effort routing"
description: "Offline model and reasoning effort suggestions from fresh host capability and access evidence."
---

# Model and effort routing

COPS can suggest an exact available model and supported reasoning effort before
issue implementation or security work. The shared CLI powers the portable
`model-effort-routing` skill in Offensive Engagement Workbench.

```bash
python3 -m cops route "Review the issue's authorization boundary" \
  --suggest-model --model-catalog ./host-models.json \
  --current-model exact-current-host-id --current-effort medium --json
```

The [complete operator guide](../plugins/offensive-security/offensive-engagement-workbench/docs/MODEL_ROUTING.md)
defines the catalog, task requirements, exclusions and preflight workflow. The
[plugin skill](../plugins/offensive-security/offensive-engagement-workbench/skills/model-effort-routing/SKILL.md)
ships that workflow to assistant hosts. Both require access to the COPS checkout
and Python 3.11 or newer; the portable archive does not bundle the core runtime.

Daybreak, Fable, Mythos, Astra and future families are eligible only when fresh
operator evidence establishes the exact model's availability, granted access,
capabilities and efforts. Blue and Red access are independent. The advisor neither
contacts providers nor changes model settings, launches agents or grants authority.

Before implementing any issue, assess Daybreak benefit and verify the current
model and effort. Pause for a beneficial Daybreak change or an unverified or
insufficient current pair. Authorized delegation still requires a model/effort
pair supported by the actual launcher. Routine work starts at the lowest sufficient
tier and effort; `xhigh`, `max` and `ultra` remain manual escalations.
