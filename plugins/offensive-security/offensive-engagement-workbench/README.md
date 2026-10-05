# COPS Offensive Engagement Workbench

`offensive-engagement-workbench` provides authorized adversarial assessment intake, scope boundary validation, execution mode classification, and reviewable immutable action planning for the Copilot Operations Plugin for Security (COPS) ecosystem.

## Features

- **Engagement Intake**: Enforces explicit operator ownership, valid authorized windows, unambiguous targets, non-colliding exclusions, execution budgets, and credential references.
- **Scope Ambiguity Prevention**: Rejects wildcards, universal networks, and targets colliding with excluded boundaries.
- **Execution Mode Distinction**: Strictly differentiates between `planning`, `import`, `laboratory`, and `live` modes.
- **Live Safety Guard**: Prohibits live execution without mandatory budgets, emergency contact channels, active windows, and tight subnet scopes.
- **Action Plan Compilation**: Generates immutable `ActionPlan` (`cops.action-plan/v1`) contracts with platform prerequisites, expected evidence receipts, side effects, and verified cleanup obligations.
- **Triad Specialist Handoffs**: Emits and validates `SpecialistHandoff` (`cops.specialist-handoff/v1`) contracts coordinating Planner, Specialist, Skeptic, and Auditor with capability matching and re-approval triggers.

## CLI Usage

```bash
# Create an engagement contract
python3 -m cops engagement create \
  --name "App Scope Review" \
  --owner "secops-operator" \
  --targets "10.100.0.10,app.internal" \
  --exclusions "10.100.0.1" \
  --start "2026-10-05T00:00:00Z" \
  --until "2026-10-05T23:59:59Z" \
  --budget-duration 1800 \
  --budget-output-bytes 5242880 \
  --output engagement.json

# Validate an engagement contract
python3 -m cops engagement validate engagement.json

# Compile an action plan
python3 -m cops engagement plan \
  --engagement engagement.json \
  --scenario COPS-E03.01-S01 \
  --target 10.100.0.10 \
  --output action_plan.json

# Run Triad specialist handoff workflow
python3 -m cops engagement handoff workflow \
  --engagement engagement.json \
  --plan action_plan.json \
  --task "Network perimeter assessment" \
  --planner "secops-operator" \
  --output handoff.json
```

## Offline Verification Gate

```bash
python3 -m cops check offensive-engagement-workbench
```
