---
layout: documentation
title: "Getting Started with COPS"
description: "Start with a security goal, try a local example, and learn what is required before execution."
---

# Getting started with COPS

Start with what you want to accomplish. You do not need to know a plugin name,
prepare a signed engagement, or connect a live account to ask for help or draft
a plan. In an assistant with the relevant COPS skills available, try:

- “Help me plan a security assessment.”
- “Help me understand this suspicious login.”
- “List the endpoints in this API specification.”
- “Help me decide what security logs my app needs.”

The assistant can draft next steps from the information you have and mark what
is missing. If the goal is ambiguous, it should ask a short question about the
outcome you want. A draft is not an approved or validated execution plan.

## Try it locally

The core CLI requires Python 3.11 or newer. Use an existing checkout, or clone
with Git and network access:

```bash
git clone https://github.com/sodejm/copilot-operation-plugin-for-security.git
cd copilot-operation-plugin-for-security
```

Route a goal, then inspect the recommended plugin:

```bash
python3 -m cops route "Help me understand this suspicious login"
python3 -m cops info soc-investigation-workbench
```

Routing recommends a specialist; it does not launch an agent, contact a target,
or grant permission. No assistant installation or cloud credentials are needed
for these CLI commands. Run `python3 -m cops list` to browse the current catalog,
or `python3 -m cops doctor` if you need environment diagnostics.

For a packaged example with synthetic local evidence:

```bash
python3 -m cops demo soc-investigation-workbench
python3 -m cops check soc-investigation-workbench
```

These checks establish the packaged offline behavior, not production readiness.
For a complete investigation, follow [Investigate possible malicious access](investigate-malicious-access.md).

## What you need at each stage

| Stage | Enough to start | Boundary |
| --- | --- | --- |
| Discuss or draft | A goal and any context you have | Record unknowns; do not invent scope, evidence, or approval. |
| Inspect local evidence | Permission to process the supplied files | Use the relevant parser, protect secrets, and report missing evidence. Listed hosts are not authorized targets. |
| Validate a contract | Required fields for that contract | Run its validator. Incomplete draft notes are not a valid Engagement or ActionPlan. |
| Run a laboratory | The documented fixture and isolation prerequisites | Follow the lab’s readiness and approval requirements; do not substitute a live target. |
| Execute against a live system | Supported capability, approved scope and exact plan, valid authorization, ready worker, budgets and stop/cleanup controls | Fail closed when any required check is missing. Drafting or routing never bypasses these checks. |

Some capabilities only support offline evidence or local fixtures. For example,
the API CLI inventories local files and supports synthetic replay; it rejects
live replay until the shared CLI integrates approval, worker, and scope
dependencies. Live WebSocket execution is unsupported. Check each capability’s
[playback and limitations](plugin-playbacks.md) before choosing an execution path.

## Continue when needed

- [Plugin guide](plugin-guide.md): package usage and assistant integration.
- [Specialist agents](specialist-agents.md): routing, proposed critical-task review, and authorization.
- [Runnable workflows](plugin-playbacks.md): examples and reference material for every plugin.
- [Verification playbooks](plugin-verification.md): qualification and evidence requirements.
- [Troubleshooting](troubleshooting.md): environment and offline installation help.
- [Contributor guide](contributing.md): development setup and full repository tests.

Core CLI commands use the Python standard library. Contributor test dependencies
are listed in `requirements.txt`; signed laboratory receipt verification requires
the optional `laboratory` extra. Install these only when the chosen workflow needs
them, using network access or prepared local packages.
