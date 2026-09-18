---
name: agentskills-frontmatter-enforcer
description: Verify that all workspace and plugin skill files strictly adhere to the Agent Skills spec.
---

# Agent Skills Frontmatter Enforcer Skill

Use this skill to check all `SKILL.md` files (such as those under `security-logging-advisor/skills/` and `.agents/skills/`) to guarantee compliance with the Agent Skills standard (agentskills.io).

## Verification Checks

Ensure all `SKILL.md` files contain frontmatter with exactly:
- `name`: unique identifier
- `description`: clear operational description

Additionally, ensure no skill exceeds 500 lines. Supporting reference material must reside in a `references/` subdirectory.
