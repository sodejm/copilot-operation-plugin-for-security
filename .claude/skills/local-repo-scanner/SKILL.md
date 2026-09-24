---
name: local-repo-scanner
description: Run the repository context scanner locally to map codebase languages, configurations, and check for secrets.
---

# Local Repository Scanner Skill

Use this skill to run the local scanning logic against a target repository or subdirectory path.

## Command

Execute the collection script:
```bash
python3 security-logging-advisor/skills/repository-context/scripts/collect-repository-context.py <target_directory>
```

Always ensure `<target_directory>` is passed. By default, use `.` for the current project.
