---
name: repository-context
description: Scan and analyze repository structure to identify languages, frameworks, IaC, CI/CD pipelines, and credentials.
---

# Repository Context Collector Skill

This skill allows the agent to analyze a workspace or repository and gather critical architecture signals needed to customize security logging recommendations.

## Trigger Instructions

Run this skill during the initial stage of workspace analysis.

## Core Capabilities

1. **Deterministic Scan**: Invoke `scripts/collect-repository-context.py` to examine files in the workspace.
2. **Metadata Discovery**: Parse configuration manifests and package descriptors to identify:
   - Languages and frameworks (e.g., Node.js, Python, Go, Java)
   - Datastores (e.g., PostgreSQL, MongoDB, Redis)
   - Cloud providers (AWS, GCP, Azure) via IaC and configuration files
   - Identity & Authentication systems (JWT, OAuth, Keycloak, Auth0)
   - CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins)
3. **Data Classification**: Identify sensitive entrypoints, public endpoints, and data flows to map data zones.
4. **Secrets Detection**: Check for credential patterns (e.g., API keys, passwords, database URLs). Report locations for technology context, but **never** copy or display the secret value.

## Output Generation

Save the output of this scan as a JSON/markdown payload matching the schema defined in `assets/repository-context.md`.
