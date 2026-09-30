---
name: entra-identity-analysis
description: Model and review Entra ID and AI Agent identity graphs, privilege boundaries, and exposure paths offline. Use when analyzing users, groups, service principals, managed identities, agent blueprints, or Entra Agent IDs for privilege escalation, consent risks, and entitlement boundaries.
---

# Entra Identity & Agent Exposure Analysis

Use this skill to model and audit identity relationships, privilege boundaries, and AI agent entitlements from offline Microsoft Graph and Azure RBAC exports.

## Core Workflow

1. **Verify Export Manifest & Boundaries**:
   - Inspect the target tenant manifest (`manifest.json`) declaring snapshot timestamp, tenant ID, and relative JSON export paths.
   - Confirm each export file matches its declared SHA-256 checksum.
   - Verify that data stays strictly bounded to the authorized tenant; never evaluate cross-tenant relationships as trusted unless explicitly configured as a verified multi-tenant trust.

2. **Build Typed Identity Graph**:
   - Run the local graph builder to construct typed nodes (`user`, `group`, `service_principal`, `managed_identity`, `agent_blueprint`, `agent_identity`, `resource`) and directed edges.
   - Never infer an identity type solely from a display name; identity types must strictly derive from validated export schemas.
   - Distinguish:
     - **Delegated / OBO access** (requires user context and consent) versus **Autonomous Application access** (admin-consented app roles).
     - **Direct role assignments** versus **Inherited group/management group assignments**.
     - **Active PIM role assignments** versus **Eligible PIM states**.
     - **Agent Blueprint definition** (tools and declarative template) versus **Instantiated Agent ID** (acting runtime principal).

3. **Evaluate Exposure & Privilege Hypotheses**:
   - **Broad App Consent**: High-privilege Graph permissions granted to applications or multi-tenant apps.
   - **Ownerless Principals**: Applications or service principals lacking registered human owners.
   - **Stale / Wildcard Federated Credentials**: Workload identity federations with wildcard subjects or unconstrained trust.
   - **Privileged Managed Identities**: System or user-assigned identities holding Contributor, Owner, or directory administrator roles.
   - **Agent-to-Resource Mismatch**: Discrepancies between an agent's intended tool access and its actual granted cloud role entitlements.
   - **Cross-Tenant Escalation**: Unvetted foreign guests or multi-tenant service principals with standing directory privileges.

4. **Review and Export**:
   - Generate human-readable Markdown reports detailing supporting edges and missing evidence for each hypothesis.
   - Where evidence is partial or timestamps differ, classify paths as *unknown* rather than asserting complete safety.
   - Export content-addressed JSON snapshots for downstream review or ingestion into the Attack Path Workbench.

## Operational Boundaries

- **Read-Only Analysis**: This skill operates exclusively on offline export files. It makes zero live network calls to Microsoft Graph or Azure Resource Manager.
- **Privacy & Redaction**: Tenant IDs and principal IDs are normalized; never expose raw credentials, certificates, or client secrets in prompts or generated reports.
