# Specification: COPS Security Logging Advisor Plugin

This document outlines the requirements, user stories, and acceptance criteria for the **COPS Security Logging Advisor** plugin. It serves as the single source of truth for the plugin's features and technical scope.

---

## 1. Goal & Intent

Provide software development teams with an automated, cost-conscious, and security-first advisor that audits a codebase's framework footprint and generates direct, actionable recommendations to improve security audit logging posture.

---

## 2. User Stories

- **As a Developer**, I want to scan my repository so that I know what logging packages and configurations are missing or insecure.
- **As a Security Engineer**, I want the advisor to verify that logging statements include critical fields (correlation IDs, timestamps, actor references) without writing sensitive variables to logs.
- **As a Platform Administrator**, I want to deploy this tool organization-wide and ensure developers have cost-aware settings that prevent budget overflows in our SIEM ingestion.

---

## 3. Functional Requirements

### A. Repository Context Scanning

- **Supported Languages**: Auto-detect files and analyze code patterns for:
  - TypeScript / JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`)
  - Python (`.py`)
  - Go (`.go`)
  - Java (`.java`, `pom.xml`, `build.gradle`)
  - HashiCorp Configuration Language / HCL (`.tf`, `.tfvars`)
  - Bicep (`.bicep`)
  - PowerShell (`.ps1`, `.psm1`)
  - Shell Script / Bash (`.sh`)
  - Perl (`.pl`, `.pm`)
  - C# / .NET / dotnet (`.cs`, `.csproj`, `.sln`)
  - C/C++ (`.c`, `.cpp`, `.h`, `.hpp`)
  - Rust (`.rs`)
  - Ruby (`.rb`, `Gemfile`)
  - PHP (`.php`, `composer.json`)
  - Swift (`.swift`)
  - Kotlin (`.kt`)
  - Scala (`.scala`)
- **Supported Cloud & IaC Detections**: Scan configuration, packages, and infra files to identify:
  - **AWS**: Amazon Web Services (via HCL, Docker base, BICEP, ARM, or NPM/pip dependencies)
  - **GCP**: Google Cloud Platform (via HCL, NPM/pip dependencies)
  - **Azure**: Microsoft Azure (via Bicep, ARM templates, HCL, or dependencies)
  - **Oracle Cloud**: Oracle Cloud Infrastructure / OCI (via HCL, NPM/pip dependencies)
- **IaC & Containers**: Detect Docker, Kubernetes, Helm, and Terraform indicators.
- **Data Zones**: Map databases (Redis, Postgres, Mongo) and authentication providers.
- **Secrets Audit**: Scan config files for credentials, reporting their file and line locations while strictly redacting/hiding the credential values.

### B. Logging Recommendation System

- **Tiered Telemetry**: Recommend distinct tiers for Sandbox (low budget, minimal logs), Development (debug support), and Production (structured format, SIEM ingestion).
- **Format Advice**: Direct the implementation of structured JSON logs with correlation IDs.
- **Alerting Guidance**: Suggest triage rules and alarm criteria for high-priority security failures.

### C. Plugin & Skill Validation

- Verify JSON formatting of the portable manifest (`plugin.json`), host manifest, canonical catalog, and marketplace indexes.
- Ensure all required docs, example templates, scripts, and the slash command definition (`commands/security-logging-advisor.md`) are present in the package before release.
- Validate that all skill files (`SKILL.md`) strictly adhere to the **Agent Skills standard** ([agentskills.io](https://agentskills.io)) to ensure compatibility, specifically verifying naming conventions, frontmatter fields (YAML), and the nested directory layout.

---

## 4. Technical Constraints & Security Boundaries

- **Local Boundary**: Scanning logic runs locally without network calls. Agent-assisted processing must respect the approved host/provider data boundary; review context before sharing.
- **License Compliance**: Preserve the **PolyForm Noncommercial License 1.0.0** project terms and the separate notices for imported PARK foundation material.
- **Zero-Dependency Core**: Validation and scanning scripts must run using standard libraries in Python 3.
- **Circuit Breakers**: The scanner must not crash on massive repositories or single large log files. It will skip files over 1MB and stop scanning after 10,000 files to conserve memory.

## 5. Model Selection & Runtime Environment Guidelines

The local scanner and validator require no model. Agent-assisted synthesis uses
the host's approved, currently available model and tool permissions, with model
choice based on task complexity and cost. Do not pin an unverified model in the
command definition. Document host-specific discovery boundaries and record
integration evidence separately from static validation. See the portable model
guidance scenario in `specs/features/repository_conformance.feature`.

---

## 6. Acceptance Criteria

- [ ] Running `validate-plugin.py` returns code `0` on compliant packages.
- [ ] All `SKILL.md` files pass parsing and verification against the Agent Skills (agentskills.io) frontmatter specification.
- [ ] Running `skills/repository-context/scripts/collect-repository-context.py` yields a complete JSON map of the codebase without listing any hardcoded credential values.
- [ ] The generated report matches the fields laid out in the recommendations markdown template.
- [ ] The repository contains comprehensive documentation on model selection and runtime routing guidelines.
- [ ] The package contains valid portable and host manifests plus the command definitions in `commands/` and `com.github.copilot/commands/`.

## CVE reachability extension

The optional agent-assisted workflow is specified in [cve-reachability.spec.md](cve-reachability.spec.md). Its helper checks evidence integrity and report structure, not vulnerability truth.
