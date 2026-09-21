# Architectural Design Document: COPS Security Logging Advisor

This document explains the software architecture, data flows, components, and script configurations for the **COPS Security Logging Advisor** plugin.

---

## 1. Architectural Overview

The COPS Security Logging Advisor plugin is structured as an orchestratable agent package intended for integration with coding-assistant hosts, subject to version-specific discovery and tool support. The plugin separates declarative rules (manifests and markdown skills) from deterministic runtime logic (Python scripts).

```mermaid
graph TD
    subgraph Client [Client Environment]
        A[GitHub Copilot CLI / VS Code] -->|Interprets Manifest| B(plugin.json)
        A -->|Discovers Agent| C(@security-logging-advisor)
    end

    subgraph Agent [Agent & Skills Orchestration]
        C -->|Orchestrated by| D[security-logging-advisor.agent.md]
        D -->|Step 1: Scan Workspace| E[skills/repository-context]
        D -->|Step 2: Formulate Report| F[skills/logging-recommendations]
    end

    subgraph Scripts [Local Deterministic Scripts]
        E -->|Executes| G[collect-repository-context.py]
        G -->|Outputs JSON| H[Repository Context JSON]
        F -->|Merges Context & Templates| I[logging-recommendations.md]
    end

    subgraph Output [Report Deliverables]
        I -->|Generates Output| J[docs/security/logging-recommendations.md]
    end
    
    subgraph Packaging [CI/CD Validation]
        K[validate-plugin.py] -->|Verifies Structure| B
        K -->|Validates Skills| E
        K -->|Validates Skills| F
    end
```

---

## 2. Component Descriptions

### Manifests & Discovery Metadata

- **[plugin.json](../plugin.json)**: The core manifest defining the plugin identity, associated agents, capabilities, modular skills mapping, and file paths to executable scripts.
- **[GitHub marketplace index](../../../../.github/plugin/marketplace.json)**: Repository marketplace metadata; host registry acceptance requires separate verification.
- **[Claude marketplace index](../../../../.claude-plugin/marketplace.json)**: Configuration manifest supporting registration and discovery inside Claude-compatible plugin tools.

### Agents & Skills Orchestration

- **[security-logging-advisor.agent.md](../agents/security-logging-advisor.agent.md)**: Main instruction document defining the agent system persona, operational stages (Context Collection, Clarifying Questions, Gap Analysis, Report Generation), and security boundaries.
- **[repository-context SKILL.md](../skills/repository-context/SKILL.md)**: Details instruction guidelines for triggering and utilizing the scanning script to map languages, databases, cloud indicators, and pipelines.
- **[logging-recommendations SKILL.md](../skills/logging-recommendations/SKILL.md)**: Directs the agent on evaluating identified technologies against security matrices (OWASP logging guides, MITRE ATT&CK) using environment calibration rules (Sandbox to Production).

### Automation & Verification Scripts

- **[collect-repository-context.py](../skills/repository-context/scripts/collect-repository-context.py)**: Python scanner executing local static analysis of codebase directories to detect engineering footprints and search for potential secrets exposure.
- **[validate-plugin.py](../scripts/validate-plugin.py)**: Pre-release pipeline script ensuring integrity of JSON manifests, file structure requirements, and markdown frontmatter formatting.

---

## 3. Codebase Scripts & Variable Reference

This section documents the configuration variables, core regular expressions, and logical functionality embedded inside the codebase.

### A. Repository Context Collector (`collect-repository-context.py`)

#### Core Variables & Configurations

- **`IGNORE_DIRS` (Set)**: Defines the directories excluded from the recursive filesystem walk. This prevents scanning dependencies, local virtual environments, and generated artifacts to optimize performance and prevent token limit issues.

  ```python
  IGNORE_DIRS = {
      ".git", "node_modules", "venv", ".venv", "dist", "build", "target", 
      ".gemini", "__pycache__", ".pytest_cache", ".mypy_cache", ".idea"
  }
  ```

- **`SECRETS_PATTERNS` (Dict)**: Maps named credential classes to compiled regular expression objects. To safeguard secrets, the matches target patterns with high confidence:
  - **AWS Access Key ID**: Identifies standard `AKIA` prefixes followed by 16 alphanumeric characters.
  - **Generic Secret / Password Assignment**: Matches standard config keys (like `password`, `api-key`, `private-key`, `auth-token`) assigned to string values of 8+ characters.
  - **Private Key Header**: Searches for PEM block headers (`-----BEGIN ... PRIVATE KEY-----`).
  - **Database Connection String**: Detects database protocols (`mongodb`, `postgres`, `mysql`, `redis`) containing embedded username/password strings.

#### Functionality

1. **`is_ignored(path, root_dir)`**: Evaluates relative components of a given directory traversal path. Returns `True` if any component matches a folder in `IGNORE_DIRS`.
2. **`scan_repository(root_dir)`**: Walks the codebase directories. It compiles statistics about file extensions (mapping them to programming languages) and scans content patterns in package manifests (`package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`) to identify dependencies.
3. **Secrets Detection Logic**: For text file formats (e.g. `.json`, `.yaml`, `.py`, `.ts`, `.env`), it reads lines sequentially, running matches against `SECRETS_PATTERNS`. When a match is detected, it logs only the **filepath**, **line number**, and **issue type**. The script **never stores or outputs the matched secret string** to maintain enterprise security integrity.

---

### B. Plugin Schema and Structure Validator (`validate-plugin.py`)

#### Core Variables & Configurations

- **`REQUIRED_STATIC_FILES` (List)**: Exhaustive list of target file paths required to make up a complete, compliant plugin package:

  ```python
  REQUIRED_STATIC_FILES = [
      "plugins/logging-telemetry/security-logging-advisor/plugin.json",
      "plugins/logging-telemetry/security-logging-advisor/agents/security-logging-advisor.agent.md",
      ...
  ]
  ```

#### Functionality

1. **`check_json_file(file_path, required_keys)`**: Opens a target file, verifies it parses as syntactically valid JSON, and confirms all keys in `required_keys` exist. This is run against `plugin.json` and the `marketplace.json` discovery files.
2. **`check_skill_markdown(file_path)`**: Uses regular expressions to extract and parse the frontmatter section (delimited by standard `---` YAML boundaries) from `SKILL.md` files. It verifies that both `name` and `description` are declared, which is crucial for trigger matching by the Copilot orchestration engine.

For the contributor foundation, see [COPS architecture](../../../../ARCHITECTURE.md).
Local validation does not certify host integration; see [installation](INSTALL.md).
