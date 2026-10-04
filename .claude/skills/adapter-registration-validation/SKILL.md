---
name: adapter-registration-validation
description: Register, validate, and assemble structured tool adapters without shell command interpolation.
---

# Adapter registration validation

Manage and validate declarative tool adapters (`cops/adapters/`) for deterministic argument assembly.

## Core Responsibilities

1. **No Arbitrary Shell Command Interpolation**:
   - Commands are constructed strictly via argument arrays (`list[str]`).
   - Metacharacters (`;`, `&`, `|`, `` ` ``, `$`) and directory traversal sequences (`..`, `/etc`) are strictly blocked.
2. **Strict Parameter Validation**:
   - Typed parameter validation (`integer`, `boolean`, `enum`, `string` with regex constraints).
   - Flag injection prevention.

## Python API

```python
from cops.adapters import ToolAdapterRegistry, AdapterInjectionError

# 1. Initialize registry
registry = ToolAdapterRegistry()

# 2. Get adapter
nmap = registry.get_adapter("nmap")

# 3. Assemble command
cmd = nmap.assemble_command("port_scan", {"target": "10.0.0.5", "ports": "80,443"})
# Returns: ['nmap', '-sT', '-Pn', '--max-retries', '1', '-p', '80,443', '-T', '3', '10.0.0.5']
```
