# Specification: Declarative Tool Adapter Registry

## Purpose
The Declarative Tool Adapter Registry provides typed, structured parameter validation and command assembly for tools executed by COPS isolated workers. It ensures security tools are invoked with deterministic arguments without arbitrary shell interpolation, prevents parameter injection attacks, and rejects directory climbing attempts.

## Architecture & Schema
Tool adapters are declared in standard JSON files located in `cops/adapters/definitions/`:
- `tool`: Binary/tool identity
- `version`: Version or pinned tag
- `binary`: Exact binary name to invoke
- `provenance`: Origin metadata
- `supported_environments`: Target OS list (e.g. `linux`, `darwin`)
- `actions`: Map of named actions defining:
  - `description`: Action summary
  - `base_args`: Invariant base flags/arguments (e.g. `["-sS"]` for SYN scan)
  - `parameters`: Typed argument definitions with:
    - `type`: `string`, `integer`, `boolean`, `enum`, `ip`, `cidr`
    - `flag`: Flag token preceding value if applicable (e.g. `-p`)
    - `required`: Boolean indicating requirement
    - `default`: Default value if omitted
    - `allowed_values`: Allowlist of string options for enum types
    - `regex_pattern`: Strict regex validation pattern

## Security Boundaries
1. **Shell Injection Prevention**: Metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`, `\r`) in parameter values are rejected immediately with `AdapterInjectionError`.
2. **Directory Traversal Guard**: Values containing path climb markers (`..`), root paths (`/etc`), or home expansion (`~`) raise `AdapterInjectionError`.
3. **No Shell Interpolation**: All execution commands are assembled as argument lists (`list[str]`) passed directly to OS `exec`-family APIs without shell wrappers (`shell=False`).
