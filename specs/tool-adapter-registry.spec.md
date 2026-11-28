# Specification: Declarative Tool Adapter Registry

## Purpose
The Declarative Tool Adapter Registry provides typed, structured parameter validation and command assembly for tools executed by COPS isolated workers. It ensures security tools are invoked with deterministic arguments without arbitrary shell interpolation, prevents parameter injection attacks, and rejects directory climbing attempts.

## Architecture & Schema
Tool adapters are declared in standard JSON files located in `cops/adapters/definitions/`:
- `tool`: Binary/tool identity
- `version`: Version or pinned tag
- `binary`: Exact binary name to invoke
- `provenance`: Origin metadata
- `execution`: Per-launch executable verification contract:
  - `sha256`: Optional deployment-specific digest. Packaged adapters omit this
    value and workers fail closed until an operator supplies a platform pin.
  - `version_args`: Arguments used for a bounded version probe.
  - `version_pattern`: Regex with a `version` capture group matched against the
    probe output. The capture is compared with `provenance.pinned_revision`;
    `version` remains the logical adapter-contract version.
  - `max_size_bytes`: Maximum executable bytes copied and hashed.
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
4. **Verified Launch Identity**: Before each launch, the Linux worker opens the
   located executable without following a final symlink, copies and hashes it
   into an owner-only workspace, probes the version, and runs both the probe and
   approved action through one held descriptor under `/proc/self/fd`. Digest,
   version, or provenance mismatches fail closed. This binds pathname replacement
   attempts to the verified staged inode. The deployment must isolate the worker
   account because another process with the same UID can alter a regular staged
   inode in place.
5. **Bounded Collection and Evidence**: The worker bounds aggregate raw stdout
   and stderr while draining pipes. Timeout or overflow terminates the dedicated
   process group and produces a partial result. Evidence files are bounded,
   created through protected directory descriptors, and reject symlinks,
   existing paths, and workspace escapes.
6. **Supported Launch Platform**: Substitution-resistant adapter execution is
   supported on Linux hosts with `/proc/self/fd`, POSIX directory descriptors,
   `O_NOFOLLOW`, and process groups. Other hosts fail closed before invocation.
