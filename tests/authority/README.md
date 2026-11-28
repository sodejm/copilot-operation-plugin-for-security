# Approval fixture ownership

Approval tests have three roles. Keep their account privileges separate:

| Role | Owns and may create | Must not do |
| --- | --- | --- |
| Disposable-VM provisioner | Accounts and directories, including the authority-owned SGID control directory | Run the worker with provisioning privileges |
| Approval authority | Private signing material, trust store, approval database and authority socket | Give the worker access to its private state |
| Restricted worker | Its own private workspace and requests to the consume-only socket | Create SGID state, mutate the control directory, or read authority keys/database |

`test_approval_listener.py` owns the positive SGID listener fixture. Run it as
the separate authority-capable test account, outside the restricted worker unit.
It retains the real socket type/mode, non-inheritance and removal assertions.
The negative control-directory and protocol tests remain in the worker suite.
In-process tests use synthetic authority identities; they cannot prove kernel
account separation. `auth_testkit.make_test_approval_authority` centralizes their
signed, persisted approval setup without granting production authority.

In a disposable systemd Linux VM, provision locked, distinct `cops-worker` and
`cops-approval` accounts first. Bind `PYTHONPATH` and the working directory to the
same source revision and use the prepared repository interpreter as `PYTHON`.
Run the following test arguments in their respective service units:

```sh
# Restricted worker unit, retaining RestrictSUIDSGID=yes and its other controls:
"$PYTHON" -m pytest -o addopts= -p no:cacheprovider -q -ra tests/test_offline_research.py tests/test_approval_control_boundary.py tests/step_defs/test_offline_research_execution_steps.py
"$PYTHON" -m pytest -o addopts= -p no:cacheprovider -q -ra tests/integration/test_linux_bubblewrap_sandbox.py tests/integration/test_offline_sandbox_gate.py
# Separate authority account, with writes limited to its own state:
"$PYTHON" -m pytest -o addopts= -p no:cacheprovider -q -ra tests/authority/test_approval_listener.py
```

For a real cross-account check, run the provisioner from that source directory:

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m tests.authority.check_role_separation
```

This Linux-only acceptance probe requires root, systemd and the two existing
accounts; it installs neither accounts nor a production supervisor. It creates
temporary authority state and starts a worker transient unit with
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
`NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, inaccessible host mounts/Docker
socket, and writes limited to the worker home. It records the effective unit
properties, invocation identity and actual process UID/GID. An independent
authority process creates fresh signing material and a persisted approval.
The probe requires denial of worker SGID creation and private-state/control
mutation, rejection of wrong PID/plan/identity and replay, exactly one valid
consumption, non-inheritable sockets, socket removal and fixture cleanup.
Failures exit nonzero; unsupported environments are not reported as skips.
Retain the JSON output with the tested source revision and runtime evidence.

Run `make check` and `make check-docs` in a separate writable Git checkout under
the test account, which can create authority fixtures. Do not relax the worker
unit to run the full repository suite. Report unrelated platform skips explicitly.
These checks establish disposable Linux fixture separation, not installed
supervision, production observation or other-platform readiness. See the
[acceptance record](../../docs/EXPANSION_ACCEPTANCE.md) for tested revisions.
