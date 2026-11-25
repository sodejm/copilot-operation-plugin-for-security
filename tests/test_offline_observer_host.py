from pathlib import Path

import pytest

from cops.evidence.canonical import digest
from cops.execution import offline_observer_host as observer


@pytest.mark.parametrize("changed", [None, "socket", "lineage", "namespace", "executable", "child_identity", "profile"])
def test_live_sample_requires_the_same_restricted_pinned_process(tmp_path, monkeypatch, changed):
    task = tmp_path / "42/task/42"
    task.mkdir(parents=True)
    (task / "children").write_text("43\n", encoding="ascii")
    child = tmp_path / "43"
    (child / "attr").mkdir(parents=True)
    (child / "ns").mkdir()
    (child / "attr/current").write_text("bwrap//&unpriv_bwrap (enforce)\n", encoding="ascii")
    (child / "ns/net").symlink_to("net:[101]")
    pinned = child / "exe"
    pinned.touch()
    inode = pinned.stat()
    monkeypatch.setattr(observer, "Path", lambda path: tmp_path if path == "/proc" else Path(path))

    lineage = [(42, (12, 100)), (12, (1, 90))]
    after = [(42, (12, 102)), lineage[-1]] if changed == "lineage" else lineage
    gate_identities = iter((lineage, after))
    monkeypatch.setattr(observer, "_worker_lineage", lambda *_: next(gate_identities))
    child_identity = (42, 101)
    process_identities = iter((child_identity, (42, 102) if changed == "child_identity" else child_identity))
    monkeypatch.setattr(observer, "_process_identity", lambda _: next(process_identities))
    approved_isolation = {
        "interfaces": ["lo"],
        "routes": [],
        "ipv6_routes": ["lo"],
        "socket_fds": 0,
        "separate_network_namespace": True,
    }

    def measure(_pid):
        if changed == "namespace":
            (child / "ns/net").unlink()
            (child / "ns/net").symlink_to("net:[102]")
        if changed == "executable":
            replacement = child / "replacement"
            replacement.touch()
            replacement.replace(pinned)
        if changed == "profile":
            (child / "attr/current").write_text("unconfined\n", encoding="ascii")
        return {**approved_isolation, "socket_fds": int(changed == "socket")}

    monkeypatch.setattr(observer.LinuxBubblewrapSandbox, "_measure_network_boundary", measure)
    release = {"gate": {"child_pid": 42}, "worker_pid": 12, "isolation_digest": digest(approved_isolation)}
    pin = "a" * 64
    sample = observer._sample_live_cat(release, lineage, "net:[101]", (inode.st_dev, inode.st_ino), pin)

    if changed:
        assert sample is None
    else:
        assert sample == {
            "schema_version": "cops.offline-observer-live-sample/v1",
            "release_sha256": digest(release),
            "observed_monotonic_ns": sample["observed_monotonic_ns"],
            "gate_pid": 42,
            "child_pid": 43,
            "child_start_ticks": 101,
            "executable_sha256": pin,
            "isolation": approved_isolation,
        }
