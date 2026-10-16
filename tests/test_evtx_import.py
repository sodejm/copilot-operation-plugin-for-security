"""Binary fixture correction and hostile-input tests for the optional adapter."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from cops.adapters.evtx import EvtxImportError, import_evtx, validate_evtx
from cops.adapters import _evtx_worker, evtx

FIXTURES = Path(__file__).resolve().parents[1] / "cops/laboratory/service_fixtures"


def fixture(name: str) -> tuple[Path, str]:
    path = FIXTURES / f"sysmon-{name}.evtx"
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def require_parser() -> None:
    if sys.platform != "linux":
        pytest.skip("bounded binary parsing requires the isolated Linux runtime")
    pytest.importorskip("Evtx")
    if importlib.metadata.version("python-evtx") != "0.8.1":
        pytest.skip("requires the registered optional parser version")


@pytest.mark.parametrize("name,events", [("vulnerable", 2), ("corrected", 2), ("insufficient", 1)])
def test_binary_fixtures_have_complete_framing(name, events):
    path, _ = fixture(name)
    assert path.read_bytes().startswith(b"ElfFile\0")
    assert len(validate_evtx(path.read_bytes())) == events


def test_binary_correction_and_provenance():
    require_parser()
    results = {}
    for name in ("vulnerable", "corrected", "insufficient"):
        path, digest = fixture(name)
        result = import_evtx(path, expected_sha256=digest)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert result["source_sha256"] == digest
        assert result["records_total"] == result["records_normalized"] + result["records_incomplete"]
        assert result["adapter"] == "sysmon-evtx/v1"
        assert result["parser"] == "python-evtx==0.8.1"
        serialized = json.dumps(result)
        for secret in ("SYNTHETIC_SECRET", "CommandLine", "lab-user", "C:\\\\"):
            assert secret not in serialized
        assert all(event["evidence_ref"].startswith(f"evtx:sha256:{digest}:") for event in result["events"])
        results[name] = result
    assert results["vulnerable"]["status"] == results["corrected"]["status"] == "imported"
    assert results["vulnerable"]["indicator_counts"]["powershell_network"] == 1
    assert results["vulnerable"]["indicator_counts"]["encoded_command"] == 1
    assert results["corrected"]["indicator_counts"] == {"powershell_network": 0, "encoded_command": 0}
    assert results["insufficient"]["status"] == "partial"
    assert results["insufficient"]["coverage_status"] == "indeterminate"
    assert results["insufficient"]["events"] == []


def test_integrity_and_budgets_before_parser(tmp_path, monkeypatch):
    import cops.adapters.evtx as adapter

    monkeypatch.setattr(adapter, "_parse_snapshot", lambda *a, **k: pytest.fail("parser must not start"))
    path, digest = fixture("vulnerable")
    with pytest.raises(EvtxImportError, match="source_hash_mismatch"):
        import_evtx(path, expected_sha256="0" * 64)
    with pytest.raises(EvtxImportError, match="input_size_limit"):
        import_evtx(path, expected_sha256=digest, max_bytes=1024)
    with pytest.raises(EvtxImportError, match="record_limit"):
        import_evtx(path, expected_sha256=digest, max_records=1)
    modified = bytearray(path.read_bytes())
    modified[5000] ^= 1
    bad = tmp_path / "bad.evtx"
    bad.write_bytes(modified)
    with pytest.raises(EvtxImportError, match="chunk_data_checksum"):
        import_evtx(bad, expected_sha256=hashlib.sha256(modified).hexdigest())
    link = tmp_path / "linked.evtx"
    link.symlink_to(path)
    with pytest.raises(EvtxImportError, match="source_not_regular"):
        import_evtx(link, expected_sha256=digest)


@pytest.mark.parametrize("change", ["truncated", "header_crc", "record_size", "record_count", "dirty", "wrapped"])
def test_malformed_framing(change):
    raw = bytearray(fixture("vulnerable")[0].read_bytes())
    if change == "truncated":
        del raw[-1]
    elif change == "header_crc":
        raw[124] ^= 1
    elif change in {"record_size", "record_count"}:
        if change == "record_size":
            struct.pack_into("<I", raw, 4096 + 512 + 4, 0)
        else:
            struct.pack_into("<Q", raw, 4096 + 16, 9)
        end = struct.unpack_from("<I", raw, 4096 + 48)[0]
        struct.pack_into("<I", raw, 4096 + 52, zlib.crc32(raw[4096 + 512:4096 + end]))
        struct.pack_into("<I", raw, 4096 + 124, zlib.crc32(raw[4096:4096 + 120] + raw[4096 + 128:4096 + 512]))
    else:
        struct.pack_into("<I" if change == "dirty" else "<Q", raw, 120 if change == "dirty" else 8, 1)
        struct.pack_into("<I", raw, 124, zlib.crc32(raw[:120]))
    with pytest.raises(EvtxImportError):
        validate_evtx(bytes(raw))


@pytest.mark.parametrize("budget", [True, 0, -1, 4097])
def test_invalid_record_budget(budget):
    path, digest = fixture("vulnerable")
    with pytest.raises(EvtxImportError, match="invalid_budget"):
        import_evtx(path, expected_sha256=digest, max_records=budget)


def event_xml(*, provider="Microsoft-Windows-Sysmon", event_id=1, fields=None):
    from xml.sax.saxutils import escape
    if fields is None:
        fields = {"Image": r"C:\private\powershell.exe", "CommandLine": "powershell -enc PRIVATE_VALUE"}
    data = "".join(f'<Data Name="{escape(key)}">{escape(value)}</Data>' for key, value in fields.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            '<EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-10-15T12:00:00Z"/>'
            f'</System><EventData>{data}</EventData></Event>')


def test_normalization_omits_source_secrets_and_does_not_execute_content(tmp_path):
    marker = tmp_path / "must-not-exist"
    result = _evtx_worker.normalize(event_xml(fields={"Image": "powershell.exe", "CommandLine": f"-enc PRIVATE_VALUE; touch {marker}"}), 1)
    assert result["event"]["encoded_command"] is True
    assert result["event"]["image_family"] == "powershell"
    assert "PRIVATE_VALUE" not in json.dumps(result)
    assert str(marker) not in json.dumps(result)
    assert not marker.exists()


@pytest.mark.parametrize("options,reason", [
    ({"provider": "Unknown"}, "unsupported_provider"),
    ({"event_id": 42}, "unsupported_event_id"),
    ({"fields": {"Image": "powershell.exe"}}, "missing_event_fields"),
])
def test_unsupported_and_missing_records_remain_incomplete(options, reason):
    assert _evtx_worker.normalize(event_xml(**options), 1) == {"record_id": 1, "incomplete": reason}


@pytest.mark.parametrize("mutation", [
    lambda xml: '<!DOCTYPE Event [<!ENTITY x "private">]>' + xml,
    lambda xml: xml.replace("<EventID>1</EventID>", "<EventID>1</EventID><EventID>1</EventID>"),
    lambda xml: xml.replace("</EventData>", '<Data Name="Image">cmd.exe</Data></EventData>'),
    lambda xml: xml.replace("<EventRecordID>1", "<EventRecordID>2"),
    lambda xml: xml.replace("12:00:00Z", "12:00:00"),
    lambda xml: xml.replace("PRIVATE_VALUE", "x" * _evtx_worker.MAX_XML),
])
def test_hostile_xml_is_rejected(mutation):
    with pytest.raises(ValueError):
        _evtx_worker.normalize(mutation(event_xml()), 1)


def test_process_access_and_ipv6_are_typed():
    access = _evtx_worker.normalize(event_xml(event_id=10, fields={
        "SourceImage": "unknown.exe", "TargetImage": r"C:\Windows\lsass.exe", "GrantedAccess": "0x1010",
    }), 1)["event"]
    assert access["target_is_lsass"] and access["process_read_access"]
    network = _evtx_worker.normalize(event_xml(event_id=3, fields={
        "Image": "pwsh.exe", "SourceIp": "2001:db8::1", "DestinationIp": "2001:0db8::2",
    }), 1)["event"]
    assert network["destination_ip"] == "2001:db8::2"
    with pytest.raises(ValueError):
        _evtx_worker.normalize(event_xml(event_id=3, fields={
            "Image": "pwsh.exe", "SourceIp": "fe80::1%eth0", "DestinationIp": "::1",
        }), 1)


def test_deadline_cleans_private_snapshot_and_preserves_original(monkeypatch):
    directories = []
    path, digest = fixture("vulnerable")
    def timeout(argv, **kwargs):
        directories.append(Path(kwargs["cwd"]))
        assert Path(argv[3]).read_bytes() == path.read_bytes()
        assert kwargs["env"] == {} and kwargs["stderr"] == subprocess.DEVNULL
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    monkeypatch.setattr(evtx.subprocess, "run", timeout)
    with pytest.raises(EvtxImportError, match="parser_deadline"):
        import_evtx(path, expected_sha256=digest, deadline=0.1)
    assert directories and all(not directory.exists() for directory in directories)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("error", ["parser_unavailable", "parser_version_mismatch", "unsupported_parser_platform", "PRIVATE_VALUE"])
def test_parser_errors_are_fixed_and_redacted(monkeypatch, error):
    def failed(argv, **kwargs):
        kwargs["stdout"].write(json.dumps({"error": error}).encode())
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(evtx.subprocess, "run", failed)
    path, digest = fixture("vulnerable")
    with pytest.raises(EvtxImportError) as exc:
        import_evtx(path, expected_sha256=digest)
    assert str(exc.value) == ("parser_failed" if error == "PRIVATE_VALUE" else error)


@pytest.mark.parametrize("rows", [
    [], [{"record_id": 2, "incomplete": "missing_event_fields"}],
    [{"record_id": 1, "incomplete": "PRIVATE_VALUE"}],
    [{"record_id": 1, "event": {"CommandLine": "PRIVATE_VALUE"}}],
])
def test_parser_output_tampering_is_rejected(monkeypatch, rows):
    monkeypatch.setattr(evtx, "_parse_snapshot", lambda *args: {"records": rows})
    path, digest = fixture("insufficient")
    with pytest.raises(EvtxImportError):
        import_evtx(path, expected_sha256=digest)


def test_binary_fixtures_are_reproducible():
    from scripts.build_evtx_fixtures import fixtures
    for name, expected in fixtures().items():
        assert (FIXTURES / name).read_bytes() == expected


def test_cli_dispatches_to_registered_importer(monkeypatch, capsys):
    from cops.cli import main
    calls = []
    def imported(path, **kwargs):
        calls.append((path, kwargs))
        return {"schema_version": "cops.evtx-import/v1", "status": "partial"}
    monkeypatch.setattr(evtx, "import_evtx", imported)
    path, digest = fixture("insufficient")
    assert main(["telemetry", "import-evtx", "--input", str(path), "--sha256", digest]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "partial"
    assert calls[0][0] == path and calls[0][1]["expected_sha256"] == digest
