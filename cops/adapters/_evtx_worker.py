"""Fixed entrypoint for the optional EVTX parser; no content is executed."""

from __future__ import annotations

import importlib.metadata
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

PIN = "0.8.1"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_XML = 128 * 1024
MAX_OUTPUT = 2 * 1024 * 1024


def normalize(xml: str, record_id: int) -> dict:
    if len(xml.encode("utf-8")) > MAX_XML or "<!" in xml:
        raise ValueError("invalid_event_xml")
    root = ET.fromstring(xml)
    nodes = list(root.iter())
    if root.tag != NS + "Event" or len(nodes) > 256 or any(len(node.attrib) > 16 for node in nodes):
        raise ValueError("invalid_event_xml")
    systems, payloads = root.findall(NS + "System"), root.findall(NS + "EventData")
    if len(systems) > 1 or len(payloads) > 1:
        raise ValueError("duplicate_event_fields")
    if len(systems) != 1 or len(payloads) != 1:
        return {"record_id": record_id, "incomplete": "missing_event_fields"}
    system = systems[0]
    required = {name: system.findall(NS + name) for name in ("Provider", "EventID", "TimeCreated", "EventRecordID")}
    if any(len(items) > 1 for items in required.values()):
        raise ValueError("duplicate_event_fields")
    if any(len(items) != 1 for items in required.values()):
        return {"record_id": record_id, "incomplete": "missing_event_fields"}
    if required["Provider"][0].get("Name") != "Microsoft-Windows-Sysmon":
        return {"record_id": record_id, "incomplete": "unsupported_provider"}
    event_id = int(required["EventID"][0].text or "")
    if event_id not in {1, 3, 10}:
        return {"record_id": record_id, "incomplete": "unsupported_event_id"}
    if int(required["EventRecordID"][0].text or "") != record_id:
        raise ValueError("event_identity_mismatch")
    timestamp = required["TimeCreated"][0].get("SystemTime", "")
    stamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if stamp.tzinfo is None or stamp.utcoffset() != timezone.utc.utcoffset(stamp):
        raise ValueError("invalid_event_timestamp")
    fields = {}
    for node in payloads[0]:
        key = node.get("Name", "")
        if node.tag != NS + "Data" or not key or key in fields or list(node):
            raise ValueError("invalid_event_fields")
        fields[key] = node.text or ""
    needed = {1: {"Image", "CommandLine"}, 3: {"Image", "SourceIp", "DestinationIp"},
              10: {"SourceImage", "TargetImage", "GrantedAccess"}}[event_id]
    if not needed <= fields.keys() or any(not fields[key] for key in needed):
        return {"record_id": record_id, "incomplete": "missing_event_fields"}
    event = {"record_id": record_id, "event_id": event_id, "timestamp": stamp.isoformat().replace("+00:00", "Z")}
    source = fields.get("Image", fields.get("SourceImage", "")).replace("\\", "/").rsplit("/", 1)[-1].lower()
    event["image_family"] = {"powershell.exe": "powershell", "pwsh.exe": "powershell", "cmd.exe": "cmd",
                             "notepad.exe": "notepad", "lsass.exe": "lsass"}.get(source, "other")
    if event_id == 1:
        event["encoded_command"] = bool(re.search(r"(?i)(?:^|\s)[-/](?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?:\s|$)", fields["CommandLine"]))
    elif event_id == 3:
        if any("%" in fields[key] for key in ("SourceIp", "DestinationIp")):
            raise ValueError("scoped_address_unsupported")
        event["source_ip"] = str(ipaddress.ip_address(fields["SourceIp"]))
        event["destination_ip"] = str(ipaddress.ip_address(fields["DestinationIp"]))
    else:
        target = fields["TargetImage"].replace("\\", "/").rsplit("/", 1)[-1].lower()
        event["target_is_lsass"] = target == "lsass.exe"
        access = int(fields["GrantedAccess"], 16)
        if not 0 <= access <= 0xFFFFFFFF:
            raise ValueError("invalid_access_mask")
        event["process_read_access"] = bool(access & 0x10)
    return {"record_id": record_id, "event": event}


def run(path: str, max_records: int) -> dict:
    if sys.platform != "linux":
        return {"error": "unsupported_parser_platform"}
    try:
        import resource
        for limit, value in ((resource.RLIMIT_AS, 512 * 1024 * 1024), (resource.RLIMIT_CPU, 5),
                             (resource.RLIMIT_FSIZE, MAX_OUTPUT), (resource.RLIMIT_NOFILE, 64)):
            resource.setrlimit(limit, (value, value))
    except (ImportError, OSError, ValueError):
        return {"error": "resource_boundary_unavailable"}
    try:
        if importlib.metadata.version("python-evtx") != PIN or importlib.metadata.version("hexdump") != "3.3":
            return {"error": "parser_version_mismatch"}
        from Evtx.Evtx import Evtx
    except (ImportError, importlib.metadata.PackageNotFoundError):
        return {"error": "parser_unavailable"}
    rows = []
    try:
        with Evtx(path) as log:
            for record in log.records():
                if len(rows) >= max_records:
                    return {"error": "record_limit"}
                rows.append(normalize(record.xml(), record.record_num()))
        result = {"records": rows}
        if len(json.dumps(result)) > MAX_OUTPUT:
            return {"error": "parser_output_limit"}
        return result
    except Exception:
        # Parser diagnostics can contain source content. Only a fixed code leaves this process.
        return {"error": "invalid_event_data"}


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], int(sys.argv[2])), separators=(",", ":")))
