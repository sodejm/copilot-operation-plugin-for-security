"""Unit tests for declarative tool adapter registry."""

import pytest

from cops.adapters import (
    AdapterError,
    AdapterInjectionError,
    AdapterParameterError,
    ToolAdapterRegistry,
)


@pytest.fixture(autouse=True)
def _linux_adapter_environment(monkeypatch):
    """Exercise built-in definitions in their declared execution environment."""
    monkeypatch.setattr("cops.adapters.registry.sys.platform", "linux")


def test_registry_lists_default_tools():
    registry = ToolAdapterRegistry()
    tools = registry.list_tools()
    assert "echo" in tools
    assert "nmap" in tools


def test_echo_adapter_valid_command():
    registry = ToolAdapterRegistry()
    echo = registry.get_adapter("echo")
    cmd = echo.assemble_command("print_status", {"message": "hello world"})
    assert cmd == ["echo", "hello world"]


def test_echo_adapter_rejects_injection():
    registry = ToolAdapterRegistry()
    echo = registry.get_adapter("echo")
    with pytest.raises(AdapterInjectionError, match="Shell metacharacters detected"):
        echo.assemble_command("print_status", {"message": "hello; rm -rf /"})


def test_echo_adapter_rejects_path_traversal():
    registry = ToolAdapterRegistry()
    echo = registry.get_adapter("echo")
    with pytest.raises(AdapterInjectionError, match="Directory climbing or path traversal"):
        echo.assemble_command("print_status", {"message": "../etc/passwd"})


def test_nmap_adapter_assembly():
    registry = ToolAdapterRegistry()
    nmap = registry.get_adapter("nmap")
    cmd = nmap.assemble_command("port_scan", {
        "target": "192.168.1.1",
        "ports": "80,443",
        "timing": 3,
    })
    assert cmd == ["nmap", "-sT", "-Pn", "--max-retries", "1", "-p", "80,443", "-T", "3", "192.168.1.1"]


def test_nmap_adapter_rejects_invalid_port_syntax():
    registry = ToolAdapterRegistry()
    nmap = registry.get_adapter("nmap")
    with pytest.raises(AdapterParameterError, match="does not match regex pattern"):
        nmap.assemble_command("port_scan", {
            "target": "10.0.0.1",
            "ports": "80abc",
        })


def test_nmap_adapter_rejects_invalid_timing():
    registry = ToolAdapterRegistry()
    nmap = registry.get_adapter("nmap")
    with pytest.raises(AdapterParameterError, match="must be an integer"):
        nmap.assemble_command("port_scan", {
            "target": "10.0.0.1",
            "timing": "invalid",
        })


def test_nmap_adapter_missing_required():
    registry = ToolAdapterRegistry()
    nmap = registry.get_adapter("nmap")
    with pytest.raises(AdapterParameterError, match="Missing required parameter 'target'"):
        nmap.assemble_command("port_scan", {})


def test_adapter_unknown_action():
    registry = ToolAdapterRegistry()
    echo = registry.get_adapter("echo")
    with pytest.raises(AdapterError, match="Action 'unknown' is not supported"):
        echo.assemble_command("unknown", {})


def test_adapter_unknown_parameter():
    registry = ToolAdapterRegistry()
    echo = registry.get_adapter("echo")
    with pytest.raises(AdapterParameterError, match="Unknown parameters"):
        echo.assemble_command("print_status", {"message": "hi", "extra": "forbidden"})
