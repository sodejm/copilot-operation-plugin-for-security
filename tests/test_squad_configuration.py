"""Keep the Squad state server's launch contract consistent across clients."""

import json
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["npx", "--ignore-scripts", "-y", "@bradygaster/squad-cli@2.0.0", "state-mcp"]


@pytest.mark.parametrize("config", [".mcp.json", ".copilot/mcp-config.json", ".cursor/mcp.json", ".kiro/settings/mcp.json"])
def test_mcp_client_launch(config):
    server = json.loads((ROOT / config).read_text())["mcpServers"]["squad_state"]
    assert [server["command"], *server["args"]] == COMMAND


def test_codex_launch():
    with (ROOT / ".codex/config.toml").open("rb") as config:
        server = tomllib.load(config)["mcp_servers"]["squad_state"]
    assert [server["command"], *server["args"]] == COMMAND


def test_opencode_launch():
    server = json.loads((ROOT / "opencode.json").read_text())["mcp"]["squad_state"]
    assert server["enabled"] and server["type"] == "local"
    assert server["command"] == COMMAND
