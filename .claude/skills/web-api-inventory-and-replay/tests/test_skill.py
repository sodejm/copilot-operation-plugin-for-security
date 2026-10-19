"""Tests for web-api-inventory-and-replay contributor skill."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cops.web_api.cli import command_web_api
from cops.web_api.importer import import_openapi, import_raw_http
from cops.web_api.models import ApiInventory, ReplayBudget, ReplayRequest
from cops.web_api.replay import DestinationGuard, OfflineSyntheticReplayer, execute_replay_session


class TestWebApiInventoryAndReplaySkill(unittest.TestCase):
    """Test suite for web-api-inventory-and-replay contributor skill."""

    def test_skill_definition_exists_and_valid(self) -> None:
        skill_file = ROOT / ".agents" / "skills" / "web-api-inventory-and-replay" / "SKILL.md"
        self.assertTrue(skill_file.is_file(), f"Skill file missing at {skill_file}")
        content = skill_file.read_text(encoding="utf-8")
        self.assertTrue(content.startswith("---\nname: web-api-inventory-and-replay\n"))
        self.assertIn("description:", content)
        self.assertIn("# Web API Inventory and Request Replay", content)

    def test_cli_inventory_import_openapi(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Accounts API", "version": "1.0.0"},
            "servers": [{"url": "https://accounts.internal/api"}],
            "paths": {
                "/balance": {
                    "get": {
                        "summary": "Get account balance",
                        "parameters": [{"name": "auth_token", "in": "header"}],
                        "responses": {"200": {"description": "Balance retrieved"}},
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_file = Path(tmpdir) / "spec.json"
            spec_file.write_text(json.dumps(spec), encoding="utf-8")
            out_file = Path(tmpdir) / "inventory.json"

            args = argparse.Namespace(
                web_api_command="inventory",
                openapi=[str(spec_file)],
                har=[],
                postman=[],
                raw=[],
                name="Accounts Inventory",
                source_id="TEST-SRC-01",
                output=str(out_file),
                json=False,
            )
            rc = command_web_api(args, root=ROOT)
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.is_file())

            inv = ApiInventory.load(out_file)
            self.assertEqual(len(inv.endpoints), 1)
            self.assertIn("accounts.internal", inv.target_hosts)
            self.assertTrue(inv.credentials_redacted)

    def test_cli_inventory_import_raw_http(self) -> None:
        raw_req = (
            "POST /graphql HTTP/1.1\r\n"
            "Host: graphql.internal\r\n"
            "Authorization: Bearer secret-auth-token-999\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"query": "{ me { id name } }"}'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_file = Path(tmpdir) / "request.http"
            raw_file.write_text(raw_req, encoding="utf-8")
            out_file = Path(tmpdir) / "inventory_raw.json"

            args = argparse.Namespace(
                web_api_command="inventory",
                openapi=[],
                har=[],
                postman=[],
                raw=[str(raw_file)],
                name="GraphQL Raw Request",
                source_id="RAW-01",
                output=str(out_file),
                json=False,
            )
            rc = command_web_api(args, root=ROOT)
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.is_file())

            inv = ApiInventory.load(out_file)
            self.assertEqual(len(inv.endpoints), 1)
            self.assertEqual(inv.endpoints[0].method, "POST")
            self.assertNotIn("secret-auth-token-999", str(inv.endpoints[0].headers_schema))

    def test_cli_replay_bounded_offline(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Users Service", "version": "1.0"},
            "servers": [{"url": "https://users.internal/v1"}],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            inv_file = Path(tmpdir) / "inv.json"
            rep_file = Path(tmpdir) / "replay.json"

            inv = import_openapi(spec)
            inv.save(inv_file)

            args = argparse.Namespace(
                web_api_command="replay",
                inventory=str(inv_file),
                allow_destination=["users.internal"],
                max_requests=10,
                rate_limit=10.0,
                timeout=5.0,
                max_redirects=3,
                max_frames=10,
                mode="offline",
                output=str(rep_file),
                json=False,
            )
            rc = command_web_api(args, root=ROOT)
            self.assertEqual(rc, 0)
            self.assertTrue(rep_file.is_file())

            data = json.loads(rep_file.read_text(encoding="utf-8"))
            self.assertEqual(data["total_dispatched"], 1)
            self.assertEqual(data["total_successful"], 1)
            self.assertEqual(data["destination_violations"], 0)

    def test_cli_inspect_inventory_and_report(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Health API", "version": "1.0"},
            "servers": [{"url": "https://health.local"}],
            "paths": {
                "/healthz": {
                    "get": {
                        "summary": "Health check",
                        "responses": {"200": {"description": "Healthy"}},
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            inv_file = Path(tmpdir) / "inv.json"
            inv = import_openapi(spec)
            inv.save(inv_file)

            args_inv = argparse.Namespace(
                web_api_command="inspect",
                file=str(inv_file),
                json=True,
            )
            rc_inv = command_web_api(args_inv, root=ROOT)
            self.assertEqual(rc_inv, 0)


if __name__ == "__main__":
    unittest.main()
