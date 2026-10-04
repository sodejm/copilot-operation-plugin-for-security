"""Tests for adapter-registration-validation contributor skill."""

from __future__ import annotations

import unittest
from cops.adapters import ToolAdapterRegistry, AdapterInjectionError


class TestAdapterRegistrationSkill(unittest.TestCase):
    def setUp(self):
        self.registry = ToolAdapterRegistry()

    def test_nmap_assembly(self):
        adapter = self.registry.get_adapter("nmap")
        cmd = adapter.assemble_command("port_scan", {"target": "10.0.0.5", "ports": "80,443"})
        self.assertEqual(cmd[0], "nmap")
        self.assertIn("10.0.0.5", cmd)
        self.assertIn("-p", cmd)

    def test_injection_prevention(self):
        adapter = self.registry.get_adapter("nmap")
        with self.assertRaises(AdapterInjectionError):
            adapter.assemble_command("port_scan", {"target": "10.0.0.5; rm -rf /"})


if __name__ == "__main__":
    unittest.main()
