"""Exercise the installed-style CLI with actual SDK evidence and no repository imports."""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from attackpath.azure.input import load
from attackpath.azure.model import AzureError
from attackpath.azure.report import build
from azure_fixtures import write_bundle
from test_azure_paths import NOW, SECRET, VAULT, S, T, base, execution, role

PLUGIN = Path(__file__).resolve().parents[1]


def run_cli(*args, script=PLUGIN / "scripts/attackpath.py"):
    env = dict(os.environ, PYTHONPATH="", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, str(script), *map(str, args)],
        env=env,
        cwd=script.parent,
        capture_output=True,
        text=True,
        timeout=30,
    )


class SDKCLI(unittest.TestCase):
    def test_execution_chains_through_sdk_and_cli(self):
        cases = [
            (
                "Microsoft.Compute/virtualMachines",
                ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines/extensions/write"],
                ["vm_agent", "network", "token_endpoint"],
                "vm_execution",
            ),
            (
                "Microsoft.Compute/virtualMachines",
                ["Microsoft.Resources/deployments/*", "Microsoft.Compute/virtualMachines/extensions/write"],
                ["vm_agent", "network", "token_endpoint"],
                "arm_deployment",
            ),
            (
                "Microsoft.Automation/automationAccounts",
                [
                    "Microsoft.Automation/automationAccounts/runbooks/draft/content/write",
                    "Microsoft.Automation/automationAccounts/runbooks/publish/action",
                    "Microsoft.Automation/automationAccounts/jobs/write",
                ],
                ["automation_sandbox", "network", "token_endpoint"],
                "automation_execution",
            ),
            (
                "Microsoft.Web/sites",
                ["Microsoft.Web/sites/write", "Microsoft.Web/sites/publish/action"],
                ["function_deployment", "invocation", "network", "token_endpoint"],
                "functions_execution",
            ),
            (
                "Microsoft.Logic/workflows",
                ["Microsoft.Logic/workflows/write", "Microsoft.Logic/workflows/triggers/run/action"],
                ["logic_consumption", "identity_action", "invocation", "network", "token_endpoint"],
                "logic_execution",
            ),
        ]
        for kind, actions, runtime, rule in cases:
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as tmp:
                g, resource = execution(kind, actions, runtime)
                manifest = write_bundle(tmp, g)
                output = Path(tmp) / "report"
                result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", output)
                self.assertEqual(0, result.returncode, result.stderr)
                report = json.loads((output / "report.json").read_text())
                paths = [
                    p
                    for p in report["paths"]
                    if p["classification"] == "modelled_reachable" and rule in [s["rule"] for s in p["steps"]]
                ]
                self.assertTrue(paths, report["paths"])
                ledger = {r["record_id"] for r in report["evidence_ledger"]["records"]}
                self.assertTrue(all(set(p["evidence"]) <= ledger for p in paths))
                self.assertIn("prerequisites", paths[0]["steps"][0])
                self.assertTrue(paths[0]["assumptions"])
                self.assertTrue(
                    all(
                        set(d["evidence"]) <= ledger
                        for p in report["paths"]
                        for s in p["steps"]
                        for d in s["prerequisites"]
                    )
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                marker = json.loads((output / "completion.json").read_text())
                for name, digest in marker["files"].items():
                    self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())
                    self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
                self.assertIn("Evidence ledger references", (output / "report.md").read_text())
                g.scenario["runtime"][resource.lower()][runtime[0]] = False
                manifest = write_bundle(tmp, g)
                negative = build(load(manifest, NOW))
                self.assertFalse(
                    any(
                        p["classification"] == "modelled_reachable" and rule in [s["rule"] for s in p["steps"]]
                        for p in negative["paths"]
                    )
                )

    def test_federation_sdk_cli(self):
        g = base()
        u = S + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u"
        g.add(
            "resources",
            T,
            {"id": u, "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "properties": {"principalId": "mi"}},
            "uami",
        )
        g.add(
            "federated_credentials",
            T,
            {
                "id": u + "/federatedIdentityCredentials/f",
                "objectId": u,
                "issuer": "https://issuer.example",
                "subject": "subject",
                "audiences": ["api://AzureADTokenExchange"],
            },
            "fic",
        )
        role(g, "user", actions=["Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"])
        role(g, "mi", data=[SECRET], scope=VAULT, suffix="downstream")
        g.scenario["assertions"] = [
            {
                "issuer": "https://issuer.example",
                "subject": "subject",
                "audience": "api://AzureADTokenExchange",
                "controlled": True,
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, g)
            out = Path(tmp) / "report"
            result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", out)
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertTrue(
                any(
                    p["classification"] == "modelled_reachable" and "federation" in [s["rule"] for s in p["steps"]]
                    for p in report["paths"]
                )
            )

    def test_incomplete_stale_and_tampered_sdk_evidence(self):
        g = base()
        role(g, "user", data=[SECRET], scope=VAULT)
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in ({"status": "partial"}, {"observed_at": "2026-09-27T12:00:00Z"}):
                manifest = write_bundle(tmp, g, **kwargs)
                report = build(load(manifest, NOW))
                self.assertFalse(any(p["classification"] == "modelled_reachable" for p in report["paths"]))
                self.assertTrue(any(r["quality"] for r in report["evidence_ledger"]["records"]))
            manifest = write_bundle(tmp, g)
            data = json.loads(manifest.read_text())
            data["sources"][0]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(AzureError, "integrity_mismatch"):
                load(manifest, NOW)
            result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", Path(tmp) / "bad")
            self.assertEqual(2, result.returncode)
            self.assertNotIn(tmp, result.stderr)
            self.assertFalse((Path(tmp) / "bad/completion.json").exists())

    def test_read_only_collection_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(
                json.dumps(
                    {
                        "schema_version": "attackpath.azure.scope/v1",
                        "tenants": [
                            {
                                "id": T,
                                "scopes": [S],
                                "groups": ["group"],
                                "applications": ["app"],
                                "service_principals": ["sp"],
                                "administrative_units": ["au"],
                                "resources": [VAULT],
                                "user_assigned_identities": [
                                    S
                                    + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u"
                                ],
                                "management_groups": ["mg"],
                            }
                        ],
                    }
                )
            )
            out = Path(tmp) / "plan"
            result = run_cli("plan-azure-collection", "--scope-file", scope, "--output", out)
            self.assertEqual(0, result.returncode, result.stderr)
            plan = json.loads((out / "collection-plan.json").read_text())
            self.assertEqual(30, len({r["family"] for r in plan["requests"]}))
            self.assertTrue(
                all(
                    (r["method"] == "GET" or (r["family"] == "resource_inventory" and r["method"] == "POST"))
                    and r["reference"].startswith("https://learn.microsoft.com/")
                    for r in plan["requests"]
                )
            )
            self.assertTrue(all(r["permission"] and r["api"] and r["scopes"] for r in plan["requests"]))
            self.assertIn("cops.evidence/v1", plan["expected_evidence"]["envelope"])

    def test_resource_graph_inventory_is_explicit_and_scope_bounded(self):
        from attackpath.azure.collection import plan, source_contract
        from attackpath.azure.model import AzureError

        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            rg = S + "/resourceGroups/rg"
            mg = "/providers/Microsoft.Management/managementGroups/mg"
            scope.write_text(
                json.dumps(
                    {
                        "schema_version": "attackpath.azure.scope/v1",
                        "tenants": [{"id": T, "scopes": [rg, VAULT, mg, "/"], "management_groups": ["ancestry-only"]}],
                    }
                )
            )
            result = plan(scope)
            inventory = [r for r in result["requests"] if r["family"] == "resource_inventory"]
            self.assertEqual(3, len(inventory))
            self.assertEqual(3, len({r["id"] for r in inventory}))
            self.assertEqual(result, plan(scope))
            for request in inventory:
                self.assertEqual("POST", request["method"])
                self.assertEqual("AzureResourceGraph", request["product"])
                self.assertEqual("2024-04-01", request["api"])
                self.assertIn("Microsoft.ResourceGraph/resources/read", request["permission"])
                self.assertIn("resource-type read", request["permission"])
                self.assertIn("$skipToken", request["pagination"])
                self.assertEqual({"$top": 1000, "resultFormat": "objectArray"}, request["body"]["options"])
                query = request["body"]["query"]
                self.assertIn("project id, type", query)
                self.assertNotIn("ancestry-only", json.dumps(request))
                if request["scopes"] == [mg.lower()]:
                    self.assertEqual(["mg"], request["body"]["managementGroups"])
                    self.assertNotIn("subscriptions", request["body"])
                else:
                    self.assertEqual(["sub-a"], request["body"]["subscriptions"])
                    self.assertIn(json.dumps(request["scopes"][0]), query)
                    self.assertIn(json.dumps(request["scopes"][0] + "/"), query)
            self.assertTrue(any("omit inaccessible" in c for c in result["constraints"]))
            # Inventory does not become authoritative RBAC/resource evidence.
            with self.assertRaisesRegex(AzureError, "unsupported_source_family"):
                source_contract("resource_inventory", "2024-04-01")

    def test_partial_graph_and_private_deterministic_reports(self):
        g = base()
        role(g, "user", data=[SECRET], scope=VAULT)
        g.scenario["pseudonymize"] = True
        g.scenario["business_impact"] = {VAULT.lower(): "sensitive-owner-name"}
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, g)
            first, second = build(load(manifest, NOW)), build(load(manifest, NOW))
            self.assertEqual(first, second)
            text = json.dumps(first)
            for private in (T, S, "sensitive-owner-name"):
                self.assertNotIn(private, text)
            ids = {n["id"] for n in first["graph"]["nodes"]}
            self.assertTrue(all(e["source"] in ids and e["target"] in ids for e in first["graph"]["edges"]))
            write_bundle(tmp, g, limits={"expansions": 1})
            partial = build(load(manifest, NOW))
            self.assertEqual("partial", partial["status"])
            self.assertIn("expansion_limit", partial["partial_reasons"])

    def test_execution_assumptions_do_not_expose_resource_identifiers(self):
        g, resource = execution(
            "Microsoft.Compute/virtualMachines",
            ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines/extensions/write"],
            ["vm_agent", "network", "token_endpoint"],
        )
        g.scenario["pseudonymize"] = True
        with tempfile.TemporaryDirectory() as tmp:
            report = build(load(write_bundle(tmp, g), NOW))
            text = json.dumps(report)
            for private in (T, S, resource, resource.lower()):
                self.assertNotIn(private, text)
            self.assertTrue(any(p["assumptions"] for p in report["paths"]))

    def test_alternate_entitlement_survives_single_removal(self):
        g = base()
        role(g, "user", data=[SECRET], scope=VAULT, suffix="a")
        role(g, "user", data=[SECRET], scope=VAULT, suffix="b")
        with tempfile.TemporaryDirectory() as tmp:
            report = build(load(write_bundle(tmp, g), NOW))
            self.assertTrue(report["remediation"]["actions"])
            for cut in report["remediation"]["actions"]:
                self.assertTrue(cut["conclusive_within_model"])
                self.assertEqual([], cut["broken_paths"])
                self.assertGreater(cut["reachable_after"], 0)
            self.assertFalse(report["remediation"]["global_minimum_claimed"])

    def test_existing_and_symlink_output_rejected(self):
        g = base()
        role(g, "user", data=[SECRET], scope=VAULT)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, g)
            real = Path(tmp) / "real"
            real.mkdir()
            alias = Path(tmp) / "alias"
            alias.symlink_to(real)
            for output in (real, alias / "new"):
                result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", output)
                self.assertEqual(2, result.returncode)
            self.assertFalse((real / "new").exists())
