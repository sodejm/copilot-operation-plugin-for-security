"""Validate actual CLI artifacts against the shipped Azure JSON Schemas."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from azure_fixtures import write_bundle
from jsonschema import Draft202012Validator, ValidationError
from test_azure_paths import NOW, SECRET, VAULT, S, T, base, role
from test_azure_sdk_cli import PLUGIN, run_cli


def validate(document, name):
    schema = json.loads((PLUGIN / "schemas" / ("azure-" + name + "-v1.schema.json")).read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


def validate_legacy_completion(document):
    schema = json.loads((PLUGIN / "schemas" / "completion-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


class SchemaTests(unittest.TestCase):
    def test_legacy_completion_schema(self):
        marker = {
            "schema_version": "attackpath.completion/v1",
            "run_id": "run-example",
            "status": "complete",
            "files": {
                "report.json": "0" * 64,
                "graph.json": "1" * 64,
                "report.md": "2" * 64,
                "remediation-ledger.json": "3" * 64,
            },
        }
        validate_legacy_completion(marker)
        for mutation in ("missing_report", "extra_report", "invalid_digest"):
            with self.subTest(mutation=mutation):
                malformed = copy.deepcopy(marker)
                if mutation == "missing_report":
                    del malformed["files"]["report.md"]
                elif mutation == "extra_report":
                    malformed["files"]["unexpected.json"] = "4" * 64
                else:
                    malformed["files"]["graph.json"] = "not-a-sha256"
                with self.assertRaises(ValidationError):
                    validate_legacy_completion(malformed)

    def test_actual_analysis_and_collection_artifacts(self):
        g = base()
        role(g, "user", data=[SECRET], scope=VAULT)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_bundle(tmp, g)
            validate(json.loads(manifest.read_text()), "input")
            output = Path(tmp) / "report"
            result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW, "--output", output)
            self.assertEqual(0, result.returncode, result.stderr)
            for filename, schema in (("report.json", "report"), ("graph.json", "graph"),
                                     ("evidence-ledger.json", "ledger"), ("remediation.json", "remediation"),
                                     ("completion.json", "completion")):
                with self.subTest(schema=schema):
                    validate(json.loads((output / filename).read_text()), schema)
            report = json.loads((output / "report.json").read_text())
            malformed = copy.deepcopy(report)
            malformed["paths"][0]["classification"] = "confirmed_compromise"
            with self.assertRaises(ValidationError):
                validate(malformed, "report")
            malformed = copy.deepcopy(report)
            malformed["paths"][0]["assumptions"] = "invented-evidence"
            with self.assertRaises(ValidationError):
                validate(malformed, "report")
            marker = json.loads((output / "completion.json").read_text())
            del marker["files"]["report.json"]
            with self.assertRaises(ValidationError):
                validate(marker, "completion")
            scope = {"schema_version": "attackpath.azure.scope/v1", "tenants": [{"id": T, "scopes": [S]}]}
            validate(scope, "scope")
            scope_file = Path(tmp) / "scope.json"
            scope_file.write_text(json.dumps(scope))
            plan_dir = Path(tmp) / "plan"
            result = run_cli("plan-azure-collection", "--scope-file", scope_file, "--output", plan_dir)
            self.assertEqual(0, result.returncode, result.stderr)
            plan = json.loads((plan_dir / "collection-plan.json").read_text())
            validate(plan, "collection")
            inventory = next(r for r in plan["requests"] if r["family"] == "resource_inventory")
            for mutation in ("method", "missing_body", "missing_scope", "mixed_scope", "get_body", "get_inventory"):
                with self.subTest(invalid_request=mutation):
                    malformed = copy.deepcopy(plan)
                    request = next(r for r in malformed["requests"] if r["id"] == inventory["id"])
                    if mutation == "method":
                        request["method"] = "GET"
                    elif mutation == "missing_body":
                        del request["body"]
                    elif mutation == "missing_scope":
                        del request["body"]["subscriptions"]
                    elif mutation == "mixed_scope":
                        request["body"]["managementGroups"] = ["other-scope"]
                    elif mutation == "get_body":
                        request = next(r for r in malformed["requests"] if r["method"] == "GET")
                        request["body"] = copy.deepcopy(inventory["body"])
                    else:
                        request = next(r for r in malformed["requests"] if r["method"] == "GET")
                        request["family"] = "resource_inventory"
                    with self.assertRaises(ValidationError):
                        validate(malformed, "collection")
