"""Portable evidence subset must exactly match canonical repository contracts."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_generated_evidence_subset_and_drift(tmp_path):
    spec = importlib.util.spec_from_file_location("azure_bundle", ROOT / "scripts/agent/bundle_evidence.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.generate(ROOT, check=True)
    target = tmp_path / "runtime"
    assert module.generate(ROOT, destination=target)
    (target / "catalog/schemas/evidence-envelope.schema.json").write_text("{}")
    assert not module.generate(ROOT, check=True, destination=target)


def test_exported_azure_cli_runs_without_repository_imports(tmp_path):
    import json
    import sys

    from cops.portable import export_portable_package
    plugin = ROOT / "plugins/detection-hunting/attack-path-workbench"
    sys.path.insert(0, str(plugin))
    sys.path.insert(0, str(plugin / "tests"))
    from azure_fixtures import write_bundle
    from test_azure_paths import NOW, execution
    from test_azure_sdk_cli import run_cli
    exported = tmp_path / "export"
    export_portable_package(plugin, exported)
    assert not (exported / "tests").exists()
    assert not (exported / "attackpath/_runtime/cops/evidence/acquisition.py").exists()
    cases = [
        ("Microsoft.Compute/virtualMachines", ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines/extensions/write"], ["vm_agent", "network", "token_endpoint"], "vm_execution"),
        ("Microsoft.Automation/automationAccounts", ["Microsoft.Automation/automationAccounts/runbooks/draft/content/write", "Microsoft.Automation/automationAccounts/runbooks/publish/action", "Microsoft.Automation/automationAccounts/jobs/write"], ["automation_sandbox", "network", "token_endpoint"], "automation_execution"),
        ("Microsoft.Web/sites", ["Microsoft.Web/sites/write", "Microsoft.Web/sites/publish/action"], ["function_deployment", "invocation", "network", "token_endpoint"], "functions_execution"),
        ("Microsoft.Logic/workflows", ["Microsoft.Logic/workflows/write", "Microsoft.Logic/workflows/triggers/run/action"], ["logic_consumption", "identity_action", "invocation", "network", "token_endpoint"], "logic_execution"),
    ]
    for index, (kind, actions, runtime, rule) in enumerate(cases):
        evidence = tmp_path / ("evidence-" + str(index))
        evidence.mkdir()
        g, _ = execution(kind, actions, runtime)
        manifest = write_bundle(evidence, g)
        output = tmp_path / ("report-" + str(index))
        result = run_cli("analyze-azure", "--input", manifest, "--as-of", NOW,
                         "--output", output, script=exported / "scripts/attackpath.py")
        assert result.returncode == 0, result.stderr
        report = json.loads((output / "report.json").read_text())
        assert any(p["classification"] == "modelled_reachable" and
                   any(s["rule"] == rule for s in p["steps"]) for p in report["paths"])
        assert (output / "completion.json").is_file()
