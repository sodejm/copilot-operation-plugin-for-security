#!/usr/bin/env python3
"""
test_plugin.py
Automated test suite for Security Logging Advisor plugin validation and scanning capabilities.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest

# Paths
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
PACKAGE = os.path.join(REPO_ROOT, "plugins", "logging-telemetry", "security-logging-advisor")
VALIDATE_SCRIPT = os.path.join(PACKAGE, "scripts", "validate-plugin.py")
SCAN_SCRIPT = os.path.join(PACKAGE, "skills", "repository-context", "scripts", "collect-repository-context.py")

class TestPluginValidation(unittest.TestCase):
    """Verifies features defined in specs/features/plugin_validation.feature"""

    def test_manifest_and_marketplace_parsing_success(self):
        """Runs the validation script on the current valid repository structure."""
        res = subprocess.run(
            [sys.executable, VALIDATE_SCRIPT],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"Validator failed: {res.stderr}\nStdout: {res.stdout}")
        self.assertIn("All checks passed successfully", res.stdout)

    def test_validation_fails_on_missing_files(self):
        """Checks that validation fails and reports errors when files are missing or broken."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run validate-plugin from a directory with no files
            res = subprocess.run(
                [sys.executable, VALIDATE_SCRIPT],
                cwd=temp_dir,
                capture_output=True,
                text=True
            )
            # It should fail because the categorized package and its manifest are missing.
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Validation failed with errors", res.stdout)
            self.assertIn("Missing required file/path", res.stdout)

    def test_validation_fails_on_invalid_skill_frontmatter(self):
        """Checks that validator catches bad frontmatter formats in SKILL.md files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = os.path.join(temp_dir, "plugins", "logging-telemetry", "security-logging-advisor")
            shutil.copytree(PACKAGE, plugin_dir)
            skill = os.path.join(plugin_dir, "skills", "repository-context", "SKILL.md")
            with open(skill, "w") as file:
                file.write("---\nname: repository-context\n# missing description\n---\nbody")
            res = subprocess.run(
                [sys.executable, VALIDATE_SCRIPT], cwd=temp_dir, capture_output=True, text=True
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("frontmatter is missing 'description'", res.stdout)



class TestRepositoryScanning(unittest.TestCase):
    """Verifies features defined in specs/features/repository_scanning.feature"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def run_scanner(self):
        res = subprocess.run(
            [sys.executable, SCAN_SCRIPT, self.temp_dir],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"Scanner failed: {res.stderr}")
        return json.loads(res.stdout)

    def test_detect_technology_and_cloud_from_hcl(self):
        """Scenario: Detect technology stack and cloud platform from HCL configuration"""
        # Create a Terraform file main.tf referencing aws provider
        tf_content = """
        provider "aws" {
          region = "us-east-1"
        }
        resource "aws_s3_bucket" "b" {
          bucket = "my-tf-test-bucket"
        }
        """
        with open(os.path.join(self.temp_dir, "main.tf"), "w") as f:
            f.write(tf_content)

        output = self.run_scanner()

        # Verify languages
        self.assertIn("HashiCorp Configuration Language (HCL)", output["languages"])
        # Verify cloud / iac
        self.assertIn("AWS", output["iac_and_cloud"])
        self.assertIn("Terraform", output["iac_and_cloud"])

    def test_prevent_credential_leakage(self):
        """Scenario: Prevent credential leakage in scanner output"""
        secret_val = "SuperSecretPassword123!"
        env_content = f"db_password = '{secret_val}'\n"
        with open(os.path.join(self.temp_dir, "config.env"), "w") as f:
            f.write(env_content)

        output = self.run_scanner()

        # Check secrets findings lists config.env
        findings = output["secrets_findings"]
        self.assertTrue(len(findings) > 0, "No secrets findings detected")

        finding = findings[0]
        self.assertEqual(finding["file"], "config.env")
        self.assertIn("remediation", finding)
        self.assertIn("vault", finding["remediation"].lower())

        # Ensure raw secret is not leaked in output json
        output_str = json.dumps(output)
        self.assertNotIn(secret_val, output_str)

    def test_detect_multi_language_and_cloud_indicators(self):
        """Scenario: Detect multi-language and Cloud provider indicators"""
        # Create a Bicep file
        with open(os.path.join(self.temp_dir, "deploy.bicep"), "w") as f:
            f.write("// Bicep deployments")

        # Create package.json with dependency "aws-sdk"
        package_json = {
            "dependencies": {
                "aws-sdk": "^2.1000.0"
            }
        }
        with open(os.path.join(self.temp_dir, "package.json"), "w") as f:
            json.dump(package_json, f)

        output = self.run_scanner()

        self.assertIn("Bicep", output["languages"])
        self.assertIn("Azure Bicep", output["iac_and_cloud"])
        self.assertIn("AWS", output["iac_and_cloud"])


if __name__ == "__main__":
    unittest.main()
