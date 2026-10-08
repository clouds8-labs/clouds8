"""
Tests for services/backend-api/routers/v1_runs.py's _build_html() - the
new HTML export format added alongside the existing CSV/JSON/PDF ones.
"""
import os
import sys
import unittest

_SERVICE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "services", "backend-api")
)
sys.path.insert(0, _SERVICE_DIR)

for _mod_name in list(sys.modules):
    if _mod_name == "routers" or _mod_name.startswith("routers."):
        del sys.modules[_mod_name]

import routers.v1_runs as v1_runs  # noqa: E402


class TestBuildHtmlExport(unittest.TestCase):
    def test_renders_asset_and_finding_tables(self):
        assets = [{
            "id": "ocid1.vm.1", "class": "vm", "name": "web-01", "compartment": "Prod",
            "region": "us-ashburn-1", "exposure": "internet_facing", "risk": 8.5,
            "finding_counts": {"critical": 1, "high": 2, "medium": 0, "low": 0},
        }]
        findings = [{
            "id": 1, "rule_id": "vm-public-ip", "title": "Public IP Exposure",
            "asset_id": "ocid1.vm.1", "asset_name": "web-01", "account": "Prod",
            "severity": "high", "state": "open", "description": "Has a public IP.",
        }]

        out = v1_runs._build_html(assets, findings, ["assets", "findings"])

        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("web-01", out)
        self.assertIn("vm-public-ip", out)
        self.assertIn("Public IP Exposure", out)
        self.assertIn("<table>", out)

    def test_escapes_html_special_characters(self):
        assets = [{
            "id": "a1", "class": "vm", "name": "<script>alert(1)</script>", "compartment": None,
            "region": None, "exposure": "internal", "risk": 1, "finding_counts": {},
        }]
        out = v1_runs._build_html(assets, [], ["assets"])
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_section_filter_excludes_the_other_table(self):
        out = v1_runs._build_html(
            [{"id": "a1", "class": "vm", "name": "n", "compartment": "", "region": "",
              "exposure": "internal", "risk": 0, "finding_counts": {}}],
            [{"id": 1, "rule_id": "r", "title": "t", "asset_id": "a1", "asset_name": None,
              "account": "", "severity": "low", "state": "open", "description": ""}],
            ["assets"],
        )
        self.assertIn("Assets (1)", out)
        self.assertNotIn("Findings (1)", out)


if __name__ == "__main__":
    unittest.main()
