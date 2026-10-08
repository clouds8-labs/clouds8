import unittest
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.oci_collector import OCICollector
from playbooks.cis_benchmark import CISBenchmarkRunner

# Database-layer tests live in tests/db_service/test_db_service.py - they test
# services/db-service directly via FastAPI's TestClient against a temp SQLite
# file, since db/database.py is now an HTTP client facade (no local
# get_connection()/sqlite3 access left to mock here).

class TestOCICollector(unittest.TestCase):
    
    def test_mock_collection_structure(self):
        """Test that mock data follows the correct asset schema"""
        collector = OCICollector()
        # Force config to None to trigger mock data execution
        collector.config = None
        
        batches = list(collector.collect_all())
        assets = []
        for batch in batches:
            assets.extend(batch)
        
        self.assertIsInstance(assets, list)
        self.assertGreater(len(assets), 0)
        
        asset = assets[0]
        self.assertIn('asset_id', asset)
        self.assertIn('asset_type', asset)
        self.assertIn('name', asset)
        self.assertIn('compartment', asset)
        self.assertIn('metadata', asset)
        self.assertIsInstance(asset['metadata'], dict)

    @patch('oci.pagination.list_call_get_all_results')
    def test_instance_normalization(self, mock_get_all):
        """Test normalization of instance data"""
        collector = OCICollector()
        collector.config = {"region": "us-ashburn-1"}
        
        # Mock Compute Client
        mock_compute = MagicMock()
        collector.clients["compute"] = mock_compute
        
        # Mock instance object
        mock_inst = MagicMock()
        mock_inst.id = "ocid1.instance.oc1..test"
        mock_inst.display_name = "Test-VM"
        mock_inst.region = "us-ashburn-1"
        mock_inst.shape = "VM.Standard2.1"
        mock_inst.lifecycle_state = "RUNNING"
        mock_inst.availability_domain = "AD-1"
        mock_inst.time_created = "2023-01-01T00:00:00Z"
        
        # Setup pagination return value
        mock_response = MagicMock()
        mock_response.data = [mock_inst]
        mock_get_all.return_value = mock_response
        
        # Execute
        results = collector._collect_instances("comp-id", "comp-name")
        
        self.assertEqual(len(results), 1)
        asset = results[0]
        self.assertEqual(asset['asset_id'], "ocid1.instance.oc1..test")
        self.assertEqual(asset['asset_type'], "vm")
        self.assertEqual(asset['name'], "Test-VM")
        self.assertEqual(asset['metadata']['shape'], "VM.Standard2.1")


class TestCISBenchmark(unittest.TestCase):
    def test_mock_run(self):
        """Test CISBenchmarkRunner in mock mode (no collector)"""
        runner = CISBenchmarkRunner(collector=None)
        report = runner.run()
        self.assertEqual(report.scan_mode, "mock")
        self.assertGreater(report.total_checks, 0)
        self.assertGreater(len(report.results), 0)
        
        # Test compliance percentage calculation
        self.assertGreaterEqual(report.compliance_pct, 0.0)
        self.assertLessEqual(report.compliance_pct, 100.0)

    @patch('collectors.oci_collector.OCICollector')
    def test_live_run_mocked_collector(self, MockCollector):
        """Test CISBenchmarkRunner in live mode with a mocked collector and client methods"""
        collector = MockCollector()
        collector.config = {"region": "us-phoenix-1", "tenancy": "ocid1.tenancy.oc1..test"}
        collector.get_subscribed_regions.return_value = ["us-phoenix-1", "us-ashburn-1"]
        collector.compartments = [
            {"id": "comp-1", "name": "Compartment 1", "lifecycle_state": "ACTIVE"}
        ]
        
        # Mock identity client
        mock_identity = MagicMock()
        mock_user = MagicMock()
        mock_user.name = "console_user"
        mock_user.can_use_console_password = True
        mock_user.is_mfa_activated = True
        mock_identity.list_users.return_value.data = [mock_user]
        
        # Mock API Key listing
        mock_key = MagicMock()
        mock_key.fingerprint = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
        mock_key.time_created = datetime.utcnow()
        mock_identity.list_api_keys.return_value.data = [mock_key]
        
        # Mock network client
        mock_network = MagicMock()
        mock_seclist = MagicMock()
        mock_seclist.display_name = "SecList 1"
        mock_rule = MagicMock()
        mock_rule.source = "10.0.0.0/24" # Safe source, shouldn't trigger FAIL
        mock_seclist.ingress_security_rules = [mock_rule]
        mock_network.list_security_lists.return_value.data = [mock_seclist]
        
        mock_subnet = MagicMock()
        mock_subnet.display_name = "Subnet 1"
        mock_subnet.prohibit_public_ip_on_vnic = True
        mock_network.list_subnets.return_value.data = [mock_subnet]
        
        # Mock objstore client
        mock_objstore = MagicMock()
        mock_objstore.get_namespace.return_value.data = "namespace"
        mock_bucket_summary = MagicMock()
        mock_bucket_summary.name = "bucket-1"
        mock_objstore.list_buckets.return_value.data = [mock_bucket_summary]
        
        mock_bucket = MagicMock()
        mock_bucket.name = "bucket-1"
        mock_bucket.public_access_type = "NoPublicAccess"
        mock_bucket.versioning = "Enabled"
        mock_bucket.kms_key_id = "kms-key"
        mock_objstore.get_bucket.return_value.data = mock_bucket
        
        # Mock compute client
        mock_compute = MagicMock()
        mock_inst = MagicMock()
        mock_inst.id = "inst-1"
        mock_inst.display_name = "VM 1"
        mock_inst.instance_options.are_legacy_imds_endpoints_disabled = True
        mock_inst.agent_config.is_monitoring_disabled = False
        mock_compute.list_instances.return_value.data = [mock_inst]
        mock_compute.list_vnic_attachments.return_value.data = []
        
        # Mock audit client
        mock_audit = MagicMock()
        mock_audit_cfg = MagicMock()
        mock_audit_cfg.retention_period_days = 365
        mock_audit.get_configuration.return_value.data = mock_audit_cfg
        
        # Mock cloud guard client
        mock_cg = MagicMock()
        mock_cg_cfg = MagicMock()
        mock_cg_cfg.status = "ENABLED"
        mock_cg.get_configuration.return_value.data = mock_cg_cfg
        
        # Mock KMS clients
        mock_kms = MagicMock()
        mock_vault = MagicMock()
        mock_vault.display_name = "Vault 1"
        mock_vault.management_endpoint = "mgmt-endpoint"
        mock_kms.list_vaults.return_value.data = [mock_vault]
        
        collector.clients = {
            "identity": mock_identity,
            "network": mock_network,
            "object_storage": mock_objstore,
            "compute": mock_compute,
            "audit": mock_audit,
            "cloud_guard": mock_cg,
            "kms_vault": mock_kms
        }
        
        with patch('oci.audit.AuditClient', return_value=mock_audit), \
             patch('oci.cloud_guard.CloudGuardClient', return_value=mock_cg):
            runner = CISBenchmarkRunner(collector=collector)
            report = runner.run()
            
            self.assertEqual(report.scan_mode, "live")
            self.assertGreater(report.total_checks, 0)
            self.assertEqual(report.region, "us-phoenix-1, us-ashburn-1")

if __name__ == '__main__':
    unittest.main()
