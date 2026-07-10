import unittest
import os
from pyshield.scanner import Scanner

class TestPyShieldScanner(unittest.TestCase):
    def setUp(self):
        # Locate the vulnerable test app
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.target_file = os.path.join(current_dir, "vulnerable_app.py")
        self.assertTrue(os.path.exists(self.target_file), "Vulnerable app test file not found.")

    def test_scanner_findings(self):
        scanner = Scanner(self.target_file)
        findings = scanner.scan()
        
        # Verify total count
        self.assertEqual(len(findings), 11, f"Expected 11 findings, got {len(findings)}")
        
        # Collect rule IDs
        rule_ids = {vuln.rule_id for vuln in findings}
        expected_rule_ids = {"SEC101", "SEC102", "SEC103", "SEC104", "SEC105", "SEC106", "SEC107", "SEC108"}
        
        # Check all expected rule IDs are detected
        for rid in expected_rule_ids:
            self.assertIn(rid, rule_ids, f"Rule {rid} was not detected by the scanner.")

        # Check detail messages or rule title presence
        has_aws = False
        has_db_pass = False
        for vuln in findings:
            if vuln.rule_id == "SEC101":
                if "AWS" in vuln.description or "AWS" in vuln.code_snippet:
                    has_aws = True
                if "DB_PASSWORD" in vuln.description or "DB_PASSWORD" in vuln.code_snippet:
                    has_db_pass = True
                    
        self.assertTrue(has_aws, "AWS secret was not detected.")
        self.assertTrue(has_db_pass, "DB password secret was not detected.")

if __name__ == "__main__":
    unittest.main()
