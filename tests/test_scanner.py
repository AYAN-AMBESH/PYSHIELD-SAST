from __future__ import annotations
from pathlib import Path
from pyshield.scanner import Scanner

def test_scanner_findings() -> None:
    # Locate the vulnerable test app
    target_file = Path(__file__).parent / "vulnerable_app.py"
    assert target_file.exists(), "Vulnerable app test file not found."

    scanner = Scanner(target_file)
    findings = scanner.scan()

    # Verify total count
    assert len(findings) == 20, f"Expected 20 findings, got {len(findings)}"

    # Collect rule IDs
    rule_ids = {vuln.rule_id for vuln in findings}
    expected_rule_ids = {
        "OWASP_A01_2021_PATH", "OWASP_A02_2021_HASH", "OWASP_A03_2021_SQLI",
        "OWASP_A03_2021_CMD", "OWASP_A03_2021_XSS", "OWASP_A03_2021_EVAL",
        "OWASP_A05_2021_SSL", "OWASP_A05_2021_DEBUG", "OWASP_A07_2021_SECRET",
        "OWASP_A08_2021_DESERIAL", "OWASP_A10_2021_SSRF"
    }

    # Check all expected rule IDs are detected
    for rid in expected_rule_ids:
        assert rid in rule_ids, f"Rule {rid} was not detected by the scanner."

    # Check detail messages or rule title presence
    has_aws = False
    has_db_pass = False
    for vuln in findings:
        if vuln.rule_id == "OWASP_A07_2021_SECRET":
            if "AWS" in vuln.description or "AWS" in vuln.code_snippet:
                has_aws = True
            if "DB_PASSWORD" in vuln.description or "DB_PASSWORD" in vuln.code_snippet:
                has_db_pass = True

    assert has_aws, "AWS secret was not detected."
    assert has_db_pass, "DB password secret was not detected."

