from __future__ import annotations
from pathlib import Path
from sapyscan.scanner import Scanner

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


def test_parallel_scanner() -> None:
    target_file = Path(__file__).parent / "vulnerable_app.py"
    assert target_file.exists(), "Vulnerable app test file not found."

    scanner_seq = Scanner(target_file)
    findings_seq = scanner_seq.scan(parallel=False)

    scanner_par = Scanner(target_file)
    findings_par = scanner_par.scan(parallel=True)

    # Sort results to compare
    key_fn = lambda x: (x.rule_id, x.file_path, x.line_no, x.col_offset)
    sorted_seq = sorted(findings_seq, key=key_fn)
    sorted_par = sorted(findings_par, key=key_fn)

    assert len(sorted_seq) == len(sorted_par), "Vulnerabilities count mismatched between sequential and parallel scans"
    for s, p in zip(sorted_seq, sorted_par):
        assert s.rule_id == p.rule_id
        assert s.file_path == p.file_path
        assert s.line_no == p.line_no
        assert s.col_offset == p.col_offset


def test_scanner_excludes(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("eval(input())", encoding="utf-8")
    
    ignored = tmp_path / "ignored_tests"
    ignored.mkdir()
    (ignored / "app_test.py").write_text("eval(input())", encoding="utf-8")
    
    scanner = Scanner(tmp_path, ignored_dirs=["ignored_tests"])
    findings = scanner.scan()
    
    assert len(findings) == 1
    assert "src/app.py" in findings[0].file_path.replace("\\", "/")


def test_scanner_suppressions(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
eval(input()) # nosec
eval(input()) # sapyscan: ignore
eval(input()) # sapyscan: ignore OWASP_A03_2021_SQLI
eval(input()) # sapyscan: ignore OWASP_A03_2021_EVAL
eval(input()) # this is not ignored
""",
        encoding="utf-8",
    )
    
    findings = Scanner(target).scan()
    assert len(findings) == 2
    assert findings[0].line_no == 4
    assert findings[1].line_no == 6


def test_scanner_sarif(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("eval(input())", encoding="utf-8")
    
    scanner = Scanner(target)
    scanner.scan()
    
    sarif_file = tmp_path / "report.sarif"
    scanner.generate_sarif_report(sarif_file)
    
    assert sarif_file.exists()
    import json
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "OWASP_A03_2021_EVAL"


def test_scanner_autofix(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text(
        """
import sqlite3

def run(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
""",
        encoding="utf-8",
    )
    
    scanner = Scanner(target)
    findings = scanner.scan()
    assert len(findings) == 1
    assert findings[0].rule_id == "OWASP_A03_2021_SQLI"
    
    # Run autofix
    fixed_count = scanner.autofix_files(findings)
    assert fixed_count == 1
    
    # Verify file content is parameterized
    fixed_content = target.read_text(encoding="utf-8")
    assert "cursor.execute('SELECT * FROM users WHERE name = %s', (username,))" in fixed_content





