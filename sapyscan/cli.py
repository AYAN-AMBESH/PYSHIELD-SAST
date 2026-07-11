from __future__ import annotations
import argparse
import sys
from pathlib import Path
from sapyscan.scanner import Scanner
from sapyscan.reporter import ReportGenerator

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SaPyScan: A lightweight static application security testing (SAST) tool for Python."
    )
    parser.add_argument(
        "target",
        help="Path to the directory or file containing Python code to scan"
    )
    parser.add_argument(
        "--json",
        help="Path to output JSON format report",
        default=None
    )
    parser.add_argument(
        "--html",
        help="Path to output HTML dashboard report",
        default="sapyscan_report.html"
    )

    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    print("=" * 60)
    print("      SaPyScan: Static Security Code Analyzer")
    print("=" * 60)
    print(f"Target: {target_path}")
    print("Scanning code modules for vulnerabilities...")

    scanner = Scanner(target_path)
    findings = scanner.scan()

    print(f"Scan complete. Found {len(findings)} potential vulnerability findings.")

    # Generate JSON report if requested
    if args.json:
        scanner.generate_json_report(args.json)
        print(f"JSON report written to: {args.json}")

    # Generate HTML report if requested (default sapyscan_report.html)
    if args.html:
        # Convert findings to dictionary list for report renderer
        dict_findings = []
        for vuln in findings:
            d = vuln.to_dict()
            vuln_path = Path(vuln.file_path)
            if target_path.is_dir():
                rel = vuln_path.relative_to(target_path)
            else:
                rel = vuln_path.name
            d["relative_path"] = str(rel).replace("\\", "/")
            dict_findings.append(d)
        ReportGenerator.render_html(dict_findings, str(target_path), args.html)
        print(f"HTML dashboard report written to: {args.html}")

    print("=" * 60)

if __name__ == "__main__":
    main()

