import os
import argparse
import sys
from pyshield.scanner import Scanner
from pyshield.reporter import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description="PyShield-SAST: A lightweight static application security testing (SAST) tool for Python."
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
        default="pyshield_report.html"
    )

    args = parser.parse_args()

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    print("=" * 60)
    print("      PyShield-SAST: Static Security Code Analyzer")
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

    # Generate HTML report if requested (default pyshield_report.html)
    if args.html:
        # Convert findings to dictionary list for report renderer
        dict_findings = [vuln.to_dict() for vuln in findings]
        ReportGenerator.render_html(dict_findings, target_path, args.html)
        print(f"HTML dashboard report written to: {args.html}")

    print("=" * 60)

if __name__ == "__main__":
    main()
