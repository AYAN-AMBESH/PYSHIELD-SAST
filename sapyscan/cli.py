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
    parser.add_argument(
        "--sarif",
        help="Path to output SARIF format report",
        default=None
    )
    parser.add_argument(
        "--parallel",
        help="Run file scans in parallel using multiprocessing",
        action="store_true"
    )
    parser.add_argument(
        "--min-severity",
        help="Filter findings by minimum severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO"
    )
    parser.add_argument(
        "--exclude",
        help="Custom directories to exclude from the scan (can be specified multiple times)",
        action="append",
        default=[]
    )
    parser.add_argument(
        "--autofix",
        help="Automatically fix supported vulnerabilities in-place",
        action="store_true"
    )

    import shlex

    # Preprocess sys.argv to handle PowerShell trailing backslash escape issue on Windows
    args_list = []
    for arg in sys.argv[1:]:
        if sys.platform.startswith("win") and '"' in arg and (' -' in arg or ' "' in arg):
            parts = arg.split('"', 1)
            path_part = parts[0] + '\\'
            remaining = parts[1]
            try:
                extra_args = shlex.split(remaining)
                args_list.append(path_part)
                args_list.extend(extra_args)
            except Exception:
                args_list.append(arg)
        else:
            args_list.append(arg)

    args = parser.parse_args(args_list)

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)

    print("=" * 60)
    print("      SaPyScan: Static Security Code Analyzer")
    print("=" * 60)
    print(f"Target: {target_path}")
    print("Scanning code modules for vulnerabilities...")

    scanner = Scanner(target_path, ignored_dirs=args.exclude)

    # Resolve settings from config, CLI overrides config
    parallel = args.parallel
    if not parallel and scanner.config.get("parallel") is True:
        parallel = True

    min_severity = args.min_severity
    if min_severity == "INFO" and "min_severity" in scanner.config:
        min_severity = scanner.config["min_severity"]

    findings = scanner.scan(parallel=parallel)

    # Filter findings by minimum severity
    if min_severity != "INFO":
        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        target_rank = severity_ranks.get(min_severity.upper(), 0)
        findings = [
            f for f in findings
            if severity_ranks.get(str(f.severity).upper(), 0) >= target_rank
        ]

    print(f"Scan complete. Found {len(findings)} potential vulnerability findings matching severity >= {min_severity}.")

    # Apply autofix if requested
    if args.autofix:
        fixed_count = scanner.autofix_files(findings)
        print(f"Autofix: successfully fixed {fixed_count} vulnerabilities in-place.")

    # Generate JSON report if requested
    if args.json:
        scanner.generate_json_report(args.json)
        print(f"JSON report written to: {args.json}")

    # Generate SARIF report if requested
    if args.sarif:
        scanner.generate_sarif_report(args.sarif)
        print(f"SARIF report written to: {args.sarif}")

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

