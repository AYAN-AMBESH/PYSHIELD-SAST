import os
import ast
import json
from typing import List, Dict, Any
from .rules import ALL_RULES, Vulnerability

class Scanner:
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = ALL_RULES
        self.results: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        """
        Scan target_dir (either a directory or single file) recursively.
        """
        self.results = []
        if os.path.isfile(self.target_dir):
            if self.target_dir.endswith(".py"):
                self.scan_file(self.target_dir)
            return self.results

        for root, _, files in os.walk(self.target_dir):
            # Ignore common cache / venv directories
            if any(part in root for part in {".git", ".venv", "venv", "__pycache__", ".egg-info", "build", "dist"}):
                continue
                
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    self.scan_file(full_path)
                    
        return self.results


    def scan_file(self, file_path: str):
        """
        Scan a single python file.
        """
        rel_path = os.path.relpath(file_path, self.target_dir) if os.path.isdir(self.target_dir) else os.path.basename(file_path)
        rel_path_clean = rel_path.replace('\\', '/')
        print(f"  Scanning: {rel_path_clean}")
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return

        try:
            # Parse the code into AST
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            # Code contains syntactic errors, skip AST analysis but can log or do basic regex checks if needed
            return

        # Run rules
        for rule in self.rules:
            try:
                vulns = rule.check(tree, file_path, content)
                self.results.extend(vulns)
            except Exception as e:
                # Log or handle exceptions inside rules gracefully so scanner doesn't crash
                pass

    def generate_json_report(self, output_path: str):
        findings_list = []
        for vuln in self.results:
            d = vuln.to_dict()
            rel = os.path.relpath(vuln.file_path, self.target_dir) if os.path.isdir(self.target_dir) else os.path.basename(vuln.file_path)
            d["relative_path"] = rel.replace("\\", "/")
            findings_list.append(d)

        report_data = {
            "target_directory": self.target_dir,
            "total_vulnerabilities": len(self.results),
            "findings": findings_list
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
