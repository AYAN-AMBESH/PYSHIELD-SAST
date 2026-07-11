from __future__ import annotations
import ast
import json
import os
from pathlib import Path
from typing import Any
from .rules import ALL_RULES, Vulnerability

class Scanner:
    def __init__(self, target_dir: str | Path) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.rules = ALL_RULES
        self.results: list[Vulnerability] = []
        self.module_trees: dict[str, ast.Module] = {}

    def scan(self) -> list[Vulnerability]:
        """
        Scan target_dir (either a directory or single file) recursively.
        """
        self.results = []
        files = list(self.python_files())
        self.module_trees = {
            self.module_name(file_path): tree
            for file_path in files
            if (tree := self.parse_file(file_path)) is not None
        }

        for file_path in files:
            self.scan_file(file_path)

        return self.results

    def python_files(self):
        if self.target_dir.is_file():
            if self.target_dir.suffix == ".py":
                yield self.target_dir
            return

        ignored_parts = {".git", ".venv", "venv", "__pycache__", ".egg-info", "build", "dist"}
        for root, dirs, files in os.walk(self.target_dir):
            # Prune ignored directories in-place to speed up walk
            dirs[:] = [d for d in dirs if d not in ignored_parts]
            
            # Double check if root itself contains any ignored part
            if any(part in ignored_parts for part in Path(root).parts):
                continue
                
            for file in files:
                if file.endswith(".py"):
                    yield Path(root) / file

    def module_name(self, file_path: Path) -> str:
        root = self.target_dir if self.target_dir.is_dir() else file_path.parent
        parts = list(file_path.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    @staticmethod
    def parse_file(file_path: Path) -> ast.Module | None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        try:
            return ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return None

    def scan_file(self, file_path: Path) -> None:
        """
        Scan a single python file.
        """
        if self.target_dir.is_dir():
            rel_path = file_path.relative_to(self.target_dir)
        else:
            rel_path = file_path.name
        rel_path_clean = str(rel_path).replace('\\', '/')
        print(f"  Scanning: {rel_path_clean}")
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        tree = self.module_trees.get(self.module_name(file_path))
        if tree is None:
            return

        # Run rules
        for rule in self.rules:
            try:
                vulns = rule.check(
                    tree, str(file_path), content, self.module_trees, self.module_name(file_path)
                )
                self.results.extend(vulns)
            except Exception:
                # Log or handle exceptions inside rules gracefully so scanner doesn't crash
                pass

    def generate_json_report(self, output_path: str | Path) -> None:
        findings_list = []
        for vuln in self.results:
            d = vuln.to_dict()
            vuln_path = Path(vuln.file_path)
            if self.target_dir.is_dir():
                rel = vuln_path.relative_to(self.target_dir)
            else:
                rel = vuln_path.name
            d["relative_path"] = str(rel).replace("\\", "/")
            findings_list.append(d)

        report_data = {
            "target_directory": str(self.target_dir),
            "total_vulnerabilities": len(self.results),
            "findings": findings_list
        }
        
        Path(output_path).write_text(json.dumps(report_data, indent=4), encoding="utf-8")
