from __future__ import annotations
import ast
import json
import os
from pathlib import Path
from typing import Any
from .rules import ALL_RULES, Vulnerability
from .config import find_config, load_config

# Multiprocessing globals and initializer/worker for parallel scanning of large codebases
_worker_module_trees = None
_worker_parent_maps = None
_worker_node_trees = None
_worker_tree_modules = None
_worker_rules = None
_worker_target_dir = None
_worker_site_packages_dir = None

def _init_worker(module_trees, parent_maps, node_trees, tree_modules, rules, target_dir, site_packages_dir=None):
    global _worker_module_trees, _worker_parent_maps, _worker_node_trees, _worker_tree_modules, _worker_rules, _worker_target_dir, _worker_site_packages_dir
    _worker_module_trees = module_trees
    _worker_parent_maps = parent_maps
    _worker_node_trees = node_trees
    _worker_tree_modules = tree_modules
    _worker_rules = rules
    _worker_target_dir = target_dir
    _worker_site_packages_dir = site_packages_dir

def _worker_module_name(file_path: Path, target_dir: Path) -> str:
    root = target_dir if target_dir.is_dir() else file_path.parent
    parts = list(file_path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)

def _worker_scan_file(file_path: Path) -> list[Vulnerability]:
    global _worker_module_trees, _worker_parent_maps, _worker_node_trees, _worker_tree_modules, _worker_rules, _worker_target_dir, _worker_site_packages_dir
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    mod_name = _worker_module_name(file_path, _worker_target_dir)
    tree = _worker_module_trees.get(mod_name)
    if tree is None:
        return []

    results = []
    # Run rules
    for rule in _worker_rules:
        try:
            vulns = rule.check(
                tree,
                str(file_path),
                content,
                _worker_module_trees,
                mod_name,
                parent_maps=_worker_parent_maps,
                node_trees=_worker_node_trees,
                tree_modules=_worker_tree_modules,
                site_packages_dir=_worker_site_packages_dir,
            )
            results.extend(vulns)
        except Exception:
            pass
    return results


class Scanner:
    def __init__(self, target_dir: str | Path, ignored_dirs: list[str] | None = None) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.results: list[Vulnerability] = []
        self.module_trees: dict[str, ast.Module] = {}
        self.ignored_parts = {".git", ".venv", "venv", "__pycache__", ".egg-info", "build", "dist"}
        if ignored_dirs:
            self.ignored_parts.update(ignored_dirs)

        # Load configuration
        config_path = find_config(self.target_dir)
        self.config = load_config(config_path)

        # Apply custom exclusions from config
        cfg_excludes = self.config.get("exclude_dirs", [])
        if isinstance(cfg_excludes, list):
            self.ignored_parts.update(str(p) for p in cfg_excludes)

        # Disable specified rules
        disabled_rules = self.config.get("disabled_rules", [])
        if not isinstance(disabled_rules, list):
            disabled_rules = []
        self.rules = [rule for rule in ALL_RULES if rule.rule_id not in disabled_rules]

        self.site_packages_dir = self.detect_site_packages()

    def detect_site_packages(self) -> Path | None:
        curr = self.target_dir
        for _ in range(4):
            for name in (".venv", "venv"):
                venv_dir = curr / name
                if venv_dir.is_dir():
                    windows_path = venv_dir / "Lib" / "site-packages"
                    if windows_path.is_dir():
                        return windows_path.resolve()
                    unix_lib = venv_dir / "lib"
                    if unix_lib.is_dir():
                        for sub in unix_lib.iterdir():
                            if sub.is_dir() and sub.name.startswith("python"):
                                sp = sub / "site-packages"
                                if sp.is_dir():
                                    return sp.resolve()
            if curr == curr.parent:
                break
            curr = curr.parent
        return None

    def scan(self, parallel: bool = False) -> list[Vulnerability]:
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

        # Precompute parent maps and node trees once for the entire scan
        self.parent_maps: dict[ast.Module, dict[ast.AST, ast.AST]] = {}
        self.node_trees: dict[ast.AST, ast.Module] = {}
        self.tree_modules: dict[ast.Module, str] = {}
        
        for mod_name, tree in self.module_trees.items():
            self.tree_modules[tree] = mod_name
            pmap = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    pmap[child] = parent
                    self.node_trees[child] = tree
            self.node_trees[tree] = tree
            self.parent_maps[tree] = pmap

        if parallel and len(files) > 1:
            from concurrent.futures import ProcessPoolExecutor
            # Run file scanning in parallel using ProcessPoolExecutor
            with ProcessPoolExecutor(
                initializer=_init_worker,
                initargs=(self.module_trees, self.parent_maps, self.node_trees, self.tree_modules, self.rules, self.target_dir, self.site_packages_dir)
            ) as executor:
                # Map files to scan
                futures = executor.map(_worker_scan_file, files)
                for file_results in futures:
                    self.results.extend(file_results)
        else:
            for file_path in files:
                self.scan_file(file_path)

        return self.results

    def python_files(self):
        if self.target_dir.is_file():
            if self.target_dir.suffix == ".py":
                if "test" not in self.target_dir.stem.lower():
                    yield self.target_dir
            return

        for root, dirs, files in os.walk(self.target_dir):
            # Prune ignored directories in-place to speed up walk
            dirs[:] = [d for d in dirs if d not in self.ignored_parts]
            
            # Double check if root itself contains any ignored part
            if any(part in self.ignored_parts for part in Path(root).parts):
                continue
                
            try:
                rel_parts = Path(root).relative_to(self.target_dir).parts
            except ValueError:
                rel_parts = ()
                
            if any("test" in part.lower() for part in rel_parts):
                continue
                
            for file in files:
                if file.endswith(".py"):
                    if "test" not in Path(file).stem.lower():
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
                    tree,
                    str(file_path),
                    content,
                    self.module_trees,
                    self.module_name(file_path),
                    parent_maps=self.parent_maps,
                    node_trees=self.node_trees,
                    tree_modules=self.tree_modules,
                    site_packages_dir=self.site_packages_dir,
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

    def generate_sarif_report(self, output_path: str | Path) -> None:
        rules_metadata = {}
        for rule in self.rules:
            rules_metadata[rule.rule_id] = {
                "id": rule.rule_id,
                "name": rule.title,
                "shortDescription": {
                    "text": rule.description
                },
                "helpUri": "https://owasp.org/www-project-top-ten/"
            }
            
        results = []
        for vuln in self.results:
            vuln_path = Path(vuln.file_path)
            if self.target_dir.is_dir():
                rel_path = str(vuln_path.relative_to(self.target_dir)).replace("\\", "/")
            else:
                rel_path = vuln_path.name
                
            results.append({
                "ruleId": vuln.rule_id,
                "message": {
                    "text": vuln.description
                },
                "locations": [
                  {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": rel_path
                      },
                      "region": {
                        "startLine": vuln.line_no,
                        "startColumn": vuln.col_offset + 1 if vuln.col_offset >= 0 else 1
                      }
                    }
                  }
                ]
            })
            
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SaPyScan",
                            "semanticVersion": "1.1.0",
                            "rules": list(rules_metadata.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        
        Path(output_path).write_text(json.dumps(sarif_data, indent=4), encoding="utf-8")

    def autofix_files(self, findings: list[Vulnerability]) -> int:
        from collections import defaultdict
        files_map = defaultdict(list)
        for vuln in findings:
            if vuln.rule_id == "OWASP_A03_2021_SQLI":
                files_map[vuln.file_path].append(vuln)
                
        fixed_count = 0
        for file_path_str, file_vulns in files_map.items():
            file_path = Path(file_path_str)
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
                
            tree = ast.parse(content)
            
            candidates = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for vuln in file_vulns:
                        if node.lineno == vuln.line_no and node.col_offset == vuln.col_offset:
                            candidates.append((node, vuln))
                            break
                            
            if not candidates:
                continue
                
            candidates.sort(key=lambda x: x[0].lineno, reverse=True)
            
            modified_content = content
            for node, vuln in candidates:
                fixed_node = self._build_fixed_sql_node(node)
                if fixed_node:
                    replacement = ast.unparse(fixed_node)
                    modified_content = self._replace_node_text(modified_content, node, replacement)
                    fixed_count += 1
                    
            if modified_content != content:
                try:
                    file_path.write_text(modified_content, encoding="utf-8")
                except Exception:
                    pass
                    
        return fixed_count

    def _build_fixed_sql_node(self, node: ast.Call) -> ast.Call | None:
        if not node.args:
            return None
        first_arg = node.args[0]
        if isinstance(first_arg, ast.JoinedStr):
            try:
                sql_parts = []
                params = []
                i = 0
                elts = list(first_arg.values)
                while i < len(elts):
                    elt = elts[i]
                    if isinstance(elt, ast.Constant):
                        val = elt.value
                        if (
                            (val.endswith("'") or val.endswith('"'))
                            and i + 1 < len(elts)
                            and isinstance(elts[i + 1], ast.FormattedValue)
                            and i + 2 < len(elts)
                            and isinstance(elts[i + 2], ast.Constant)
                            and (elts[i + 2].value.startswith("'") or elts[i + 2].value.startswith('"'))
                        ):
                            sql_parts.append(val[:-1] + "%s")
                            params.append(elts[i + 1].value)
                            new_const = ast.Constant(value=elts[i + 2].value[1:])
                            elts[i + 2] = new_const
                            i += 2
                        else:
                            sql_parts.append(val)
                            i += 1
                    elif isinstance(elt, ast.FormattedValue):
                        sql_parts.append("%s")
                        params.append(elt.value)
                        i += 1
                    else:
                        i += 1
                        
                sql_text = "".join(sql_parts)
                new_args = [ast.Constant(value=sql_text)]
                if params:
                    if len(params) == 1:
                        new_args.append(ast.Tuple(elts=[params[0]], ctx=ast.Load()))
                    else:
                        new_args.append(ast.Tuple(elts=params, ctx=ast.Load()))
                        
                return ast.Call(
                    func=node.func,
                    args=new_args,
                    keywords=node.keywords
                )
            except Exception:
                pass
        return None

    def _replace_node_text(self, content: str, node: ast.AST, replacement: str) -> str:
        lines = content.splitlines(keepends=True)
        
        start_line = node.lineno - 1
        start_col = node.col_offset
        end_line = getattr(node, 'end_lineno', start_line + 1) - 1
        end_col = getattr(node, 'end_col_offset', start_col)
        
        first_line = lines[start_line]
        prefix = first_line[:start_col]
        
        last_line = lines[end_line]
        suffix = last_line[end_col:]
        
        new_text = prefix + replacement + suffix
        new_lines = lines[:start_line] + [new_text] + lines[end_line + 1:]
        return "".join(new_lines)

