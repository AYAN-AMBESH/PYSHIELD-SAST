import ast
import re
from .base import BaseRule, Severity

class RedosRiskRule(BaseRule):
    rule_id = "OWASP_A05_2021_REDOS"
    title = "Regular Expression DoS (ReDoS) Risk"
    severity = Severity.MEDIUM
    description = "Vulnerable regular expressions with nested quantifiers can cause catastrophic backtracking."
    remediation = "Rewrite the regular expression to avoid overlapping/nested quantifiers like (a+)+ or (.*)*."

    # Heuristic for nested quantifiers
    SUSPICIOUS_REGEX = [
        r"\([^)]*[\+\*][^)]*\)[\+\*]",
        r"\([^)]*\{\d*,?\d*\}[^)]*\)[\+\*]"
    ]

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                module_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        module_name = node.func.value.id
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if module_name == "re" and func_name in {"compile", "match", "search", "findall", "finditer", "sub"}:
                    if node.args:
                        val = self.resolve_node_value(node.args[0])
                        if isinstance(val, ast.Constant) and isinstance(val.value, str):
                            pattern = val.value
                            for r in self.SUSPICIOUS_REGEX:
                                if re.search(r, pattern):
                                    self.add_vuln(
                                        file_path=file_path,
                                        line_no=node.lineno,
                                        col_offset=node.col_offset,
                                        file_content=file_content,
                                        detail=f"Potential ReDoS vulnerability: regex pattern '{pattern}' contains nested/overlapping quantifiers."
                                    )
                                    break
