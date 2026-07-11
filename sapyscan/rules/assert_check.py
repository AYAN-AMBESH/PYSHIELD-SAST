import ast
from .base import BaseRule, Severity

class AssertSecurityCheckRule(BaseRule):
    rule_id = "OWASP_A07_2021_ASSERT"
    title = "Use of assert for Security Check"
    severity = Severity.MEDIUM
    description = "Assert statements are compiled away when running Python in optimized mode (-O). Using assert for access control or security checks can allow bypasses."
    remediation = "Use standard if-statements and raise appropriate exceptions (e.g., PermissionError or ValueError) instead of assert statements."

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                self.add_vuln(
                    file_path=file_path,
                    line_no=node.lineno,
                    col_offset=node.col_offset,
                    file_content=file_content,
                    detail="Assert statement detected. If this is a security or access control check, it will be bypassed in optimized production environments (-O)."
                )
