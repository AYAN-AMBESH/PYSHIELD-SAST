import ast
from .base import BaseRule, Severity

class FlaskDebugModeRule(BaseRule):
    rule_id = "OWASP_A05_2021_DEBUG"
    title = "Flask Debug Mode Enabled"
    severity = Severity.HIGH
    description = "Running Flask applications with debug=True enables the interactive debugger, which can allow arbitrary code execution in production."
    remediation = "Set debug=False in production configurations or use environment variables (FLASK_DEBUG=0) to control debug mode."

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name == "run":
                    for kw in node.keywords:
                        if kw.arg == "debug":
                            resolved = self.resolve_node_value(kw.value)
                            if isinstance(resolved, ast.Constant) and resolved.value is True:
                                self.add_vuln(
                                    file_path=file_path,
                                    line_no=node.lineno,
                                    col_offset=node.col_offset,
                                    file_content=file_content,
                                    detail="Flask application run with 'debug=True' configuration enabled."
                                )
