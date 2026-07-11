import ast
from .base import BaseRule, Severity

class XssInsecureHttpResponseRule(BaseRule):
    rule_id = "OWASP_A03_2021_XSS"
    title = "Reflected XSS / Insecure HTTP Response"
    severity = Severity.HIGH
    description = "Returning unescaped user-controlled inputs or rendering templates with autoescape turned off."
    remediation = "Ensure proper context-aware HTML escaping is applied to all user input before outputting it. Enable autoescaping in template engines."

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            # Flag Flask render_template_string or raw Response wrappers
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name == "render_template_string":
                    # Rendering templates from dynamic strings is a huge XSS risk
                    if node.args:
                        trace = self.build_taint_trace(node.args[0])
                        if trace.tainted:
                            self.add_tainted_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            trace=trace,
                            detail="Flask template rendering receives user-controlled content."
                        )
                
                # Flag Markup(html) with string formatting or concatenation (unsafe bypasses)
                elif func_name == "Markup":
                    is_unsafe = False
                    if node.args:
                        first_arg = node.args[0]
                        trace = self.build_taint_trace(first_arg)
                        if trace.tainted:
                            is_unsafe = True
                    if is_unsafe:
                        self.add_tainted_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            trace=trace,
                            detail="Bypassing safety checks using 'Markup()' with dynamically formatted inputs can introduce Cross-Site Scripting (XSS)."
                        )
