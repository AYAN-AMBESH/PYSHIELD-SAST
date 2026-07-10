import ast
from .base import BaseRule, Severity

class PathTraversalRule(BaseRule):
    rule_id = "OWASP_A01_2021_PATH"
    title = "Potential Path Traversal"
    severity = Severity.HIGH
    description = "Use of raw concatenation or interpolation in file paths or using os.path.join with dynamic parameters without sanitization."
    remediation = "Sanitize paths using os.path.abspath and ensure it starts with the intended directory prefix, or use pathlib.Path.resolve()."

    FILE_FUNCTIONS = {"open", "File", "open_file"}

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

                # Case 1: Builtin open() or os.open or open() called with dynamic/concatenated string
                if (func_name in self.FILE_FUNCTIONS and not module_name) or (module_name == "os" and func_name == "open"):
                    if node.args:
                        first_arg = node.args[0]
                        resolved = self.resolve_node_value(first_arg)
                        
                        is_unsafe = False
                        detail_msg = ""
                        
                        if isinstance(resolved, ast.JoinedStr):
                            is_unsafe = True
                            detail_msg = "File path constructed dynamically using f-string formatting inside file open call."
                        elif isinstance(resolved, ast.BinOp) and isinstance(resolved.op, ast.Add):
                            if self.is_dynamic_expression(resolved):
                                is_unsafe = True
                                detail_msg = "File path constructed dynamically using string concatenation (+) inside file open call."
                        elif isinstance(resolved, ast.BinOp) and isinstance(resolved.op, ast.Mod):
                            is_unsafe = True
                            detail_msg = "File path constructed dynamically using '%' operator interpolation inside file open call."
                        elif isinstance(resolved, ast.Call):
                            if isinstance(resolved.func, ast.Attribute) and resolved.func.attr == "format":
                                is_unsafe = True
                                detail_msg = "File path constructed dynamically using '.format()' method inside file open call."
                        
                        if is_unsafe:
                            self.add_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                detail=detail_msg
                            )
