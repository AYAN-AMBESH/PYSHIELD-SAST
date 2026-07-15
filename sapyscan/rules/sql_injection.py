import ast
from .base import BaseRule, Severity

class SqlInjectionRule(BaseRule):
    rule_id = "OWASP_A03_2021_SQLI"
    title = "Potential SQL Injection"
    severity = Severity.HIGH
    description = "Dynamic SQL string construction using string formatting or concatenation rather than parameterized queries."
    remediation = "Always use parameterized queries/prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of formatting variables directly into strings."

    SQL_METHODS = {"execute", "executemany", "sql"}

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in self.SQL_METHODS:
                    if node.args:
                        first_arg = node.args[0]
                        resolved = self.resolve_node_value(first_arg)
                        
                        is_unsafe = False
                        detail_msg = ""
                        trace = self.build_taint_trace(first_arg)
                        
                        if isinstance(resolved, ast.JoinedStr) and trace.tainted:
                            is_unsafe = True
                            detail_msg = "SQL query constructed dynamically using f-string formatting."
                        elif (
                            isinstance(resolved, ast.BinOp)
                            and isinstance(resolved.op, ast.Mod)
                            and trace.tainted
                        ):
                            is_unsafe = True
                            detail_msg = "SQL query constructed dynamically using '%' operator interpolation."
                        elif isinstance(resolved, ast.BinOp) and isinstance(resolved.op, ast.Add):
                            if trace.tainted:
                                is_unsafe = True
                                detail_msg = "SQL query constructed dynamically using string concatenation (+)."
                        elif isinstance(resolved, ast.Call):
                            if (
                                isinstance(resolved.func, ast.Attribute)
                                and resolved.func.attr == "format"
                                and trace.tainted
                            ):
                                is_unsafe = True
                                detail_msg = "SQL query constructed dynamically using '.format()' method."
                        
                        if is_unsafe:
                            self.add_tainted_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                trace=trace,
                                detail=detail_msg
                            )
