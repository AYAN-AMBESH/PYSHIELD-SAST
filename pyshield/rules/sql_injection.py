import ast
from .base import BaseRule, Severity

class SqlInjectionRule(BaseRule):
    rule_id = "SEC104"
    title = "Potential SQL Injection"
    severity = Severity.HIGH
    description = "Dynamic SQL string construction using string formatting or concatenation rather than parameterized queries."
    remediation = "Always use parameterized queries/prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of formatting variables directly into strings."

    SQL_METHODS = {"execute", "executemany"}

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
                        # Check if first arg is dynamic (JoinedStr/FormattedValue, BinOp with '%', or Call to 'format')
                        is_unsafe = False
                        detail_msg = ""
                        
                        if isinstance(first_arg, ast.JoinedStr):  # f-string: f"SELECT ... {var}"
                            is_unsafe = True
                            detail_msg = "SQL query constructed dynamically using f-string formatting."
                        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):  # "SELECT ... %s" % var
                            is_unsafe = True
                            detail_msg = "SQL query constructed dynamically using '%' operator interpolation."
                        elif isinstance(first_arg, ast.Call):
                            # check if it is string.format(...)
                            if isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                                is_unsafe = True
                                detail_msg = "SQL query constructed dynamically using '.format()' method."
                        
                        if is_unsafe:
                            self.add_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                detail=detail_msg
                            )
