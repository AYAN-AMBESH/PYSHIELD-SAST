import ast
from .base import BaseRule, Severity

class DangerousEvalExecRule(BaseRule):
    rule_id = "OWASP_A03_2021_EVAL"
    title = "Dangerous Use of eval/exec"
    severity = Severity.HIGH
    description = "Use of eval() or exec() with dynamic inputs can allow arbitrary code execution."
    remediation = "Avoid using eval() or exec(). Use safer alternatives like json.loads, ast.literal_eval, or structured configuration parsing."

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name in {"eval", "exec"}:
                    if node.args:
                        resolved = self.resolve_node_value(node.args[0])
                        is_dynamic = self.is_dynamic_expression(resolved)
                        
                        detail_msg = f"Use of '{func_name}()' detected. If inputs are user-controlled, this allows remote code execution."
                        if is_dynamic:
                            detail_msg = f"Dangerous '{func_name}()' call detected with dynamic string expression."
                            
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail=detail_msg
                        )
