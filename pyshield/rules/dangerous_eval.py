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
                        trace = self.build_taint_trace(node.args[0])
                        if trace.tainted:
                            self.add_tainted_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                trace=trace,
                                detail=f"Dangerous '{func_name}()' call detected with user-controlled input."
                            )
