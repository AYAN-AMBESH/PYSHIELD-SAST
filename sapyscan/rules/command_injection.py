import ast
from .base import BaseRule, Severity

class CommandInjectionRule(BaseRule):
    rule_id = "OWASP_A03_2021_CMD"
    title = "Potential Command Injection"
    severity = Severity.HIGH
    description = "Use of os.system, subprocess.Popen, or subprocess.run with shell=True and dynamic variables can lead to Command Injection."
    remediation = "Avoid shell=True. Pass arguments as a list, or sanitize inputs using shlex.quote."

    DANGEROUS_FUNCTIONS = {"system", "popen", "run", "call", "check_output"}

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

                # Case 1: os.system(...) or execute_in_shell(...)
                if (module_name == "os" and func_name == "system") or func_name == "execute_in_shell":
                    if node.args:
                        trace = self.build_taint_trace(node.args[0])
                        if trace.tainted:
                            self.add_tainted_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            trace=trace,
                            detail=f"Use of '{func_name}()' with user-controlled input can lead to command injection."
                        )

                # Case 2: subprocess calls with shell=True
                elif module_name == "subprocess" or func_name in self.DANGEROUS_FUNCTIONS:
                    # Check keywords for shell=True
                    has_shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                has_shell_true = True
                    
                    if has_shell_true and node.args:
                        trace = self.build_taint_trace(node.args[0])
                        if trace.tainted:
                            self.add_tainted_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                trace=trace,
                                detail="subprocess call detected with 'shell=True'. This is a high-risk vector for command injection."
                            )
