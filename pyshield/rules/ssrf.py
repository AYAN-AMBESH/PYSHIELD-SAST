import ast
from .base import BaseRule, Severity

class SsrfRequestRule(BaseRule):
    rule_id = "OWASP_A10_2021_SSRF"
    title = "Potential Server-Side Request Forgery"
    severity = Severity.MEDIUM
    description = "Making HTTP requests to URLs constructed dynamically with user-controlled parameters can lead to Server-Side Request Forgery (SSRF)."
    remediation = "Validate and whitelist destination URLs. Avoid constructing request destinations directly from raw user inputs."

    HTTP_FUNCTIONS = {"get", "post", "put", "delete", "request", "urlopen"}
    HTTP_MODULES = {"requests", "urllib", "urllib3", "http"}

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

                if func_name in self.HTTP_FUNCTIONS:
                    is_http_call = False
                    if module_name in self.HTTP_MODULES:
                        is_http_call = True
                    elif not module_name and func_name == "urlopen":
                        is_http_call = True
                        
                    if is_http_call and node.args:
                        first_arg = node.args[0]
                        trace = self.build_taint_trace(first_arg)
                        if trace.tainted:
                            self.add_tainted_vuln(
                                file_path=file_path,
                                line_no=node.lineno,
                                col_offset=node.col_offset,
                                file_content=file_content,
                                trace=trace,
                                detail="HTTP request destination URL is constructed dynamically, presenting a potential SSRF risk."
                            )
