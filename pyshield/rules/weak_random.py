import ast
from .base import BaseRule, Severity

class WeakRandomGeneratorRule(BaseRule):
    rule_id = "OWASP_A04_2021_RANDOM"
    title = "Use of Weak Pseudo-Random Number Generator"
    severity = Severity.MEDIUM
    description = "Standard pseudo-random generators (like the random module) are predictable and should not be used for security purposes."
    remediation = "Use the secrets module (e.g., secrets.token_bytes or secrets.token_hex) for cryptographically secure random number generation."

    DANGEROUS_FUNCTIONS = {"random", "randint", "choice", "randrange", "uniform"}

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

                is_weak = False
                if module_name == "random" and func_name in self.DANGEROUS_FUNCTIONS:
                    is_weak = True
                elif func_name == "random" and not module_name:
                    is_weak = True
                    
                if is_weak:
                    self.add_vuln(
                        file_path=file_path,
                        line_no=node.lineno,
                        col_offset=node.col_offset,
                        file_content=file_content,
                        detail=f"Standard pseudo-random number generator function '{func_name}' invoked. Use the 'secrets' module instead for cryptographically secure purposes."
                    )
