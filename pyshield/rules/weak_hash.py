import ast
from .base import BaseRule, Severity

class WeakHashingCryptographyRule(BaseRule):
    rule_id = "OWASP_A02_2021_HASH"
    title = "Use of Weak Cryptographic Hash Function"
    severity = Severity.MEDIUM
    description = "Use of broken or weak cryptographic algorithms (such as MD5 or SHA1) was detected."
    remediation = "Use secure alternatives like SHA-256, SHA-3, or Argon2 / bcrypt for password hashing."

    WEAK_ALGORITHMS = {"md5", "sha1"}

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            # Check function calls (e.g., hashlib.md5(...))
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name.lower() in self.WEAK_ALGORITHMS:
                    # Verify if it's from hashlib
                    is_hashlib = False
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "hashlib":
                            is_hashlib = True
                    
                    # Alternatively, checking if we just imported md5/sha1 directly
                    # For simplicity, we flag any call matching md5 or sha1
                    self.add_vuln(
                        file_path=file_path,
                        line_no=node.lineno,
                        col_offset=node.col_offset,
                        file_content=file_content,
                        detail=f"Insecure cryptographic algorithm '{func_name}' is invoked. Use SHA-256 or stronger."
                    )
