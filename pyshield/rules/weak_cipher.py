import ast
from .base import BaseRule, Severity

class WeakCipherRule(BaseRule):
    rule_id = "OWASP_A02_2021_CIPHER"
    title = "Use of Weak Cryptographic Cipher"
    severity = Severity.HIGH
    description = "Obsolete or weak cryptographic algorithms (such as DES, RC4, Blowfish, ARC4) are vulnerable to decryption and attacks."
    remediation = "Use modern secure ciphers like AES-256 (e.g. from cryptography.hazmat.primitives.ciphers)."

    WEAK_CIPHERS = {"DES", "RC4", "Blowfish", "ARC4"}

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = node.names
                for name in names:
                    imported_name = name.name.split('.')[-1]
                    if imported_name in self.WEAK_CIPHERS:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail=f"Import of weak cryptographic cipher '{imported_name}' detected."
                        )
            elif isinstance(node, ast.Call):
                is_weak = False
                cipher_name = ""
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    if node.func.value.id in self.WEAK_CIPHERS:
                        is_weak = True
                        cipher_name = node.func.value.id
                elif isinstance(node.func, ast.Name) and node.func.id in self.WEAK_CIPHERS:
                    is_weak = True
                    cipher_name = node.func.id
                    
                if is_weak:
                    self.add_vuln(
                        file_path=file_path,
                        line_no=node.lineno,
                        col_offset=node.col_offset,
                        file_content=file_content,
                        detail=f"Insecure cryptographic cipher '{cipher_name}' is invoked."
                    )
