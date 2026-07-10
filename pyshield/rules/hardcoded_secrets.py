import ast
from .base import BaseRule, Severity

class HardcodedPasswordsRule(BaseRule):
    rule_id = "SEC101"
    title = "Hardcoded Password / Key Detected"
    severity = Severity.HIGH
    description = "A hardcoded password, API key, or token was identified in the source code."
    remediation = "Use environment variables or a secret management system (e.g., HashiCorp Vault, AWS Secrets Manager) instead of hardcoding secrets."

    # Common variable names that might contain secrets
    SECRET_KEYWORDS = {
        "password", "passwd", "secret", "api_key", "apikey", 
        "token", "private_key", "access_key", "db_pass", "db_password"
    }

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            # Check variable assignments (e.g., password = "foo")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(keyword in name_lower for keyword in self.SECRET_KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val = node.value.value
                                # Ignore empty strings or placeholders
                                if len(val) > 4 and val not in {"placeholder", "your_password", "dummy"}:
                                    self.add_vuln(
                                        file_path=file_path,
                                        line_no=node.lineno,
                                        col_offset=node.col_offset,
                                        file_content=file_content,
                                        detail=f"Variable '{target.id}' is assigned a hardcoded string literal that appears to be a password or secret key."
                                    )
