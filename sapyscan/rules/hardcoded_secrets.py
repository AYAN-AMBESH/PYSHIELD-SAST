import ast
import re
from .base import BaseRule, Severity

class HardcodedPasswordsRule(BaseRule):
    rule_id = "OWASP_A07_2021_SECRET"
    title = "Hardcoded Password / Key Detected"
    severity = Severity.HIGH
    description = "A hardcoded password, API key, or token was identified in the source code."
    remediation = "Use environment variables or a secret management system (e.g., HashiCorp Vault, AWS Secrets Manager) instead of hardcoding secrets."

    # Common variable names that might contain secrets
    SECRET_KEYWORDS = {
        "password", "passwd", "secret", "api_key", "apikey", 
        "token", "private_key", "access_key", "db_pass", "db_password",
        "aws_key", "aws_secret", "ssh_key", "key_secret", "auth_token", "jwt",
        "client_secret", "client_key"
    }

    # Common API key patterns
    SECRET_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
        (re.compile(r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{82}'), "GitHub Personal Access Token"),
        (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack Token"),
    ]

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        for node in ast.walk(tree):
            # Check variable assignments (e.g., password = "foo")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        # Match name keywords
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
                                    continue
                        
                        # Match values against patterns
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            for pattern, desc in self.SECRET_PATTERNS:
                                if pattern.search(val):
                                    self.add_vuln(
                                        file_path=file_path,
                                        line_no=node.lineno,
                                        col_offset=node.col_offset,
                                        file_content=file_content,
                                        detail=f"Hardcoded {desc} detected in variable assignment."
                                    )
                                    break
            
            # Check function defaults, e.g., def connect(password="secret"):
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                # Check normal positional/keyword arguments defaults
                if args.defaults:
                    num_defaults = len(args.defaults)
                    relevant_args = args.args[-num_defaults:]
                    for arg, default in zip(relevant_args, args.defaults):
                        if isinstance(default, ast.Constant) and isinstance(default.value, str):
                            arg_name_lower = arg.arg.lower()
                            val = default.value
                            if len(val) > 4 and val not in {"placeholder", "your_password", "dummy"}:
                                if any(keyword in arg_name_lower for keyword in self.SECRET_KEYWORDS):
                                    self.add_vuln(
                                        file_path=file_path,
                                        line_no=node.lineno,
                                        col_offset=node.col_offset,
                                        file_content=file_content,
                                        detail=f"Function '{node.name}' has a default argument value for '{arg.arg}' that appears to be a hardcoded password or secret key."
                                    )
                                    continue
                                
                                for pattern, desc in self.SECRET_PATTERNS:
                                    if pattern.search(val):
                                        self.add_vuln(
                                            file_path=file_path,
                                            line_no=node.lineno,
                                            col_offset=node.col_offset,
                                            file_content=file_content,
                                            detail=f"Function '{node.name}' has a default argument value for '{arg.arg}' containing a hardcoded {desc}."
                                        )
                                        break
                
                # Check keyword-only arguments defaults
                if args.kwonlyargs and args.kw_defaults:
                    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                        if default and isinstance(default, ast.Constant) and isinstance(default.value, str):
                            arg_name_lower = arg.arg.lower()
                            val = default.value
                            if len(val) > 4 and val not in {"placeholder", "your_password", "dummy"}:
                                if any(keyword in arg_name_lower for keyword in self.SECRET_KEYWORDS):
                                    self.add_vuln(
                                        file_path=file_path,
                                        line_no=node.lineno,
                                        col_offset=node.col_offset,
                                        file_content=file_content,
                                        detail=f"Function '{node.name}' has a keyword-only default argument value for '{arg.arg}' that appears to be a hardcoded password or secret key."
                                    )
                                    continue
                                    
                                for pattern, desc in self.SECRET_PATTERNS:
                                    if pattern.search(val):
                                        self.add_vuln(
                                            file_path=file_path,
                                            line_no=node.lineno,
                                            col_offset=node.col_offset,
                                            file_content=file_content,
                                            detail=f"Function '{node.name}' has a keyword-only default argument value for '{arg.arg}' containing a hardcoded {desc}."
                                        )
                                        break
