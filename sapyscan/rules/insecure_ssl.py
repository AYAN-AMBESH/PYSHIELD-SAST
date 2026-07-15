import ast
from .base import BaseRule, Severity

class InsecureSslTlsRule(BaseRule):
    rule_id = "OWASP_A05_2021_SSL"
    title = "Insecure SSL/TLS Configuration"
    severity = Severity.HIGH
    description = "Disabling SSL/TLS certificate verification or using obsolete protocol versions (SSLv2, SSLv3, TLSv1, TLSv1.1) exposes connections to man-in-the-middle (MITM) attacks."
    remediation = "Enable certificate verification (verify=True or do not set verify=False). Use modern TLS protocol versions (TLSv1.2, TLSv1.3)."

    WEAK_PROTOCOLS = {
        "PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"
    }

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

                # Case 1: requests.get/post/request(..., verify=False)
                # Exclude jwt.decode calls from SSL verification warnings
                if not (module_name == "jwt" and func_name == "decode"):
                    for kw in node.keywords:
                        if kw.arg == "verify":
                            resolved = self.resolve_node_value(kw.value)
                            if isinstance(resolved, ast.Constant) and resolved.value is False:
                                self.add_vuln(
                                    file_path=file_path,
                                    line_no=node.lineno,
                                    col_offset=node.col_offset,
                                    file_content=file_content,
                                    detail="SSL certificate verification is explicitly disabled (verify=False)."
                                )
                        elif kw.arg == "cert_reqs":
                            resolved = self.resolve_node_value(kw.value)
                            if isinstance(resolved, ast.Attribute) and resolved.attr == "CERT_NONE":
                                self.add_vuln(
                                    file_path=file_path,
                                    line_no=node.lineno,
                                    col_offset=node.col_offset,
                                    file_content=file_content,
                                    detail="SSL certificate requirements are set to CERT_NONE, disabling verification."
                                )
                            elif isinstance(resolved, ast.Name) and resolved.id == "CERT_NONE":
                                self.add_vuln(
                                    file_path=file_path,
                                    line_no=node.lineno,
                                    col_offset=node.col_offset,
                                    file_content=file_content,
                                    detail="SSL certificate requirements are set to CERT_NONE, disabling verification."
                                )

            # Case 2: Attribute access to weak protocols, e.g. ssl.PROTOCOL_SSLv2
            elif isinstance(node, ast.Attribute):
                if node.attr in self.WEAK_PROTOCOLS:
                    is_ssl = False
                    if isinstance(node.value, ast.Name) and node.value.id == "ssl":
                        is_ssl = True
                    if is_ssl:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail=f"Insecure SSL/TLS protocol version '{node.attr}' referenced."
                        )
