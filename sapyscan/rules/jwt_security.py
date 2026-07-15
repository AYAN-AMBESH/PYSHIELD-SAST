import ast
from .base import BaseRule, Severity

class JwtSecurityRule(BaseRule):
    rule_id = "OWASP_A02_2021_JWT"
    title = "Insecure JWT Verification"
    severity = Severity.HIGH
    description = "Decoding JWT tokens without signature verification or accepting 'none' algorithm is dangerous."
    remediation = "Ensure verify=True and do not allow the 'none' algorithm."

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

                if module_name == "jwt" and func_name == "decode":
                    # Check verify keyword
                    verify = True
                    algorithms_list = []
                    for kw in node.keywords:
                        if kw.arg == "verify":
                            val = self.resolve_node_value(kw.value)
                            if isinstance(val, ast.Constant) and val.value is False:
                                verify = False
                        elif kw.arg == "options":
                            val = self.resolve_node_value(kw.value)
                            if isinstance(val, ast.Dict):
                                for k, v in zip(val.keys, val.values):
                                    if isinstance(k, ast.Constant) and k.value == "verify_signature":
                                        res_v = self.resolve_node_value(v)
                                        if isinstance(res_v, ast.Constant) and res_v.value is False:
                                            verify = False
                        elif kw.arg == "algorithms":
                            val = self.resolve_node_value(kw.value)
                            if isinstance(val, ast.List):
                                for elt in val.elts:
                                    res_elt = self.resolve_node_value(elt)
                                    if isinstance(res_elt, ast.Constant) and isinstance(res_elt.value, str):
                                        algorithms_list.append(res_elt.value)
                            elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                                algorithms_list.append(val.value)

                    if not verify:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail="JWT decode called with verification disabled (verify=False)."
                        )
                    elif any(alg.lower() == "none" for alg in algorithms_list):
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail="JWT decode accepts 'none' algorithm, allowing token spoofing."
                        )
