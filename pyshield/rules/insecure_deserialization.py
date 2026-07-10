import ast
from .base import BaseRule, Severity

class InsecureDeserializationRule(BaseRule):
    rule_id = "SEC106"
    title = "Insecure Deserialization Detected"
    severity = Severity.CRITICAL
    description = "Use of unsafe deserialization libraries (pickle, marshal, shelve, or yaml.load) can lead to arbitrary code execution."
    remediation = "Avoid using pickle or marshal for untrusted data. Use safer serialization formats like JSON. For PyYAML, always use yaml.safe_load() or specify Loader=yaml.SafeLoader."

    DANGEROUS_MODULES = {"pickle", "_pickle", "cPickle", "marshal", "shelve"}

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

                # Pickle / Marshal / Shelve
                if module_name in self.DANGEROUS_MODULES:
                    if func_name in {"load", "loads", "open"}:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail=f"Insecure deserialization via '{module_name}.{func_name}()' detected. This can lead to remote code execution."
                        )

                # PyYAML yaml.load
                elif (module_name == "yaml" and func_name in {"load", "unsafe_load"}) or func_name == "unsafe_load":
                    is_unsafe = True
                    if func_name == "load":
                        for kw in node.keywords:
                            if kw.arg == "Loader":
                                resolved = self.resolve_node_value(kw.value)
                                if isinstance(resolved, ast.Attribute):
                                    if resolved.attr == "SafeLoader" and isinstance(resolved.value, ast.Name) and resolved.value.id == "yaml":
                                        is_unsafe = False
                                elif isinstance(resolved, ast.Name) and resolved.id == "SafeLoader":
                                    is_unsafe = False
                    
                    if is_unsafe:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail="Use of unsafe 'yaml.load()' or 'yaml.unsafe_load()' without SafeLoader. This can allow remote code execution."
                        )
