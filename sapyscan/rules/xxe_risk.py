import ast
from .base import BaseRule, Severity

class XxeRiskRule(BaseRule):
    rule_id = "OWASP_A05_2021_XXE"
    title = "XML External Entity (XXE) Vulnerability"
    severity = Severity.HIGH
    description = "Insecure XML parsing allowing resolving of external entities can lead to SSRF or file disclosure."
    remediation = "Disable external entity resolution (e.g. resolve_entities=False in lxml XMLParser, or use defusedxml)."

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

                # Match lxml.etree.XMLParser / XMLParser
                if (module_name == "etree" and func_name == "XMLParser") or func_name == "XMLParser":
                    resolve_entities = True
                    for kw in node.keywords:
                        if kw.arg == "resolve_entities":
                            val = self.resolve_node_value(kw.value)
                            if isinstance(val, ast.Constant) and val.value is False:
                                resolve_entities = False
                    
                    if resolve_entities:
                        self.add_vuln(
                            file_path=file_path,
                            line_no=node.lineno,
                            col_offset=node.col_offset,
                            file_content=file_content,
                            detail="XMLParser initialized with external entity resolution enabled (resolve_entities=True or default)."
                        )
