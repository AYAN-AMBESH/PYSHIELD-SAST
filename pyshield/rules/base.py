import ast
from typing import List, Dict, Any

class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Vulnerability:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        description: str,
        file_path: str,
        line_no: int,
        col_offset: int,
        code_snippet: str,
        remediation: str
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.description = description
        self.file_path = file_path
        self.line_no = line_no
        self.col_offset = col_offset
        self.code_snippet = code_snippet
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "col_offset": self.col_offset,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation
        }

class BaseRule:
    """
    Base class for all SAST scanning rules.
    Rules can inspect the Abstract Syntax Tree (AST) or token streams.
    """
    rule_id: str = "BASE000"
    title: str = "Base Rule"
    severity: str = Severity.INFO
    description: str = "Base rule description."
    remediation: str = "Fix the issue."

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.parent_map = {}
        self.current_tree = None

    def build_parent_map(self, tree: ast.AST) -> dict:
        parent_map = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent
        return parent_map

    def get_variable_definition(self, node: ast.AST, var_name: str) -> ast.AST:
        # Trace up to find the enclosing FunctionDef or Module
        curr = node
        scope = None
        while curr in self.parent_map:
            curr = self.parent_map[curr]
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                scope = curr
                break
                
        if not scope:
            return None
            
        recent_assign = None
        for child in ast.walk(scope):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        if hasattr(child, 'lineno') and hasattr(node, 'lineno'):
                            if child.lineno < node.lineno:
                                if not recent_assign or child.lineno > recent_assign.lineno:
                                    recent_assign = child
            elif isinstance(child, ast.AnnAssign):
                if isinstance(child.target, ast.Name) and child.target.id == var_name:
                    if hasattr(child, 'lineno') and hasattr(node, 'lineno'):
                        if child.lineno < node.lineno:
                            if not recent_assign or child.lineno > recent_assign.lineno:
                                recent_assign = child
                                
        if recent_assign:
            if isinstance(recent_assign, ast.Assign):
                return recent_assign.value
            elif isinstance(recent_assign, ast.AnnAssign):
                return recent_assign.value
                
        return None

    def resolve_node_value(self, node: ast.AST, visited: set = None) -> ast.AST:
        if visited is None:
            visited = set()
            
        if isinstance(node, ast.Name):
            if node.id in visited:
                return node
            visited.add(node.id)
            
            def_val = self.get_variable_definition(node, node.id)
            if def_val:
                return self.resolve_node_value(def_val, visited)
                
        return node

    def is_dynamic_expression(self, node: ast.AST) -> bool:
        resolved = self.resolve_node_value(node)
        
        if isinstance(resolved, ast.Constant):
            return False
            
        if isinstance(resolved, ast.JoinedStr):
            for value in resolved.values:
                if isinstance(value, ast.FormattedValue):
                    if self.is_dynamic_expression(value.value):
                        return True
            return False
            
        if isinstance(resolved, ast.BinOp):
            if isinstance(resolved.op, ast.Add):
                return self.is_dynamic_expression(resolved.left) or self.is_dynamic_expression(resolved.right)
            elif isinstance(resolved.op, ast.Mod):
                return True
                
        if isinstance(resolved, ast.Call):
            if isinstance(resolved.func, ast.Attribute) and resolved.func.attr == "format":
                return True
            return True
            
        if isinstance(resolved, ast.Name):
            return True
            
        return True

    def check(self, tree: ast.AST, file_path: str, file_content: str) -> List[Vulnerability]:
        """
        Runs the rule checks on the AST and raw content.
        Must return list of Vulnerability objects.
        """
        self.vulnerabilities = []
        self.parent_map = self.build_parent_map(tree)
        self.current_tree = tree
        self.run(tree, file_path, file_content)
        return self.vulnerabilities

    def run(self, tree: ast.AST, file_path: str, file_content: str):
        """
        Override this in subclasses to implement logic.
        """
        pass

    def add_vuln(self, file_path: str, line_no: int, col_offset: int, file_content: str, detail: str = None):
        # Extract code snippet (context of 3 lines)
        lines = file_content.splitlines()
        snippet = ""
        if 0 <= line_no - 1 < len(lines):
            snippet = lines[line_no - 1].strip()

        desc = detail if detail else self.description

        vuln = Vulnerability(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=desc,
            file_path=file_path,
            line_no=line_no,
            col_offset=col_offset,
            code_snippet=snippet,
            remediation=self.remediation
        )
        self.vulnerabilities.append(vuln)
