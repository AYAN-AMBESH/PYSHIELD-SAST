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

    def check(self, tree: ast.AST, file_path: str, file_content: str) -> List[Vulnerability]:
        """
        Runs the rule checks on the AST and raw content.
        Must return list of Vulnerability objects.
        """
        self.vulnerabilities = []
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
