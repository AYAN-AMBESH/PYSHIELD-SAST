from __future__ import annotations
import ast
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass(frozen=True)
class Vulnerability:
    rule_id: str
    title: str
    severity: Severity
    description: str
    file_path: str
    line_no: int
    col_offset: int
    code_snippet: str
    remediation: str
    data_flow: list[str] = field(default_factory=list)
    taint_source: str = ""
    assessment: str = "needs_review"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


@dataclass(frozen=True)
class TaintTrace:
    tainted: bool
    steps: tuple[str, ...] = ()
    source: str = "unknown"
    assessment: str = "needs_review"


class BaseRule:
    """
    Base class for all SAST scanning rules.
    Rules can inspect the Abstract Syntax Tree (AST) or token streams.
    """
    rule_id: str = "BASE000"
    title: str = "Base Rule"
    severity: Severity = Severity.INFO
    description: str = "Base rule description."
    remediation: str = "Fix the issue."

    def __init__(self) -> None:
        self.vulnerabilities: list[Vulnerability] = []
        self.parent_map: dict[ast.AST, ast.AST] = {}
        self.current_tree: ast.AST | None = None
        self.module_trees: dict[str, ast.Module] = {}
        self.tree_modules: dict[ast.Module, str] = {}
        self.parent_maps: dict[ast.Module, dict[ast.AST, ast.AST]] = {}
        self.node_trees: dict[ast.AST, ast.Module] = {}

    def build_parent_map(self, tree: ast.AST) -> dict[ast.AST, ast.AST]:
        parent_map: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent
        return parent_map

    @staticmethod
    def describe_node(node: ast.AST) -> str:
        try:
            rendered = ast.unparse(node)
        except Exception:
            rendered = node.__class__.__name__
        rendered = " ".join(rendered.split())
        return rendered if len(rendered) <= 120 else f"{rendered[:117]}..."

    @staticmethod
    def _prepend_trace(step: str, trace: TaintTrace, source: str | None = None, assessment: str | None = None) -> TaintTrace:
        return TaintTrace(
            tainted=True,
            steps=(step, *trace.steps),
            source=source or trace.source,
            assessment=assessment or trace.assessment,
        )

    def build_taint_trace(self, node: ast.AST, visited: set[int] | None = None) -> TaintTrace:
        if visited is None:
            visited = set()

        node_id = id(node)
        if node_id in visited:
            return TaintTrace(False)
        visited.add(node_id)

        if isinstance(node, ast.Name):
            definition = self.get_variable_definition(node, node.id)
            if definition is not None:
                trace = self.build_taint_trace(definition, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(f"{node.id} <- {self.describe_node(definition)}", trace)

            parameter_trace = self.trace_function_parameter(node.id, node)
            if parameter_trace is not None:
                return parameter_trace
            return TaintTrace(False)

        if isinstance(node, ast.Constant):
            return TaintTrace(False)

        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    trace = self.build_taint_trace(value.value, visited.copy())
                    if trace.tainted:
                        return self._prepend_trace(
                            f"f-string interpolation: {self.describe_node(value.value)}",
                            trace,
                        )
            return TaintTrace(False)

        if isinstance(node, ast.BinOp):
            left_trace = self.build_taint_trace(node.left, visited.copy())
            if left_trace.tainted:
                return self._prepend_trace(
                    f"left side of {type(node.op).__name__} concatenation",
                    left_trace,
                )

            right_trace = self.build_taint_trace(node.right, visited.copy())
            if right_trace.tainted:
                return self._prepend_trace(
                    f"right side of {type(node.op).__name__} concatenation",
                    right_trace,
                )
            return TaintTrace(False)

        if isinstance(node, ast.BoolOp):
            for index, value in enumerate(node.values):
                trace = self.build_taint_trace(value, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(
                        f"{type(node.op).__name__.lower()} operand {index + 1}",
                        trace,
                    )
            return TaintTrace(False)

        if isinstance(node, ast.IfExp):
            test_trace = self.build_taint_trace(node.test, visited.copy())
            if test_trace.tainted:
                return self._prepend_trace("conditional test", test_trace)

            body_trace = self.build_taint_trace(node.body, visited.copy())
            if body_trace.tainted:
                return self._prepend_trace("conditional true branch", body_trace)

            orelse_trace = self.build_taint_trace(node.orelse, visited.copy())
            if orelse_trace.tainted:
                return self._prepend_trace("conditional false branch", orelse_trace)

            return TaintTrace(False)

        if isinstance(node, ast.NamedExpr):
            return self.build_taint_trace(node.value, visited.copy())

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                trace = self.build_taint_trace(element, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(
                        f"{type(node).__name__.lower()} element {self.describe_node(element)}",
                        trace,
                    )
            return TaintTrace(False)

        if isinstance(node, ast.Dict):
            for value in node.values:
                if value is None:
                    continue
                trace = self.build_taint_trace(value, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(
                        f"dict value {self.describe_node(value)}",
                        trace,
                    )
            return TaintTrace(False)

        if isinstance(node, ast.Subscript):
            trace = self.build_taint_trace(node.value, visited.copy())
            if trace.tainted:
                return self._prepend_trace(f"subscript access on {self.describe_node(node.value)}", trace)
            return TaintTrace(False)

        if isinstance(node, ast.Attribute):
            if self.is_external_source(node):
                return TaintTrace(
                    True,
                    (self.describe_node(node),),
                    source="external_source",
                    assessment="confirmed",
                )

            trace = self.build_taint_trace(node.value, visited.copy())
            if trace.tainted:
                return self._prepend_trace(
                    f"attribute access .{node.attr}",
                    trace,
                )
            return TaintTrace(False)

        if isinstance(node, ast.Call):
            if self.is_input_call(node) or (
                isinstance(node.func, ast.Attribute) and self.is_external_source(node.func.value)
            ):
                return TaintTrace(
                    True,
                    (self.describe_node(node),),
                    source="external_input",
                    assessment="confirmed",
                )

            function = self.get_called_function(node)
            if function:
                for return_node in ast.walk(function):
                    if isinstance(return_node, ast.Return) and return_node.value is not None:
                        trace = self.build_taint_trace(return_node.value, visited.copy())
                        if trace.tainted:
                            return self._prepend_trace(
                                f"return value from {function.name}()",
                                trace,
                            )

            for value in [*node.args, *(keyword.value for keyword in node.keywords)]:
                trace = self.build_taint_trace(value, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(
                        f"call argument in {self.describe_node(node.func)}",
                        trace,
                    )

            if isinstance(node.func, ast.Attribute):
                trace = self.build_taint_trace(node.func.value, visited.copy())
                if trace.tainted:
                    return self._prepend_trace(
                        f"call receiver for {node.func.attr}",
                        trace,
                    )

            return TaintTrace(False)

        return TaintTrace(False)

    def get_variable_definition(self, node: ast.AST, var_name: str) -> ast.AST | None:
        # Trace up to find the enclosing FunctionDef or Module
        curr = node
        scope = None
        while (parent := self.get_parent(curr)) is not None:
            curr = parent
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

    def resolve_node_value(self, node: ast.AST, visited: set[str] | None = None) -> ast.AST:
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

    def is_tainted(self, node: ast.AST, visited: set[ast.AST] | None = None) -> bool:
        """Return whether an expression can originate from external input."""
        return self.build_taint_trace(node).tainted

    def is_function_parameter(
        self, var_name: str, node: ast.AST, visited: set[ast.AST]
    ) -> bool:
        function = self.get_enclosing_function(node)
        if function is None:
            return False

        parameters = self.get_function_parameters(function)
        try:
            parameter_index = next(
                index for index, parameter in enumerate(parameters) if parameter.arg == var_name
            )
        except StopIteration:
            return False

        arguments = [
            argument
            for call in self.get_function_calls(function)
            if (argument := self.get_call_argument(call, parameters, parameter_index)) is not None
        ]
        if not arguments:
            return True
        return any(self.is_tainted(argument, visited.copy()) for argument in arguments)

    def get_called_function(self, node: ast.Call) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        tree = self.get_tree(node)
        if tree is None:
            return None

        if isinstance(node.func, ast.Name):
            return self.find_function(tree, node.func.id) or self.find_imported_function(
                tree, node.func.id
            )

        if isinstance(node.func, ast.Attribute):
            module = self.get_imported_module(tree, node.func.value)
            if module:
                return self.find_function(module, node.func.attr)
            class_definition = self.get_receiver_class(tree, node.func.value)
            if class_definition:
                return self.find_method(class_definition, node.func.attr)

        return None

    def get_enclosing_function(
        self, node: ast.AST
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        scope = node
        while (parent := self.get_parent(scope)) is not None:
            scope = parent
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return scope
        return None

    @staticmethod
    def get_function_parameters(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[ast.arg]:
        arguments = function.args
        parameters = [
            *getattr(arguments, "posonlyargs", []),
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        if arguments.vararg:
            parameters.append(arguments.vararg)
        if arguments.kwarg:
            parameters.append(arguments.kwarg)
        return parameters

    def get_function_calls(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
        return [
            node
            for tree in self.module_trees.values()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and self.get_called_function(node) is function
        ]

    def get_call_argument(
        self,
        call: ast.Call,
        parameters: list[ast.arg],
        parameter_index: int,
    ) -> ast.AST | None:
        function = self.get_called_function(call)
        if (
            function
            and isinstance(call.func, ast.Attribute)
            and self.get_enclosing_class(function) is not None
        ):
            parameter_index -= 1
        if 0 <= parameter_index < len(call.args):
            return call.args[parameter_index]
        if parameter_index < 0:
            return None
        parameter_name = parameters[parameter_index].arg
        return next(
            (keyword.value for keyword in call.keywords if keyword.arg == parameter_name),
            None,
        )

    def trace_function_parameter(
        self,
        var_name: str,
        node: ast.AST,
    ) -> TaintTrace | None:
        function = self.get_enclosing_function(node)
        if function is None:
            return None

        parameters = self.get_function_parameters(function)
        try:
            parameter_index = next(
                index for index, parameter in enumerate(parameters) if parameter.arg == var_name
            )
        except StopIteration:
            return None

        calls = self.get_function_calls(function)
        if not calls:
            return TaintTrace(
                True,
                (f"{var_name} is a parameter of {function.name}() with no resolved call sites",),
                source="parameter",
                assessment="needs_review",
            )

        for call in calls:
            argument = self.get_call_argument(call, parameters, parameter_index)
            if argument is None:
                continue

            trace = self.build_taint_trace(argument, visited=set())
            if trace.tainted:
                return self._prepend_trace(
                    f"{var_name} is a parameter of {function.name}()",
                    trace,
                )

        return None

    def get_parent(self, node: ast.AST) -> ast.AST | None:
        tree = self.get_tree(node)
        return self.parent_maps.get(tree, {}).get(node) if tree else None

    def get_tree(self, node: ast.AST) -> ast.Module | None:
        return self.node_trees.get(node)

    def find_function(
        self, tree: ast.Module, name: str
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        return next(
            (
                function
                for function in tree.body
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name == name
            ),
            None,
        )

    @staticmethod
    def find_method(
        class_definition: ast.ClassDef, name: str
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        return next(
            (
                method
                for method in class_definition.body
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name == name
            ),
            None,
        )

    @staticmethod
    def find_class(tree: ast.Module, name: str) -> ast.ClassDef | None:
        return next(
            (
                class_definition
                for class_definition in tree.body
                if isinstance(class_definition, ast.ClassDef) and class_definition.name == name
            ),
            None,
        )

    def find_imported_function(
        self, tree: ast.Module, name: str
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    if (alias.asname or alias.name) == name:
                        module = self.resolve_module(tree, statement.module, statement.level)
                        if module:
                            return self.find_function(module, alias.name)
        return None

    def get_imported_module(self, tree: ast.Module, value: ast.AST) -> ast.Module | None:
        if not isinstance(value, ast.Name):
            return None
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if (alias.asname or alias.name.split(".")[0]) == value.id:
                        return self.module_trees.get(alias.name)
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    if (alias.asname or alias.name) == value.id:
                        return self.resolve_module(
                            tree, f"{statement.module}.{alias.name}", statement.level
                        )
        return None

    def get_receiver_class(self, tree: ast.Module, value: ast.AST) -> ast.ClassDef | None:
        if isinstance(value, ast.Call):
            return self.get_constructor_class(tree, value.func)
        if not isinstance(value, ast.Name):
            return None
        definition = self.get_variable_definition(value, value.id)
        if isinstance(definition, ast.Call):
            return self.get_constructor_class(tree, definition.func)
        return self.find_class(tree, value.id) or self.find_imported_class(tree, value.id)

    def get_constructor_class(self, tree: ast.Module, node: ast.AST) -> ast.ClassDef | None:
        if isinstance(node, ast.Name):
            return self.find_class(tree, node.id) or self.find_imported_class(tree, node.id)
        if isinstance(node, ast.Attribute):
            module = self.get_imported_module(tree, node.value)
            if module:
                return self.find_class(module, node.attr)
        return None

    def find_imported_class(self, tree: ast.Module, name: str) -> ast.ClassDef | None:
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    if (alias.asname or alias.name) == name:
                        module = self.resolve_module(tree, statement.module, statement.level)
                        if module:
                            return self.find_class(module, alias.name)
        return None

    def resolve_module(self, tree: ast.Module, module: str, level: int = 0) -> ast.Module | None:
        # ponytail: scanned modules only; add dependency resolution for third-party source trees.
        if level:
            current_module = self.tree_modules.get(tree, "")
            package = current_module.split(".")[:-1]
            module = ".".join([*package[: len(package) - level + 1], module])
        return self.module_trees.get(module)

    def get_enclosing_class(self, node: ast.AST) -> ast.ClassDef | None:
        scope = node
        while (parent := self.get_parent(scope)) is not None:
            scope = parent
            if isinstance(scope, ast.ClassDef):
                return scope
        return None

    @staticmethod
    def is_external_source(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id == "request"
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id == "request" or (node.value.id, node.attr) in {
                    ("os", "environ"),
                    ("sys", "argv"),
                }
            return BaseRule.is_external_source(node.value)
        if isinstance(node, ast.Subscript):
            return BaseRule.is_external_source(node.value)
        return False

    @staticmethod
    def is_input_call(node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name):
            return node.func.id in {"input", "getpass"}
        return (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (node.func.value.id, node.func.attr) in {("os", "getenv"), ("getpass", "getpass")}
        )

    def check(
        self,
        tree: ast.AST,
        file_path: str,
        file_content: str,
        module_trees: dict[str, ast.Module] | None = None,
        current_module: str = "",
    ) -> list[Vulnerability]:
        """
        Runs the rule checks on the AST and raw content.
        Must return list of Vulnerability objects.
        """
        self.vulnerabilities = []
        self.parent_map = self.build_parent_map(tree)
        self.module_trees = module_trees or {current_module: tree}
        self.tree_modules = {module_tree: name for name, module_tree in self.module_trees.items()}
        self.parent_maps = {
            module_tree: self.build_parent_map(module_tree)
            for module_tree in self.module_trees.values()
        }
        self.node_trees = {
            node: module_tree
            for module_tree in self.module_trees.values()
            for node in ast.walk(module_tree)
        }
        self.current_tree = tree
        self.run(tree, file_path, file_content)
        return self.vulnerabilities

    def run(self, tree: ast.AST, file_path: str, file_content: str) -> None:
        """
        Override this in subclasses to implement logic.
        """
        pass

    def add_vuln(self, file_path: str, line_no: int, col_offset: int, file_content: str, detail: str | None = None) -> None:
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
            remediation=self.remediation,
        )
        self.vulnerabilities.append(vuln)

    def add_tainted_vuln(
        self,
        file_path: str,
        line_no: int,
        col_offset: int,
        file_content: str,
        trace: TaintTrace,
        detail: str | None = None,
    ) -> None:
        lines = file_content.splitlines()
        snippet = ""
        if 0 <= line_no - 1 < len(lines):
            snippet = lines[line_no - 1].strip()

        vuln = Vulnerability(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=detail if detail else self.description,
            file_path=file_path,
            line_no=line_no,
            col_offset=col_offset,
            code_snippet=snippet,
            remediation=self.remediation,
            data_flow=list(trace.steps),
            taint_source=trace.source,
            assessment=trace.assessment,
        )
        self.vulnerabilities.append(vuln)
