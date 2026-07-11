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
            if self.is_sanitizer_call(node):
                return TaintTrace(False)

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
        # Walk only the current scope, ignoring nested scopes (e.g. nested function/class definitions)
        nodes_to_visit = [scope]
        while nodes_to_visit:
            current_node = nodes_to_visit.pop(0)
            
            # Check if this node is an assignment
            if isinstance(current_node, ast.Assign):
                for target in current_node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        if hasattr(current_node, 'lineno') and hasattr(node, 'lineno'):
                            if current_node.lineno < node.lineno:
                                if not recent_assign or current_node.lineno > recent_assign[0].lineno:
                                    recent_assign = (current_node, None)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for idx, elt in enumerate(target.elts):
                            if isinstance(elt, ast.Name) and elt.id == var_name:
                                if hasattr(current_node, 'lineno') and hasattr(node, 'lineno'):
                                    if current_node.lineno < node.lineno:
                                        if not recent_assign or current_node.lineno > recent_assign[0].lineno:
                                            recent_assign = (current_node, idx)
            elif isinstance(current_node, ast.AnnAssign):
                if isinstance(current_node.target, ast.Name) and current_node.target.id == var_name:
                    if hasattr(current_node, 'lineno') and hasattr(node, 'lineno'):
                        if current_node.lineno < node.lineno:
                            if not recent_assign or current_node.lineno > recent_assign[0].lineno:
                                recent_assign = (current_node, None)
            elif isinstance(current_node, ast.AugAssign):
                if isinstance(current_node.target, ast.Name) and current_node.target.id == var_name:
                    if hasattr(current_node, 'lineno') and hasattr(node, 'lineno'):
                        if current_node.lineno < node.lineno:
                            if not recent_assign or current_node.lineno > recent_assign[0].lineno:
                                recent_assign = (current_node, None)
                                
            # Add child nodes to visit, but do not descend into nested scopes
            for child in ast.iter_child_nodes(current_node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                nodes_to_visit.append(child)
                                
        if recent_assign:
            assign_node, tuple_idx = recent_assign
            if isinstance(assign_node, ast.Assign):
                if tuple_idx is not None and isinstance(assign_node.value, (ast.Tuple, ast.List)):
                    if tuple_idx < len(assign_node.value.elts):
                        return assign_node.value.elts[tuple_idx]
                return assign_node.value
            elif isinstance(assign_node, ast.AnnAssign):
                # Type inference: drop taint for primitive annotated variables (int, float, bool)
                ann_name = ""
                if isinstance(assign_node.annotation, ast.Name):
                    ann_name = assign_node.annotation.id
                if ann_name in {"int", "float", "bool"}:
                    return ast.Constant(value=0)
                return assign_node.value
            elif isinstance(assign_node, ast.AugAssign):
                # Recursively get the previous definition of this variable
                prev_def = self.get_variable_definition(assign_node, var_name)
                if prev_def is not None:
                    # Construct a virtual BinOp representing (prev_def + value)
                    virtual_binop = ast.BinOp(left=prev_def, op=assign_node.op, right=assign_node.value)
                    if hasattr(assign_node, 'lineno'):
                        virtual_binop.lineno = assign_node.lineno
                        virtual_binop.col_offset = getattr(assign_node, 'col_offset', 0)
                    return virtual_binop
                return assign_node.value
                
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
        if self.call_graph is None:
            self.call_graph = {}
            for tree in self.module_trees.values():
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        called = self.get_called_function(node)
                        if called is not None:
                            if called not in self.call_graph:
                                self.call_graph[called] = []
                            self.call_graph[called].append(node)
        return self.call_graph.get(function, [])

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

        # Type inference check: drop taint if parameter annotation is int, float, bool
        parameter = parameters[parameter_index]
        if parameter.annotation:
            ann_name = ""
            if isinstance(parameter.annotation, ast.Name):
                ann_name = parameter.annotation.id
            if ann_name in {"int", "float", "bool"}:
                return None

        # Check if function is a web route/handler
        is_web_handler = False
        if hasattr(function, "decorator_list") and function.decorator_list:
            route_keywords = {"route", "get", "post", "put", "delete", "patch", "options", "head", "websocket"}
            for dec in function.decorator_list:
                dec_func = dec.func if isinstance(dec, ast.Call) else dec
                dec_name = ""
                if isinstance(dec_func, ast.Name):
                    dec_name = dec_func.id
                elif isinstance(dec_func, ast.Attribute):
                    dec_name = dec_func.attr
                    
                if dec_name in route_keywords:
                    is_web_handler = True
                    break

        if parameters and parameters[0].arg in {"request", "req"}:
            is_web_handler = True

        if is_web_handler and var_name not in {"request", "req"}:
            return TaintTrace(
                True,
                (f"{var_name} is a parameter of web route/handler {function.name}()",),
                source="web_route_parameter",
                assessment="confirmed",
            )

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

    @staticmethod
    def get_attribute_chain(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            val = BaseRule.get_attribute_chain(node.value)
            if val:
                return f"{val}.{node.attr}"
        return None

    def get_imported_module(self, tree: ast.Module, value: ast.AST) -> ast.Module | None:
        chain = self.get_attribute_chain(value)
        if not chain:
            return None
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    import_name = alias.asname or alias.name
                    if chain == import_name:
                        return self.module_trees.get(alias.name)
                    if chain.startswith(import_name + "."):
                        suffix = chain[len(import_name)+1:]
                        full_mod_name = f"{alias.name}.{suffix}"
                        if full_mod_name in self.module_trees:
                            return self.module_trees.get(full_mod_name)
            elif isinstance(statement, ast.ImportFrom) and statement.module:
                for alias in statement.names:
                    import_name = alias.asname or alias.name
                    if chain == import_name:
                        return self.resolve_module(
                            tree, f"{statement.module}.{alias.name}", statement.level
                        )
                    if chain.startswith(import_name + "."):
                        suffix = chain[len(import_name)+1:]
                        return self.resolve_module(
                            tree, f"{statement.module}.{alias.name}.{suffix}", statement.level
                        )
        return None

    def get_receiver_class(self, tree: ast.Module, value: ast.AST) -> ast.ClassDef | None:
        if isinstance(value, ast.Call):
            return self.get_constructor_class(tree, value.func)
        chain = self.get_attribute_chain(value)
        if not chain:
            return None
        definition = None
        if isinstance(value, ast.Name):
            definition = self.get_variable_definition(value, value.id)
        if isinstance(definition, ast.Call):
            return self.get_constructor_class(tree, definition.func)
        return self.find_class(tree, chain) or self.find_imported_class(tree, chain)

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
        if level:
            current_module = self.tree_modules.get(tree, "")
            package = current_module.split(".")[:-1]
            module = ".".join([*package[: len(package) - level + 1], module])
            return self.module_trees.get(module)
            
        res = self.module_trees.get(module)
        if res is not None:
            return res
            
        current_module = self.tree_modules.get(tree, "")
        if current_module:
            parts = current_module.split(".")
            if len(parts) > 1:
                package = ".".join(parts[:-1])
                res = self.module_trees.get(f"{package}.{module}")
                if res is not None:
                    return res
                    
        # Try third-party sites-packages resolution on-demand
        if getattr(self, "site_packages_dir", None) and self.site_packages_dir:
            res_tree = self.load_third_party_module(module)
            if res_tree:
                return res_tree
                
        return None

    def load_third_party_module(self, module_name: str) -> ast.Module | None:
        if module_name in self.module_trees:
            return self.module_trees[module_name]
            
        parts = module_name.split(".")
        path_a = self.site_packages_dir.joinpath(*parts).with_suffix(".py")
        path_b = self.site_packages_dir.joinpath(*parts, "__init__.py")
        
        target_file = None
        if path_a.is_file():
            target_file = path_a
        elif path_b.is_file():
            target_file = path_b
            
        if target_file:
            try:
                content = target_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content)
                
                self.module_trees[module_name] = tree
                self.tree_modules[tree] = module_name
                
                pmap = {}
                for parent in ast.walk(tree):
                    for child in ast.iter_child_nodes(parent):
                        pmap[child] = parent
                        self.node_trees[child] = tree
                self.node_trees[tree] = tree
                self.parent_maps[tree] = pmap
                
                return tree
            except Exception:
                pass
        return None

    def get_enclosing_class(self, node: ast.AST) -> ast.ClassDef | None:
        scope = node
        while (parent := self.get_parent(scope)) is not None:
            scope = parent
            if isinstance(scope, ast.ClassDef):
                return scope
        return None

    @staticmethod
    def is_external_source(node: ast.AST) -> bool:
        chain = BaseRule.get_attribute_chain(node)
        if chain:
            parts = chain.split(".")
            # Django self.request.GET / POST
            if len(parts) >= 3 and parts[0] == "self" and parts[1] == "request" and parts[2] in {"GET", "POST", "COOKIES", "FILES", "headers", "body"}:
                return True
            # Tornado self.request.get / arguments
            if len(parts) >= 2 and parts[0] == "self" and parts[1] == "request":
                return True
            # Flask/FastAPI request.args, request.form, request.json, request.query_params
            if len(parts) >= 2 and parts[0] in {"request", "req"} and parts[1] in {"args", "form", "json", "query_params", "cookies", "headers", "files", "values", "data"}:
                return True
                
        if isinstance(node, ast.Name):
            return node.id in {"request", "req", "payload", "event", "params"}
        if isinstance(node, ast.Attribute):
            if node.attr in {"request", "req", "query_params", "form", "args"}:
                return True
            if isinstance(node.value, ast.Name):
                return node.value.id in {"request", "req", "payload", "event"} or (node.value.id, node.attr) in {
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

    @staticmethod
    def is_sanitizer_call(node: ast.Call) -> bool:
        """
        Check if the call represents a known sanitizer or escaping function.
        """
        func_name = ""
        module_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id

        # Sanitizers/escapers by name pattern or library module
        sanitizer_names = {
            "escape", "html_escape", "quote", "quote_plus", "urlencode",
            "shlex_quote", "sanitize", "clean", "bleach_clean", "int", "float"
        }
        if func_name.lower() in sanitizer_names:
            return True
        if module_name in {"shlex", "html", "urllib", "urllib.parse", "bleach"}:
            return True
        if func_name in {"escape", "escape_silent", "soft_str"} and module_name in {"markupsafe", "jinja2"}:
            return True
        return False

    def check(
        self,
        tree: ast.AST,
        file_path: str,
        file_content: str,
        module_trees: dict[str, ast.Module] | None = None,
        current_module: str = "",
        parent_maps: dict[ast.Module, dict[ast.AST, ast.AST]] | None = None,
        node_trees: dict[ast.AST, ast.Module] | None = None,
        tree_modules: dict[ast.Module, str] | None = None,
        site_packages_dir: Path | None = None,
    ) -> list[Vulnerability]:
        """
        Runs the rule checks on the AST and raw content.
        Must return list of Vulnerability objects.
        """
        self.vulnerabilities = []
        self.module_trees = module_trees or {current_module: tree}
        self.site_packages_dir = site_packages_dir
        
        if tree_modules is not None:
            self.tree_modules = tree_modules
        else:
            self.tree_modules = {module_tree: name for name, module_tree in self.module_trees.items()}
            
        if parent_maps is not None:
            self.parent_maps = parent_maps
        else:
            self.parent_maps = {
                module_tree: self.build_parent_map(module_tree)
                for module_tree in self.module_trees.values()
            }
            
        if node_trees is not None:
            self.node_trees = node_trees
        else:
            self.node_trees = {
                node: module_tree
                for module_tree in self.module_trees.values()
                for node in ast.walk(module_tree)
            }
            
        self.call_graph: dict[ast.FunctionDef | ast.AsyncFunctionDef, list[ast.Call]] | None = None
        
        self.parent_map = self.parent_maps.get(tree) or self.build_parent_map(tree)
        self.current_tree = tree
        self.run(tree, file_path, file_content)
        return self.vulnerabilities

    def run(self, tree: ast.AST, file_path: str, file_content: str) -> None:
        """
        Override this in subclasses to implement logic.
        """
        pass

    def is_suppressed(self, file_content: str, line_no: int) -> bool:
        lines = file_content.splitlines()
        if 0 <= line_no - 1 < len(lines):
            line_code = lines[line_no - 1]
            if "#" in line_code:
                comment = line_code.split("#", 1)[1].strip().lower()
                # Matches: # nosec, # sapyscan: ignore, # sapyscan: ignore <rule_id>
                if "nosec" in comment or "sapyscan: ignore" in comment:
                    if "sapyscan: ignore" in comment:
                        parts = comment.split("sapyscan: ignore")
                        if len(parts) > 1 and parts[1].strip():
                            ignored_rule = parts[1].strip().lower()
                            if ignored_rule not in self.rule_id.lower() and ignored_rule not in self.title.lower():
                                return False
                    return True
        return False

    def add_vuln(self, file_path: str, line_no: int, col_offset: int, file_content: str, detail: str | None = None) -> None:
        if self.is_suppressed(file_content, line_no):
            return
            
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
        if self.is_suppressed(file_content, line_no):
            return
            
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
