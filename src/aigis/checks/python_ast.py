from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from aigis.checks.common import SECRET_NAME, is_placeholder, mask
from aigis.models import Finding, Severity
from aigis.rules import get

SQL_SINKS = {"execute", "executemany", "executescript", "text", "raw", "extra"}
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"}
UNSAFE_LOADERS = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "yaml.unsafe_load",
    "jsonpickle.decode",
}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
MUTATING_METHODS = {"post", "put", "patch", "delete"}
RANDOM_FUNCS = {
    "random.choice",
    "random.choices",
    "random.randint",
    "random.random",
    "random.randrange",
    "random.getrandbits",
    "random.sample",
}
TOKENISH = re.compile(r"(token|secret|passw|otp|code|salt|nonce|session|reset|verify|api_?key)", re.I)


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def kw(call: ast.Call, name: str) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _has_str(node.left) or _has_str(node.right)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _has_str(node.func.value)
    )


def _has_str(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return _has_str(node.left) or _has_str(node.right)
    return False


def secret_name(name: str) -> bool:
    return bool(SECRET_NAME.search(name))


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str], source: str) -> None:
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        self.is_fastapi = "fastapi" in source
        self.global_auth = False

    def add(
        self,
        rule_id: str,
        node: ast.AST,
        *,
        severity: Severity | None = None,
        detail: str = "",
        secret: str | None = None,
    ) -> None:
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if secret:
            snippet = snippet.replace(secret, mask(secret))
        self.findings.append(Finding(get(rule_id), self.path, line, snippet, severity, detail))

    def _check_secret_value(self, name: str, value: ast.AST, node: ast.AST) -> None:
        if (
            secret_name(name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and not is_placeholder(value.value)
        ):
            self.add("AIG002", node, detail=name, secret=value.value)

    def _targets(self, node: ast.Assign | ast.AnnAssign) -> Iterator[str]:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name):
                yield t.id
            elif isinstance(t, ast.Attribute):
                yield t.attr

    def _check_assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        value = node.value
        if value is None:
            return
        for name in self._targets(node):
            self._check_secret_value(name, value, node)
            if name == "DEBUG" and is_const(value, True):
                self.add("AIG014", node)
            if TOKENISH.search(name) and any(
                isinstance(n, ast.Call) and dotted(n.func) in RANDOM_FUNCS for n in ast.walk(value)
            ):
                self.add("AIG019", node, detail=name)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_assign(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_assign(node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and value is not None:
                self._check_secret_value(key.value, value, value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        short = name.rsplit(".", 1)[-1]

        for k in node.keywords:
            if k.arg:
                self._check_secret_value(k.arg, k.value, k.value)

        if (
            short in SQL_SINKS
            and node.args
            and is_dynamic_string(node.args[0])
            and (short != "text" or name in {"text", "sqlalchemy.text", "sa.text"})
        ):
            self.add("AIG010", node)

        if (
            name.startswith("subprocess.")
            and short in SUBPROCESS_FUNCS
            and is_const(kw(node, "shell"), True)
            and node.args
            and not isinstance(node.args[0], ast.Constant)
        ):
            self.add("AIG011", node)
        if name in {"os.system", "os.popen"} and node.args and not isinstance(node.args[0], ast.Constant):
            self.add("AIG011", node)

        if name in {"eval", "exec"} and node.args and not isinstance(node.args[0], ast.Constant):
            self.add("AIG012", node)

        if name in UNSAFE_LOADERS:
            self.add("AIG013", node)
        if name == "yaml.load":
            loader = kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or dotted(loader).rsplit(".", 1)[-1] not in SAFE_YAML_LOADERS:
                self.add("AIG013", node)

        if is_const(kw(node, "debug"), True) and (short in {"run", "FastAPI", "Flask", "Starlette"}):
            self.add("AIG014", node)

        if short == "add_middleware" and node.args and dotted(node.args[0]).endswith("CORSMiddleware"):
            origins = kw(node, "allow_origins")
            regex = kw(node, "allow_origin_regex")
            wildcard = (
                isinstance(origins, (ast.List, ast.Tuple, ast.Set)) and any(is_const_str(e, "*") for e in origins.elts)
            ) or (isinstance(regex, ast.Constant) and regex.value in {".*", "^.*$", ".+"})
            if wildcard:
                creds = is_const(kw(node, "allow_credentials"), True)
                self.add(
                    "AIG015",
                    node,
                    severity=Severity.HIGH if creds else None,
                    detail="allow_credentials=True" if creds else "",
                )

        if is_const(kw(node, "verify"), False) and short != "decode":
            self.add("AIG016", node)

        if name.endswith("jwt.decode"):
            self._check_jwt(node)

        if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"} and not is_const(kw(node, "usedforsecurity"), False):
            self.add("AIG018", node)
        if (
            name == "hashlib.new"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and str(node.args[0].value).lower() in {"md5", "sha1"}
        ):
            self.add("AIG018", node)

        if short in {"APIRouter", "FastAPI"} and kw(node, "dependencies") is not None:
            self.global_auth = True

        self.generic_visit(node)

    def _check_jwt(self, node: ast.Call) -> None:
        options = kw(node, "options")
        if isinstance(options, ast.Dict):
            for key, value in zip(options.keys, options.values):
                if is_const_str(key, "verify_signature") and is_const(value, False):
                    self.add("AIG017", node)
                    return
        if is_const(kw(node, "verify"), False):
            self.add("AIG017", node)
            return
        algorithms = kw(node, "algorithms")
        if isinstance(algorithms, (ast.List, ast.Tuple)) and any(
            isinstance(e, ast.Constant) and str(e.value).lower() == "none" for e in algorithms.elts
        ):
            self.add("AIG017", node)

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self.is_fastapi:
            for dec in node.decorator_list:
                if (
                    isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in MUTATING_METHODS
                    and kw(dec, "dependencies") is None
                    and not _has_depends(node)
                ):
                    self.add("AIG021", dec, detail=f"{dec.func.attr.upper()} {node.name}")
        self.generic_visit(node)

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func


def is_const_str(node: ast.AST | None, value: str) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def _has_depends(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = func.args
    nodes: list[ast.AST] = [*args.defaults, *[d for d in args.kw_defaults if d is not None]]
    nodes += [a.annotation for a in [*args.args, *args.kwonlyargs] if a.annotation is not None]
    for n in nodes:
        for sub in ast.walk(n):
            if isinstance(sub, ast.Call) and dotted(sub.func).rsplit(".", 1)[-1] in {"Depends", "Security"}:
                return True
    return False


def check_python(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = _Visitor(path, source.splitlines(), source)
    visitor.visit(tree)
    if visitor.global_auth:
        return [f for f in visitor.findings if f.rule.id != "AIG021"]
    return visitor.findings
