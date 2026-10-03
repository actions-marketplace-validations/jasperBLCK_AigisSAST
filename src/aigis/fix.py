from __future__ import annotations

import ast
import difflib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from aigis.checks.python_ast import dotted, is_const, kw
from aigis.models import Finding
from aigis.scanner import scan_path

SECRET_RULES = {"AIG001", "AIG002", "AIG003"}
FIXABLE = SECRET_RULES | {"AIG005", "AIG013", "AIG014", "AIG016", "AIG019", "AIG042"}
ENV_NAME = re.compile(r"[^A-Z0-9_]")
COMPOSE_PORT = re.compile(r"""^(\s*-\s*["']?)(?:0\.0\.0\.0:)?(\d+:\d+(?:/tcp)?["']?\s*)$""")


@dataclass
class Edit:
    line: int
    start: int
    end: int
    text: str


@dataclass
class FileFix:
    path: str
    before: str
    after: str
    rules: list[str] = field(default_factory=list)

    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                f"a/{self.path}",
                f"b/{self.path}",
            )
        )


@dataclass
class FixPlan:
    root: Path
    files: list[FileFix] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    gitignore_env: bool = False
    manual: list[Finding] = field(default_factory=list)

    @property
    def fixed(self) -> int:
        return sum(len(f.rules) for f in self.files) + int(self.gitignore_env)


def is_fixable(finding: Finding) -> bool:
    return finding.rule.id in FIXABLE


def _env_name(raw: str) -> str:
    name = ENV_NAME.sub("_", raw.upper()).strip("_")
    return name if name and not name[0].isdigit() else f"APP_{name}"


def _apply(lines: list[str], edits: list[Edit]) -> list[str]:
    raw = [ln.encode("utf-8") for ln in lines]
    for e in sorted(edits, key=lambda e: (e.line, e.start), reverse=True):
        b = raw[e.line - 1]
        raw[e.line - 1] = b[: e.start] + e.text.encode("utf-8") + b[e.end :]
    return [b.decode("utf-8") for b in raw]


def _has_import(tree: ast.Module, module: str) -> bool:
    return any(
        isinstance(node, ast.Import) and any(a.name == module and a.asname is None for a in node.names)
        for node in tree.body
    )


def _import_lines(tree: ast.Module, modules: list[str], lines: list[str]) -> list[tuple[int, str]]:
    plain = [n for n in tree.body if isinstance(n, ast.Import)]
    if plain:
        out = []
        for m in modules:
            after = next((n for n in plain if n.names[0].name > m), None)
            at = after.lineno - 1 if after else (plain[-1].end_lineno or plain[-1].lineno)
            out.append((at, f"import {m}\n"))
        return out
    at = 0
    for i, node in enumerate(tree.body):
        is_doc = i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
        if not (is_doc or is_future):
            break
        at = node.end_lineno or node.lineno
    block = "".join(f"import {m}\n" for m in modules)
    if at:
        block = "\n" + block
    if at < len(lines) and lines[at].strip():
        block += "\n"
    return [(at, block)]


class _PyFixer:
    def __init__(self, source: str, targets: dict[int, set[str]], env: dict[str, str]) -> None:
        self.source = source
        self.lines = source.splitlines(keepends=True)
        self.targets = targets
        self.env = env
        self.edits: list[Edit] = []
        self.imports: set[str] = set()
        self.done: list[str] = []

    def seg(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ""

    def replace(self, node: ast.AST, text: str, rule: str, *imports: str) -> None:
        line, end_line = node.lineno, node.end_lineno
        if end_line != line or node.end_col_offset is None:
            return
        self.edits.append(Edit(line, node.col_offset, node.end_col_offset, text))
        self.imports.update(imports)
        self.done.append(rule)

    def wants(self, node: ast.AST, *rules: str) -> str | None:
        found = self.targets.get(getattr(node, "lineno", 0), set())
        return next((r for r in rules if r in found), None)

    def secret(self, name: str, value: ast.AST) -> None:
        rule = self.wants(value, *SECRET_RULES)
        if not rule or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        env_name = _env_name(name)
        n = 2
        while env_name in self.env and self.env[env_name] != value.value:
            env_name = f"{_env_name(name)}_{n}"
            n += 1
        self.env[env_name] = value.value
        self.replace(value, f'os.environ["{env_name}"]', rule, "os")

    def run(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if len(names) == 1:
                    self.secret(names[0], node.value)
                    self._debug_var(names[0], node.value)
                    self._random(node.value)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and value is not None:
                        self.secret(key.value, value)
            elif isinstance(node, ast.Call):
                self._call(node)

    def _debug_var(self, name: str, value: ast.AST) -> None:
        if name == "DEBUG" and is_const(value, True) and self.wants(value, "AIG014"):
            self.replace(value, 'os.getenv("DEBUG") == "1"', "AIG014", "os")

    def _random(self, value: ast.AST) -> None:
        for node in ast.walk(value):
            if not isinstance(node, ast.Call) or not self.wants(node, "AIG019"):
                continue
            name, args = dotted(node.func), [self.seg(a) for a in node.args]
            if node.keywords or not all(args):
                continue
            if name == "random.choice" and len(args) == 1:
                self.replace(node, f"secrets.choice({args[0]})", "AIG019", "secrets")
            elif name == "random.getrandbits" and len(args) == 1:
                self.replace(node, f"secrets.randbits({args[0]})", "AIG019", "secrets")
            elif name == "random.randint" and len(args) == 2:
                lo, hi = args
                text = f"secrets.randbelow({hi} - {lo} + 1) + {lo}"
                if all(isinstance(a, ast.Constant) and isinstance(a.value, int) for a in node.args):
                    lo_v, hi_v = (a.value for a in node.args)  # type: ignore[attr-defined]
                    text = f"secrets.randbelow({hi_v - lo_v + 1})" + (f" + {lo_v}" if lo_v else "")
                self.replace(node, text, "AIG019", "secrets")

    def _call(self, node: ast.Call) -> None:
        for k in node.keywords:
            if k.arg:
                self.secret(k.arg, k.value)
        verify = kw(node, "verify")
        if is_const(verify, False) and self.wants(verify, "AIG016"):
            self.replace(verify, "True", "AIG016")
        debug = kw(node, "debug")
        if is_const(debug, True) and self.wants(debug, "AIG014"):
            self.replace(debug, "False", "AIG014")
        if (
            dotted(node.func) == "yaml.load"
            and len(node.args) == 1
            and not node.keywords
            and self.wants(node, "AIG013")
        ):
            self.replace(node.func, "yaml.safe_load", "AIG013")

    def result(self, tree: ast.Module) -> str:
        out = _apply([ln.rstrip("\r\n") for ln in self.lines], self.edits)
        endings = [ln[len(ln.rstrip("\r\n")) :] for ln in self.lines]
        text = [o + e for o, e in zip(out, endings)]
        missing = sorted(m for m in self.imports if not _has_import(tree, m))
        for at, block in sorted(_import_lines(tree, missing, text), key=lambda x: x[0], reverse=True):
            text[at:at] = [block]
        return "".join(text)


def _fix_python(source: str, targets: dict[int, set[str]], env: dict[str, str]) -> tuple[str, list[str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, []
    fixer = _PyFixer(source, targets, env)
    fixer.run(tree)
    if not fixer.edits:
        return source, []
    return fixer.result(tree), fixer.done


def _fix_compose(source: str, targets: dict[int, set[str]]) -> tuple[str, list[str]]:
    lines = source.splitlines(keepends=True)
    done = []
    for line, rules in targets.items():
        if "AIG042" not in rules or line > len(lines):
            continue
        body = lines[line - 1].rstrip("\r\n")
        m = COMPOSE_PORT.match(body)
        if m:
            lines[line - 1] = f"{m.group(1)}127.0.0.1:{m.group(2)}" + lines[line - 1][len(body) :]
            done.append("AIG042")
    return "".join(lines), done


def _read_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out = {}
    for ln in path.read_text("utf-8", "replace").splitlines():
        if "=" in ln and not ln.lstrip().startswith("#"):
            k, v = ln.split("=", 1)
            out[k.strip().removeprefix("export ").strip()] = v.strip().strip("'\"")
    return out


def plan(target: Path) -> FixPlan:
    result = scan_path(target)
    root = result.root
    fp = FixPlan(root=root)
    existing_env = _read_env(root / ".env")
    env: dict[str, str] = dict(existing_env)

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)

    for rel, findings in sorted(by_file.items()):
        if any(f.rule.id == "AIG005" for f in findings):
            fp.gitignore_env = True
            continue
        targets: dict[int, set[str]] = defaultdict(set)
        for f in findings:
            targets[f.line].add(f.rule.id)
        path = root / rel
        before = path.read_text("utf-8")
        if path.suffix == ".py":
            after, done = _fix_python(before, targets, env)
        elif path.name.startswith(("docker-compose", "compose")) and path.suffix in {".yml", ".yaml"}:
            after, done = _fix_compose(before, targets)
        else:
            after, done = before, []
        if done:
            fp.files.append(FileFix(rel, before, after, done))
        remaining = list(done)
        for f in findings:
            if f.rule.id in remaining:
                remaining.remove(f.rule.id)
            else:
                fp.manual.append(f)

    fp.env = {k: v for k, v in env.items() if k not in existing_env}
    if fp.env:
        fp.gitignore_env = fp.gitignore_env or not _env_ignored(root)
    return fp


def _env_ignored(root: Path) -> bool:
    gi = root / ".gitignore"
    return gi.is_file() and any(ln.strip() in {".env", "/.env", ".env*", "*.env"} for ln in gi.read_text().splitlines())


def _quote(value: str) -> str:
    return value if re.fullmatch(r"[\w@%+=:,./\-]*", value) else '"' + value.replace('"', '\\"') + '"'


def apply(fp: FixPlan) -> None:
    for f in fp.files:
        (fp.root / f.path).write_text(f.after, "utf-8")
    if fp.env:
        env_path = fp.root / ".env"
        prefix = ""
        if env_path.is_file() and not env_path.read_text("utf-8").endswith("\n"):
            prefix = "\n"
        with env_path.open("a", encoding="utf-8") as fh:
            fh.write(prefix + "".join(f"{k}={_quote(v)}\n" for k, v in fp.env.items()))
        example = fp.root / ".env.example"
        known = set(_read_env(example))
        new = [k for k in fp.env if k not in known]
        if new:
            with example.open("a", encoding="utf-8") as fh:
                fh.write("".join(f"{k}=\n" for k in new))
    if fp.gitignore_env and not _env_ignored(fp.root):
        gi = fp.root / ".gitignore"
        text = gi.read_text("utf-8") if gi.is_file() else ""
        gi.write_text(text + ("" if not text or text.endswith("\n") else "\n") + ".env\n", "utf-8")
