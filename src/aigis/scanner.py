from __future__ import annotations

import fnmatch
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from aigis.checks.python_ast import check_python
from aigis.checks.text import check_text, env_has_secret, is_env_file
from aigis.models import Finding, Severity
from aigis.rules import get

DEFAULT_EXCLUDES = [
    ".git/**",
    "**/.git/**",
    "**/node_modules/**",
    "node_modules/**",
    "**/.venv/**",
    ".venv/**",
    "**/venv/**",
    "venv/**",
    "**/__pycache__/**",
    "**/dist/**",
    "dist/**",
    "**/build/**",
    "build/**",
    "**/.next/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.bundle.js",
    "**/vendor/**",
    "vendor/**",
    "**/third_party/**",
    "**/assets/vue/**",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Pipfile.lock",
    "**/bun.lockb",
    "**/.mypy_cache/**",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/site-packages/**",
]
BINARY_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".mp4",
    ".mp3",
    ".mov",
    ".db",
    ".sqlite",
    ".pyc",
    ".jar",
    ".class",
    ".svg",
    ".psd",
    ".xlsx",
    ".docx",
}
MAX_FILE_BYTES = 1_000_000
IGNORE_COMMENT = re.compile(r"aigis:\s*ignore(?:\[([A-Z0-9, ]+)\])?", re.I)
EXTERNAL_IGNORE = re.compile(r"#\s*nosec\b|noqa:[^#\n]*\bS\d{3}\b|pragma:\s*allowlist\s+secret", re.I)
ROUTER_AUTH = re.compile(
    r"\b(APIRouter|FastAPI|include_router|__init__)\([^()]*(?:\([^()]*\)[^()]*)*?"
    r"dependencies\s*=\s*\[[^\]]*Depends\(\s*\w*(auth|user|token|permission|verify|api_key|login)",
    re.I,
)


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.effective_severity == severity)

    @property
    def score(self) -> int:
        penalty = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1}
        return max(0, 100 - sum(penalty[f.effective_severity] for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def _git_files(root: Path) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def _matches(path: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatch(path, pat)
        or fnmatch.fnmatch(path, pat.rstrip("/*"))
        or (pat.startswith("**/") and fnmatch.fnmatch(path, pat[3:]))
        for pat in patterns
    )


def _load_ignore(root: Path) -> list[str]:
    f = root / ".aigisignore"
    if not f.is_file():
        return []
    return [ln.strip() for ln in f.read_text("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("#")]


def _gitignore_covers_env(root: Path) -> bool:
    gi = root / ".gitignore"
    if not gi.is_file():
        return False
    pats = [ln.strip() for ln in gi.read_text("utf-8", "replace").splitlines()]
    return any(p in {".env", "*.env", ".env*", ".env.*", "/.env", "**/.env"} for p in pats)


def iter_files(root: Path, excludes: list[str]) -> list[str]:
    if root.is_file():
        return [root.name]
    files = _git_files(root) if (root / ".git").exists() else None
    if files is None:
        files = [p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()]
    return sorted(p for p in files if not _matches(p, excludes))


def _suppressed(finding: Finding, lines: list[str]) -> bool:
    for idx in (finding.line - 1, finding.line - 2):
        if 0 <= idx < len(lines):
            m = IGNORE_COMMENT.search(lines[idx])
            if m and (not m.group(1) or finding.rule.id in {r.strip() for r in m.group(1).split(",")}):
                return True
    idx = finding.line - 1
    return 0 <= idx < len(lines) and bool(EXTERNAL_IGNORE.search(lines[idx]))


def scan_path(target: Path, *, excludes: list[str] | None = None, min_severity: Severity = Severity.LOW) -> ScanResult:
    target = target.resolve()
    root = target if target.is_dir() else target.parent
    patterns = DEFAULT_EXCLUDES + _load_ignore(root) + list(excludes or [])
    result = ScanResult(root=root)
    in_git = (root / ".git").exists()
    env_ignored = _gitignore_covers_env(root)
    router_auth = False

    for rel in iter_files(target, patterns):
        path = root / rel
        if path.suffix.lower() in BINARY_EXT or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", "replace")
        result.files_scanned += 1

        if is_env_file(rel):
            if (in_git or not env_ignored) and env_has_secret(text):
                result.findings.append(Finding(get("AIG005"), rel, 1, f"{rel} ∉ .gitignore"))
            continue

        is_python = path.suffix == ".py"
        router_auth = router_auth or (is_python and bool(ROUTER_AUTH.search(text)))
        found = check_text(rel, text, is_python=is_python)
        if is_python:
            found += check_python(rel, text)
        lines = text.splitlines()
        result.findings.extend(f for f in found if f.effective_severity >= min_severity and not _suppressed(f, lines))

    if router_auth:
        result.findings = [f for f in result.findings if f.rule.id != "AIG021"]
    result.findings = _dedupe(result.findings)
    result.findings.sort(key=lambda f: f.sort_key)
    return result


SHADOWED_BY_TOKEN = {"AIG002", "AIG003"}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    token_lines = {(f.path, f.line) for f in findings if f.rule.id == "AIG001"}
    seen: set[tuple[str, str, int]] = set()
    out = []
    for f in findings:
        key = (f.rule.id, f.path, f.line)
        if key in seen or (f.rule.id in SHADOWED_BY_TOKEN and (f.path, f.line) in token_lines):
            continue
        seen.add(key)
        out.append(f)
    return out
