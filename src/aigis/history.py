from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from aigis.checks.common import is_dummy_token, is_local_default_db, is_placeholder, is_test_path, mask
from aigis.checks.text import (
    CONFIG_EXT,
    DB_URL,
    DOC_EXT,
    PRIVATE_KEY,
    TOKEN_PATTERNS,
    generic_secret,
    is_env_file,
    is_example,
)
from aigis.models import Severity
from aigis.rules import get
from aigis.scanner import DEFAULT_EXCLUDES, IGNORE_COMMENT, _load_ignore, _matches

SEP = "\x1e"


@dataclass
class Leak:
    rule_id: str
    path: str
    commit: str
    date: str
    secret: str
    detail: str
    live: bool = False

    @property
    def severity(self) -> Severity:
        return get(self.rule_id).severity

    @property
    def masked(self) -> str:
        return mask(self.secret)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.secret.encode()).hexdigest()[:12]

    def as_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule_id,
            "severity": self.severity.label,
            "path": self.path,
            "commit": self.commit,
            "date": self.date,
            "secret": self.masked,
            "fingerprint": self.fingerprint,
            "detail": self.detail,
            "still_in_code": self.live,
        }


class NotARepo(Exception):
    pass


def _secrets_in_line(path: str, line: str) -> list[tuple[str, str, str]]:
    out = []
    for label, pattern in TOKEN_PATTERNS:
        m = pattern.search(line)
        if m and not is_dummy_token(m.group(0)):
            return [("AIG001", m.group(0), label)]
    if PRIVATE_KEY.search(line) and not ("..." in line or "your" in line.lower()):
        return [("AIG004", line.strip(), "private key")]
    p = PurePosixPath(path)
    if p.suffix.lower() in DOC_EXT or is_example(path) or is_test_path(path):
        return out
    m = DB_URL.search(line)
    if m and not is_placeholder(m.group(1)) and "{" not in m.group(1) and not is_local_default_db(*m.groups()):
        return [("AIG003", m.group(1), "database URL")]
    ext = p.suffix.lower()
    is_config = ext in CONFIG_EXT or is_env_file(path)
    secret = generic_secret(line, is_config=is_config, is_code=not is_config, is_dockerfile=False)
    if secret:
        out.append(("AIG002", secret[1], secret[0]))
    return out


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=300, check=True)
    except FileNotFoundError as exc:
        raise NotARepo("git не установлен") from exc
    except subprocess.CalledProcessError as exc:
        raise NotARepo(exc.stderr.decode("utf-8", "replace").strip() or "не git-репозиторий") from exc
    return proc.stdout.decode("utf-8", "replace")


def scan_history(root: Path, *, max_commits: int | None = None) -> list[Leak]:
    root = root.resolve()
    _git(root, "rev-parse", "--git-dir")
    args = ["log", "--all", "-p", "-U0", "--no-color", "--no-renames", "--date=short", f"--format={SEP}%h %ad"]
    if max_commits:
        args.append(f"-n{max_commits}")
    log = _git(root, *args)

    patterns = DEFAULT_EXCLUDES + _load_ignore(root)
    leaks: dict[tuple[str, str], Leak] = {}
    commit = date = path = ""
    for line in log.split("\n"):
        if line.startswith(SEP):
            commit, _, date = line[1:].partition(" ")
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else ""
            if _matches(path, patterns):
                path = ""
        elif line.startswith("+") and path and len(line) < 2000 and not IGNORE_COMMENT.search(line):
            for rule_id, secret, detail in _secrets_in_line(path, line[1:]):
                key = (rule_id, secret)
                leaks[key] = Leak(rule_id, path, commit, date, secret, detail)

    head = _tracked_text(root)
    for leak in leaks.values():
        leak.live = leak.secret in head.get(leak.path, "")
    return sorted(leaks.values(), key=lambda x: (-int(x.severity), x.live, x.path))


def _tracked_text(root: Path) -> dict[str, str]:
    out = {}
    for rel in _git(root, "ls-files", "-z").split("\0"):
        p = root / rel
        if rel and p.is_file() and p.stat().st_size < 1_000_000:
            try:
                out[rel] = p.read_text("utf-8", "replace")
            except OSError:
                continue
    return out
