from __future__ import annotations

import re
import subprocess
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitea.com")


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace").strip()


def _web_base(remote: str) -> str | None:
    url = remote.strip()
    # Known host appearing anywhere (also handles auth/mirror proxies that
    # prepend their own host, e.g. .../proxy/github.com/owner/repo).
    for host in _HOSTS:
        idx = url.rfind(host + "/")
        if idx != -1:
            path = url[idx + len(host) + 1 :]
            path = re.sub(r"\.git$", "", path).strip("/")
            return f"https://{host}/{path}" if path else None
    m = re.match(r"git@([^:]+):(.+)", url)  # git@host:owner/repo(.git)
    if not m:
        m = re.match(r"(?:ssh|https?|git)://(?:[^@/]+@)?([^/]+)/(.+)", url)
    if not m:
        return None
    host, path = m.group(1), m.group(2)
    path = re.sub(r"\.git$", "", path).strip("/")
    if not path:
        return None
    return f"https://{host}/{path}"


@lru_cache(maxsize=64)
def repo_web(root_str: str) -> tuple[str | None, str | None]:
    """Return (web base URL, HEAD sha) for a checkout, or (None, None)."""
    root = Path(root_str)
    remote = _git(root, "config", "--get", "remote.origin.url")
    if not remote:
        remotes = _git(root, "remote")
        name = remotes.split("\n")[0] if remotes else None
        remote = _git(root, "config", "--get", f"remote.{name}.url") if name else None
    base = _web_base(remote) if remote else None
    sha = _git(root, "rev-parse", "HEAD") if base else None
    return base, sha


def file_url(base: str, ref: str, path: str, line: int | None = None) -> str:
    sep = "/src/" if "bitbucket.org" in base else "/blob/"
    url = f"{base}{sep}{ref}/{quote(path)}"
    if line and line > 0:
        anchor = f"lines-{line}" if "bitbucket.org" in base else f"L{line}"
        url += f"#{anchor}"
    return url


def commit_url(base: str, ref: str) -> str:
    seg = "commits" if "bitbucket.org" in base else "commit"
    return f"{base}/{seg}/{ref}"
