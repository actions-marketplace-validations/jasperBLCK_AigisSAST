import json
import subprocess

from aigis import gitlink
from aigis.cli import main


def test_web_base_variants():
    assert gitlink._web_base("git@github.com:jasperBLCK/AigisSAST.git") == "https://github.com/jasperBLCK/AigisSAST"
    assert gitlink._web_base("https://github.com/o/r.git") == "https://github.com/o/r"
    assert gitlink._web_base("https://github.com/o/r") == "https://github.com/o/r"
    assert gitlink._web_base("ssh://git@gitlab.com/o/r.git") == "https://gitlab.com/o/r"
    assert gitlink._web_base("not a url") is None
    # auth/mirror proxy that prepends its own host
    assert gitlink._web_base("https://proxy.internal/proxy/github.com/o/r") == "https://github.com/o/r"


def test_file_and_commit_url():
    b = "https://github.com/o/r"
    assert gitlink.file_url(b, "abc", "a/b.py", 10) == "https://github.com/o/r/blob/abc/a/b.py#L10"
    assert gitlink.file_url(b, "abc", "a/b.py") == "https://github.com/o/r/blob/abc/a/b.py"
    assert gitlink.commit_url(b, "abc") == "https://github.com/o/r/commit/abc"
    bb = "https://bitbucket.org/o/r"
    assert gitlink.file_url(bb, "abc", "x.py", 3) == "https://bitbucket.org/o/r/src/abc/x.py#lines-3"


def test_repo_web_on_real_checkout(tmp_path):
    import subprocess

    def g(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)

    g("init", "-q")
    g("config", "user.email", "a@b.c")
    g("config", "user.name", "t")
    g("remote", "add", "origin", "git@github.com:o/r.git")
    (tmp_path / "f.txt").write_text("x\n")
    g("add", "f.txt")
    g("commit", "-qm", "init")
    base, sha = gitlink.repo_web(str(tmp_path))
    assert base == "https://github.com/o/r"
    assert sha and len(sha) == 40


def test_repo_web_no_git(tmp_path):
    gitlink.repo_web.cache_clear()
    assert gitlink.repo_web(str(tmp_path)) == (None, None)


def test_scan_links_include_subdirectory(tmp_path):
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "x.py").write_text("eval(x)\n")
    run = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(tmp_path)]
    subprocess.run([*run, "init", "-q"], check=True)
    subprocess.run([*run, "remote", "add", "origin", "git@github.com:o/r.git"], check=True)
    subprocess.run([*run, "add", "."], check=True)
    subprocess.run([*run, "commit", "-qm", "x"], check=True)
    gitlink.repo_web.cache_clear()
    gitlink.repo_prefix.cache_clear()
    out = tmp_path / "r.json"
    main(["scan", str(sub), "-f", "json", "-o", str(out)])
    url = json.loads(out.read_text())["findings"][0]["url"]
    assert url.startswith("https://github.com/o/r/blob/") and url.endswith("/svc/x.py#L1")
