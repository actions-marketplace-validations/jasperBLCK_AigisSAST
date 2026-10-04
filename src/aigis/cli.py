from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aigis import __version__, ai, badge, fix, gitlink, history, i18n, report
from aigis.i18n import pick, tr
from aigis.models import Severity
from aigis.rules import RULES
from aigis.scanner import ScanResult, scan_path

SEVERITIES = [s.label for s in Severity]
COMMANDS = {"scan", "fix", "history", "badge", "init", "rules", "explain", "help"}

HELP = {
    "en": """\
{b}AigisSAST v{version}{r} {d}// security scanner for AI-generated code{r}

{h}QUICK START{r}
  aigis scan                  scan the current folder
  aigis scan path/to/app      scan a folder or a file (or just: aigis path/to/app)
  aigis fix --dry-run         preview automatic fixes
  aigis fix                   apply them
  aigis history               find secrets ever committed to git

{h}COMMANDS{r}
  scan      find vulnerabilities and leaked secrets, with a link to every line
  fix       auto-fix safe cases: secrets to .env, verify=False, random, debug, ports
  history   check every commit for secrets, with a link to the commit
  badge     security grade badge for your README
  init      add a GitHub Actions workflow and .aigisignore to the project
  rules     list all rules
  explain   explain one rule:  aigis explain AIG010
  help      this screen

{h}USEFUL FLAGS{r} {d}(scan){r}
  -f json|sarif|markdown      machine and CI formats      -o FILE          write to a file
  -q, --quiet                 short output                --min-severity   medium, high, ...
  --fail-on critical|none     exit-code threshold         -e GLOB          skip files
  --ai                        LLM fixes for your code (AIGIS_API_KEY; secrets are never sent)

{h}LANGUAGE{r}
  --lang ru|en   or   AIGIS_LANG=ru     {d}(default: system locale, else English){r}

{h}EXIT CODES{r}   0 ok  ·  1 issues found  ·  2 usage error
{h}IGNORE{r}       # aigis: ignore[AIG014]  on the line, or globs in .aigisignore
{d}More: aigis <command> -h  ·  https://github.com/jasperBLCK/AigisSAST{r}
""",
    "ru": """\
{b}AigisSAST v{version}{r} {d}// сканер безопасности для кода, написанного ИИ{r}

{h}БЫСТРЫЙ СТАРТ{r}
  aigis scan                  проверить текущую папку
  aigis scan путь/к/проекту   проверить папку или файл (или просто: aigis путь/к/проекту)
  aigis fix --dry-run         посмотреть, что исправится автоматически
  aigis fix                   исправить
  aigis history               найти секреты за всю историю git

{h}КОМАНДЫ{r}
  scan      найти уязвимости и утёкшие ключи, со ссылкой на каждую строку
  fix       исправить безопасные случаи: секреты в .env, verify=False, random, debug, порты
  history   проверить каждый коммит на секреты, со ссылкой на коммит
  badge     бейдж с оценкой безопасности для README
  init      добавить в проект GitHub Actions workflow и .aigisignore
  rules     список всех правил
  explain   разобрать правило:  aigis explain AIG010
  help      этот экран

{h}ПОЛЕЗНЫЕ ФЛАГИ{r} {d}(scan){r}
  -f json|sarif|markdown      форматы для CI и скриптов   -o ФАЙЛ          записать в файл
  -q, --quiet                 короткий вывод              --min-severity   medium, high, ...
  --fail-on critical|none     порог для exit-кода         -e GLOB          пропустить файлы
  --ai                        исправления от LLM под твой код (AIGIS_API_KEY; секреты не отправляются)

{h}ЯЗЫК{r}
  --lang ru|en   или   AIGIS_LANG=ru     {d}(по умолчанию: язык системы, иначе английский){r}

{h}EXIT-КОДЫ{r}    0 всё ок  ·  1 есть проблемы  ·  2 ошибка запуска
{h}ИСКЛЮЧЕНИЯ{r}   # aigis: ignore[AIG014]  в строке или glob-шаблоны в .aigisignore
{d}Подробнее: aigis <команда> -h  ·  https://github.com/jasperBLCK/AigisSAST{r}
""",
}

WORKFLOW = """\
name: aigis
on: [push, pull_request]

jobs:
  aigis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: jasperBLCK/AigisSAST@v{version}
        with:
          fail-on: high
"""

AIGISIGNORE = """\
# AigisSAST: files and folders to skip (glob patterns, one per line)
# node_modules, .venv, dist, lock files and everything in .gitignore are skipped already
# fixtures/**
# docs/examples/**
"""


def _extract_lang(argv: list[str]) -> tuple[str | None, list[str]]:
    lang, rest, it = None, [], iter(argv)
    for arg in it:
        if arg == "--lang":
            lang = next(it, None)
        elif arg.startswith("--lang="):
            lang = arg.split("=", 1)[1]
        else:
            rest.append(arg)
    return lang, rest


def _build_parser(lang: str) -> argparse.ArgumentParser:
    def h(key: str) -> str:
        return tr(lang, key)

    p = argparse.ArgumentParser(prog="aigis", description=h("h_prog"))
    p.add_argument("--version", action="version", version=f"AigisSAST {__version__}")
    p.add_argument("--lang", choices=i18n.LANGS, help=h("h_lang"))
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help=h("h_scan"), description=h("h_scan"))
    s.add_argument("paths", nargs="*", default=["."], help=h("h_paths"))
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help=h("h_output"))
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help=h("h_minsev"))
    s.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="high", help=h("h_failon"))
    s.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB", help=h("h_exclude"))
    s.add_argument("-q", "--quiet", action="store_true", help=h("h_quiet"))
    s.add_argument("--ai", action="store_true", help=h("h_ai"))
    color = s.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None)
    color.add_argument("--no-color", dest="color", action="store_false")

    fx = sub.add_parser("fix", help=h("h_fix"), description=h("h_fix"))
    fx.add_argument("path", nargs="?", default=".")
    fx.add_argument("--dry-run", action="store_true", help=h("h_dryrun"))

    hi = sub.add_parser("history", help=h("h_history"), description=h("h_history"))
    hi.add_argument("path", nargs="?", default=".")
    hi.add_argument("-f", "--format", choices=["text", "json"], default="text")
    hi.add_argument("-n", "--max-commits", type=int, help=h("h_maxcommits"))

    b = sub.add_parser("badge", help=h("h_badge"), description=h("h_badge"))
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default="aigis-badge.svg", help=h("h_badge_out"))
    b.add_argument("--url", action="store_true", help=h("h_badge_url"))

    i = sub.add_parser("init", help=h("h_init"), description=h("h_init"))
    i.add_argument("path", nargs="?", default=".")

    sub.add_parser("rules", help=h("h_rules"))
    e = sub.add_parser("explain", help=h("h_explain"))
    e.add_argument("rule_id")
    sub.add_parser("help", help=h("h_help"))
    return p


def _merge(results: list[ScanResult]) -> ScanResult:
    if len(results) == 1:
        return results[0]
    merged = ScanResult(root=Path.cwd())
    for r in results:
        prefix = r.root.relative_to(Path.cwd()).as_posix() if r.root.is_relative_to(Path.cwd()) else str(r.root)
        for f in r.findings:
            if prefix not in {".", ""}:
                f.path = f"{prefix}/{f.path}"
            merged.findings.append(f)
        merged.files_scanned += r.files_scanned
    merged.findings.sort(key=lambda f: f.sort_key)
    return merged


def _missing(path: str, lang: str) -> int:
    print(tr(lang, "path_not_found", path=path), file=sys.stderr)
    return 2


def cmd_scan(args: argparse.Namespace, lang: str) -> int:
    min_sev = Severity.parse(args.min_severity)
    results = []
    for raw in args.paths:
        target = Path(raw)
        if not target.exists():
            return _missing(raw, lang)
        results.append(scan_path(target, excludes=args.exclude, min_severity=min_sev))
    result = _merge(results)

    if args.ai:
        note = ai.enrich(result.root, result.findings, lang=lang)
        if note:
            print(f"aigis: {note}", file=sys.stderr)

    color = report.use_color(sys.stdout, args.color) and args.format == "text" and not args.output
    text = report.render(result, args.format, color=color, verbose=not args.quiet, lang=lang)
    report.write(text, args.output)
    fixable = sum(1 for f in result.findings if fix.is_fixable(f))
    if fixable and args.format == "text" and not args.output:
        print(f"  {tr(lang, 'fixable_hint', n=fixable)}\n", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.effective_severity >= threshold for f in result.findings) else 0


def cmd_fix(args: argparse.Namespace, lang: str) -> int:
    target = Path(args.path)
    if not target.exists():
        return _missing(args.path, lang)
    plan = fix.plan(target)
    for f in plan.files:
        print(f.diff())
    if plan.env:
        print(tr(lang, "fix_env_added", keys=", ".join(plan.env)))
    if plan.gitignore_env:
        print(tr(lang, "fix_gitignore"))
    if not args.dry_run:
        fix.apply(plan)

    verb = tr(lang, "fix_will" if args.dry_run else "fix_did")
    print(tr(lang, "fix_summary", verb=verb, n=plan.fixed, manual=len(plan.manual)))
    if plan.env:
        print(tr(lang, "fix_env_note"))
    if plan.gitignore_env and (plan.root / ".git").exists():
        print(tr(lang, "fix_env_cached"))
    for m in plan.manual:
        print(f"  {m.rule.id}  {m.path}:{m.line}  {pick(m.rule.title, lang)}")
    if args.dry_run and plan.fixed:
        print(tr(lang, "fix_apply"))
    return 0


def cmd_history(args: argparse.Namespace, lang: str) -> int:
    root = Path(args.path)
    try:
        leaks = history.scan_history(root, max_commits=args.max_commits)
    except history.NotARepo as exc:
        key = str(exc)
        print(f"aigis: {tr(lang, key) if key in i18n.MESSAGES else key}", file=sys.stderr)
        return 2
    base, _ = gitlink.repo_web(str(root.resolve()))
    if args.format == "json":
        rows = []
        for lk in leaks:
            d = lk.as_dict()
            if base:
                d["commit_url"] = gitlink.commit_url(base, lk.commit)
                d["url"] = gitlink.file_url(base, lk.commit, lk.path)
            rows.append(d)
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 1 if leaks else 0
    if not leaks:
        print(tr(lang, "hist_none"))
        return 0
    print(tr(lang, "hist_found", n=len(leaks)))
    for lk in leaks:
        state = tr(lang, "hist_live" if lk.live else "hist_gone")
        print(f"  [{lk.severity.name}] {lk.rule_id}  {lk.masked}  ({lk.detail})")
        print(
            f"      {lk.path}  ·  {tr(lang, 'hist_commit')} {lk.commit} {tr(lang, 'hist_from')} {lk.date}  ·  {state}"
        )
        if base:
            print(f"      ↗ {gitlink.commit_url(base, lk.commit)}")
    print(tr(lang, "hist_epilogue"))
    return 1


def cmd_badge(args: argparse.Namespace, lang: str) -> int:
    target = Path(args.path)
    if not target.exists():
        return _missing(args.path, lang)
    result = scan_path(target)
    if args.url:
        print(badge.badge_url(result))
        return 0
    Path(args.output).write_text(badge.badge_svg(result), "utf-8")
    print(f"{args.output}: {badge.badge_message(result)}")
    print(f"{tr(lang, 'badge_readme')} ![aigis]({args.output})")
    return 0


def cmd_init(args: argparse.Namespace, lang: str) -> int:
    root = Path(args.path)
    if not root.is_dir():
        return _missing(args.path, lang)
    files = {
        root / ".github" / "workflows" / "aigis.yml": WORKFLOW.format(version=__version__),
        root / ".aigisignore": AIGISIGNORE,
    }
    for path, content in files.items():
        shown = path.relative_to(root).as_posix()
        if path.exists():
            print(tr(lang, "init_exists", path=shown))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, "utf-8")
        print(tr(lang, "init_created", path=shown))
    print(tr(lang, "init_next"))
    return 0


def cmd_rules(lang: str) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity.name:<8}  {r.slug:<26} {pick(r.title, lang)}")
    print(f"\n{tr(lang, 'rules_header', n=len(RULES))}")
    return 0


def cmd_explain(rule_id: str, lang: str) -> int:
    r = RULES.get(rule_id.upper())
    if not r:
        print(tr(lang, "no_rule", rule=rule_id), file=sys.stderr)
        return 2
    print(f"{r.id} · {pick(r.title, lang)}  [{r.severity.name}]\n")
    print(f"{tr(lang, 'explain_why')}\n  {pick(r.why, lang)}\n")
    print(f"{tr(lang, 'explain_fix')}\n  {pick(r.fix, lang)}")
    if r.example:
        print(f"\n{tr(lang, 'explain_example')}\n" + "\n".join("  " + ln for ln in r.example.splitlines()))
    return 0


def cmd_help(lang: str) -> int:
    st = report.Style(report.use_color(sys.stdout, None))
    marks = dict.fromkeys("bhdr", "")
    if st.enabled:
        marks = {"b": "\033[1m", "h": "\033[1;4m", "d": "\033[2m", "r": "\033[0m"}
    print(HELP[lang].format(version=__version__, **marks), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    explicit, rest = _extract_lang(sys.argv[1:] if argv is None else list(argv))
    lang = i18n.resolve(explicit)
    if rest and rest[0] not in COMMANDS and not rest[0].startswith("-") and Path(rest[0]).exists():
        rest = ["scan", *rest]
    args = _build_parser(lang).parse_args(rest)
    if args.command in {None, "help"}:
        return cmd_help(lang)
    if args.command == "rules":
        return cmd_rules(lang)
    if args.command == "explain":
        return cmd_explain(args.rule_id, lang)
    handlers = {"scan": cmd_scan, "fix": cmd_fix, "history": cmd_history, "badge": cmd_badge, "init": cmd_init}
    return handlers[args.command](args, lang)
