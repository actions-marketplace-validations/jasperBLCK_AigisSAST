from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aigis import __version__, ai, badge, fix, gitlink, history, report
from aigis.models import Severity
from aigis.rules import RULES
from aigis.scanner import ScanResult, scan_path

SEVERITIES = [s.label for s in Severity]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aigis",
        description="AigisSAST: security scanner for AI-generated code.",
    )
    p.add_argument("--version", action="version", version=f"AigisSAST {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project (default: current directory)")
    s.add_argument("paths", nargs="*", default=["."], help="files or directories to scan")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this level")
    s.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "none"],
        default="high",
        help="exit with code 1 if a finding of this level or higher exists (default: high)",
    )
    s.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB", help="extra glob to skip")
    s.add_argument("-q", "--quiet", action="store_true", help="text format: hide 'why' and 'fix' blocks")
    s.add_argument(
        "--ai",
        action="store_true",
        help="ask an OpenAI-compatible LLM for context-specific fixes (needs AIGIS_API_KEY)",
    )
    color = s.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None)
    color.add_argument("--no-color", dest="color", action="store_false")

    fx = sub.add_parser("fix", help="auto-fix safe cases: secrets to .env, verify=False, random, debug, ports")
    fx.add_argument("path", nargs="?", default=".")
    fx.add_argument("--dry-run", action="store_true", help="only show the diff, do not change files")

    h = sub.add_parser("history", help="find secrets ever committed to git history")
    h.add_argument("path", nargs="?", default=".")
    h.add_argument("-f", "--format", choices=["text", "json"], default="text")
    h.add_argument("-n", "--max-commits", type=int, help="only check the last N commits")

    b = sub.add_parser("badge", help="security grade badge for your README")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default="aigis-badge.svg", help="SVG file (default: aigis-badge.svg)")
    b.add_argument("--url", action="store_true", help="print a shields.io URL instead of writing an SVG")

    sub.add_parser("rules", help="list all rules")
    e = sub.add_parser("explain", help="show a rule in detail")
    e.add_argument("rule_id")
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


def cmd_scan(args: argparse.Namespace) -> int:
    min_sev = Severity.parse(args.min_severity)
    results = []
    for raw in args.paths:
        target = Path(raw)
        if not target.exists():
            print(f"aigis: путь не найден: {raw}", file=sys.stderr)
            return 2
        results.append(scan_path(target, excludes=args.exclude, min_severity=min_sev))
    result = _merge(results)

    if args.ai:
        note = ai.enrich(result.root, result.findings)
        if note:
            print(f"aigis: {note}", file=sys.stderr)

    color = report.use_color(sys.stdout, args.color) and args.format == "text" and not args.output
    report.write(report.render(result, args.format, color=color, verbose=not args.quiet), args.output)
    fixable = sum(1 for f in result.findings if fix.is_fixable(f))
    if fixable and args.format == "text" and not args.output:
        print(f"  {fixable} можно исправить автоматически: aigis fix --dry-run\n", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.effective_severity >= threshold for f in result.findings) else 0


def cmd_fix(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"aigis: путь не найден: {args.path}", file=sys.stderr)
        return 2
    plan = fix.plan(target)
    for f in plan.files:
        print(f.diff())
    if plan.env:
        print(f"+ .env: {', '.join(plan.env)} (значения перенесены из кода)")
    if plan.gitignore_env:
        print("+ .gitignore: .env")
    if not args.dry_run:
        fix.apply(plan)

    verb = "будет исправлено" if args.dry_run else "исправлено"
    print(f"\naigis fix: {verb} {plan.fixed}, вручную осталось {len(plan.manual)}")
    if plan.env:
        print("  Ключи из кода теперь читаются из окружения. Подгрузи .env (python-dotenv, docker --env-file)")
        print("  и перевыпусти эти ключи: они уже были в коде. Старые коммиты проверит `aigis history`.")
    if plan.gitignore_env and (plan.root / ".git").exists():
        print("  Если .env уже закоммичен, убери его из индекса: git rm --cached .env")
    for m in plan.manual:
        print(f"  {m.rule.id}  {m.path}:{m.line}  {m.rule.title}")
    if args.dry_run and plan.fixed:
        print("\nПрименить: aigis fix")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        leaks = history.scan_history(root, max_commits=args.max_commits)
    except history.NotARepo as exc:
        print(f"aigis: {exc}", file=sys.stderr)
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
        print("aigis history: секретов в истории git не найдено")
        return 0
    print(f"aigis history: секретов в истории git: {len(leaks)}\n")
    for lk in leaks:
        state = "ещё в коде" if lk.live else "удалён, но остался в истории"
        print(f"  [{lk.severity.name}] {lk.rule_id}  {lk.masked}  ({lk.detail})")
        print(f"      {lk.path}  ·  коммит {lk.commit} от {lk.date}  ·  {state}")
        if base:
            print(f"      {gitlink.commit_url(base, lk.commit)}")
    print(
        "\nУдалить коммит мало: любой, кто склонировал репо, видит старые версии файлов.\n"
        "1. Отзови и перевыпусти каждый ключ.\n"
        "2. Если нужно, вычисти историю: git filter-repo --replace-text или BFG, затем force push."
    )
    return 1


def cmd_badge(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"aigis: путь не найден: {args.path}", file=sys.stderr)
        return 2
    result = scan_path(target)
    if args.url:
        print(badge.badge_url(result))
        return 0
    Path(args.output).write_text(badge.badge_svg(result), "utf-8")
    print(f"{args.output}: {badge.badge_message(result)}")
    print(f"README: ![aigis]({args.output})")
    return 0


def cmd_rules() -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity.name:<8}  {r.slug:<26} {r.title}")
    return 0


def cmd_explain(rule_id: str) -> int:
    r = RULES.get(rule_id.upper())
    if not r:
        print(f"aigis: нет правила {rule_id}. Список: aigis rules", file=sys.stderr)
        return 2
    print(f"{r.id} · {r.title}  [{r.severity.name}]\n")
    print(f"Чем опасно:\n  {r.why}\n")
    print(f"Как исправить:\n  {r.fix}")
    if r.example:
        print("\nПример:\n" + "\n".join("  " + ln for ln in r.example.splitlines()))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return cmd_rules()
    if args.command == "explain":
        return cmd_explain(args.rule_id)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "fix":
        return cmd_fix(args)
    if args.command == "history":
        return cmd_history(args)
    if args.command == "badge":
        return cmd_badge(args)
    parser.print_help()
    return 0
