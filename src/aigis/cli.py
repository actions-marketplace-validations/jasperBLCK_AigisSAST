from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aigis import __version__, ai, report
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

    if args.fail_on == "none":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.effective_severity >= threshold for f in result.findings) else 0


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
    parser.print_help()
    return 0
