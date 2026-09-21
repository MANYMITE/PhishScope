"""Command-line interface: python -m phishscope [--explain] [--json] URL..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import Report, analyze
from . import __version__

BAR_WIDTH = 28

# Score bar characters: box-drawing glyphs on Unicode-capable consoles,
# plain ASCII fallback for Windows cp1252 and friends.
try:
    "█░".encode(sys.stdout.encoding or "ascii")
    BAR_FILLED, BAR_EMPTY = "█", "░"
except (UnicodeEncodeError, LookupError):
    BAR_FILLED, BAR_EMPTY = "#", "-"


def _verdict_color(verdict: str) -> str:
    colors = {
        "CRITICAL": "\033[91m",  # bright red
        "HIGH": "\033[31m",      # red
        "MEDIUM": "\033[33m",    # yellow
        "LOW": "\033[36m",       # cyan
        "CLEAN": "\033[32m",     # green
    }
    return colors.get(verdict, "")


RESET = "\033[0m"
BOLD = "\033[1m"


def _score_bar(score: int) -> str:
    filled = round(score / 100 * BAR_WIDTH)
    return BAR_FILLED * filled + BAR_EMPTY * (BAR_WIDTH - filled)


def render_report(report: Report, explain: bool = False, color: bool = True) -> str:
    """Human-readable report for one URL."""
    color_on = color
    col = _verdict_color(report.verdict) if color_on else ""
    reset = RESET if color_on else ""
    bold = BOLD if color_on else ""

    lines = [
        f"{bold}URL:{reset}     {report.url}",
        f"{bold}Verdict:{reset} {col}{report.verdict}{reset}  "
        f"{col}{_score_bar(report.score)}{reset} {report.score}/100",
    ]

    if not report.flags:
        lines.append(f"{bold}Flags:{reset}    none — no heuristics triggered")
    else:
        lines.append(f"{bold}Flags:{reset}")
        for flag in report.flags:
            lines.append(f"  {col}[{flag.weight:>2}]{reset} {flag.name}")
            if explain:
                lines.append(f"        {flag.why}")
    return "\n".join(lines)


def _read_urls(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishscope",
        description="Offline, explainable phishing-URL risk scoring.",
        epilog="Every flag ships with a 'why' — pass --explain to see it.",
    )
    parser.add_argument("urls", nargs="*", help="URL(s) to analyze")
    parser.add_argument("-f", "--file", help="file with one URL per line")
    parser.add_argument("-j", "--json", action="store_true",
                        help="emit JSON instead of the pretty report")
    parser.add_argument("--json-out", metavar="PATH",
                        help="also write JSON results to PATH")
    parser.add_argument("-e", "--explain", action="store_true",
                        help="show the reasoning behind every flag")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only print URL + verdict + score")
    parser.add_argument("-V", "--version", action="version",
                        version=f"phishscope {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    urls = list(args.urls)
    if args.file:
        try:
            urls.extend(_read_urls(args.file))
        except OSError as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
    if not urls:
        print("error: no URLs given (pass URLs or --file)", file=sys.stderr)
        return 2

    reports = [analyze(u) for u in urls]

    if args.json or args.json_out:
        payload = json.dumps([r.to_dict() for r in reports], indent=2)
        if args.json_out:
            Path(args.json_out).write_text(payload + "\n", encoding="utf-8")
        if args.json:
            print(payload)

    if not args.json:
        for i, report in enumerate(reports):
            if i and not args.quiet:
                print()
            if args.quiet:
                print(f"{report.verdict:<8} {report.score:>3}  {report.url}")
            else:
                print(render_report(report, explain=args.explain))

    # MEDIUM or worse fails the run, so CI pipelines can gate on it.
    return 1 if any(r.is_suspicious for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
