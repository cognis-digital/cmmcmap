"""Command-line interface for cmmcmap."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    StackError,
    load_stack,
    map_stack,
    coverage_report,
    build_ssp_skeleton,
    practice_catalog,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _emit(obj: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2))
        return
    # table format
    if isinstance(obj, dict) and "practices" in obj:
        rows = obj["practices"]
        print(f"System: {obj['system_name']}")
        print(f"{'PRACTICE':<16} {'DOM':<4} {'STATUS':<10} TITLE")
        print("-" * 72)
        for r in rows:
            print(f"{r['id']:<16} {r['domain']:<4} {r['status']:<10} {r['title']}")
    elif isinstance(obj, dict) and "counts" in obj:
        c = obj["counts"]
        print(f"System: {obj['system_name']}")
        print(f"Total practices : {obj['total_practices']}")
        print(f"Coverage score  : {obj['coverage_score']}")
        print(f"Satisfied/Partial/Planned: "
              f"{c['satisfied']}/{c['partial']}/{c['planned']}")
        print(f"{'DOMAIN':<8} SAT PART PLAN TOTAL")
        for dom, d in sorted(obj["per_domain"].items()):
            print(f"{dom:<8} {d['satisfied']:>3} {d['partial']:>4} "
                  f"{d['planned']:>4} {d['total']:>5}")
    elif isinstance(obj, list):
        print(f"{'PRACTICE':<16} {'DOM':<4} TITLE")
        print("-" * 72)
        for r in obj:
            print(f"{r['id']:<16} {r['domain']:<4} {r['title']}")
    else:
        print(json.dumps(obj, indent=2))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="CMMC Level 2 practice mapper and SSP skeleton generator.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="json",
                   help="output format (default: json)")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("map", help="map a stack to CMMC practices")
    m.add_argument("stack", help="path to stack JSON ('-' for stdin)")

    c = sub.add_parser("coverage", help="summarize coverage for a stack")
    c.add_argument("stack", help="path to stack JSON ('-' for stdin)")

    s = sub.add_parser("ssp", help="generate an OSCAL-flavored SSP skeleton")
    s.add_argument("stack", help="path to stack JSON ('-' for stdin)")

    sub.add_parser("catalog", help="list the CMMC L2 practice catalog")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "catalog":
            _emit(practice_catalog(), args.format)
            return 0

        stack = load_stack(_read(args.stack))
        mapping = map_stack(stack)

        if args.command == "map":
            _emit(mapping, args.format)
        elif args.command == "coverage":
            _emit(coverage_report(mapping), args.format)
        elif args.command == "ssp":
            # SSP is structured OSCAL; always JSON regardless of --format
            print(json.dumps(build_ssp_skeleton(mapping), indent=2))
        return 0
    except StackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
