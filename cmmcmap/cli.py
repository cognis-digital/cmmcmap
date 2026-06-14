"""Command-line interface for cmmcmap."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CATALOG,
    FAMILIES,
    assess,
    build_ssp,
    build_poam,
    has_findings,
    list_controls,
    render_json,
    render_table,
    score_sprs,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="NIST SP 800-171 / CMMC Level 2 self-assessment: "
                    "110-control catalog, stack-aware gap assessment, SSP + POA&M.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    # controls: list the bundled catalog.
    lc = sub.add_parser("controls", help="List the bundled 800-171 catalog.")
    lc.add_argument("--family", help="Filter to one family abbrev (e.g. AC).")
    lc.add_argument("--format", choices=["table", "json"], default="table")

    # families: list the 14 families.
    fa = sub.add_parser("families", help="List the 14 control families.")
    fa.add_argument("--format", choices=["table", "json"], default="table")

    # assess: stack-aware gap assessment from an inventory JSON.
    asr = sub.add_parser("assess", help="Assess an inventory against the catalog.")
    asr.add_argument("inventory", help="Path to inventory JSON ('-' for stdin).")
    asr.add_argument("--family", help="Limit assessment to one family abbrev.")
    asr.add_argument("--name", default="Information System", help="System name.")
    asr.add_argument("--format", choices=["table", "json"], default="table")
    asr.add_argument("-o", "--output", help="Write report to a file.")

    # score: just the SPRS number.
    sc = sub.add_parser("score", help="Print the SPRS score for an inventory.")
    sc.add_argument("inventory", help="Path to inventory JSON ('-' for stdin).")
    sc.add_argument("--format", choices=["table", "json"], default="table")

    # ssp: emit the System Security Plan skeleton.
    ssp = sub.add_parser("ssp", help="Emit an SSP skeleton (Markdown or JSON).")
    ssp.add_argument("inventory", help="Path to inventory JSON ('-' for stdin).")
    ssp.add_argument("--name", default="Information System", help="System name.")
    ssp.add_argument("--format", choices=["table", "json"], default="table",
                     help="table = Markdown SSP; json = full bundle incl. SSP.")
    ssp.add_argument("-o", "--output", help="Write SSP to a file.")

    # poam: emit the Plan of Action & Milestones.
    pm = sub.add_parser("poam", help="Emit the POA&M for open controls.")
    pm.add_argument("inventory", help="Path to inventory JSON ('-' for stdin).")
    pm.add_argument("--format", choices=["table", "json"], default="table")

    return p


def _load_inventory(path: str) -> dict:
    if path == "-":
        data = sys.stdin.read()
    else:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read()
    inv = json.loads(data)
    if not isinstance(inv, dict):
        raise ValueError("inventory JSON must be an object/dict")
    return inv


def _validate_family(family: Optional[str]) -> int:
    """Return 0 if family is None or a valid 2-letter abbreviation, else print error and return 2."""
    if family is None:
        return 0
    fam = family.upper()
    if fam not in FAMILIES:
        known = ", ".join(sorted(FAMILIES))
        print(
            f"error: unknown family {family!r}. Known families: {known}",
            file=sys.stderr,
        )
        return 2
    return 0


def _write(report: str, output: Optional[str], fmt: str) -> int:
    if output:
        try:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"wrote {fmt} report to {output}", file=sys.stderr)
        except OSError as e:
            print(f"error: cannot write {output}: {e}", file=sys.stderr)
            return 2
    else:
        print(report)
    return 0


def _cmd_controls(args) -> int:
    rc = _validate_family(args.family)
    if rc:
        return rc
    controls = list_controls(args.family)
    if args.format == "json":
        print(json.dumps([c.to_dict() for c in controls], indent=2))
        return 0
    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(controls)} controls")
    print("-" * 72)
    cur = None
    for c in controls:
        if c.family != cur:
            cur = c.family
            print(f"\n[{c.family}] {FAMILIES.get(c.family, c.family)}")
        print(f"  {c.id:<8} (w{c.weight}) {c.title}")
    return 0


def _cmd_families(args) -> int:
    from collections import Counter
    counts = Counter(c.family for c in CATALOG)
    if args.format == "json":
        print(json.dumps(
            [{"abbrev": k, "name": v, "controls": counts.get(k, 0)}
             for k, v in FAMILIES.items()], indent=2))
        return 0
    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(FAMILIES)} families, {len(CATALOG)} controls")
    print("-" * 60)
    for k, v in FAMILIES.items():
        print(f"  {k:<4} {counts.get(k,0):>3}  {v}")
    return 0


def _cmd_assess(args) -> int:
    rc = _validate_family(getattr(args, "family", None))
    if rc:
        return rc
    try:
        inv = _load_inventory(args.inventory)
    except FileNotFoundError:
        print(f"error: file not found: {args.inventory}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = assess(inv, args.family)
    if args.format == "json":
        report = render_json(findings, inv, args.name)
    else:
        report = render_table(findings, args.name)

    rc = _write(report, getattr(args, "output", None), args.format)
    if rc != 0:
        return rc
    return 1 if has_findings(findings) else 0


def _cmd_score(args) -> int:
    try:
        inv = _load_inventory(args.inventory)
    except FileNotFoundError:
        print(f"error: file not found: {args.inventory}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = assess(inv)
    score = score_sprs(findings)
    if args.format == "json":
        print(json.dumps(score, indent=2))
    else:
        print(f"SPRS score: {score['sprs_score']} / {score['max_score']} "
              f"(deduction {score['deduction']})")
        c = score["counts"]
        print(f"  MET {c['MET']}  PARTIAL {c['PARTIAL']}  NOT_MET {c['NOT_MET']}  "
              f"NA {c['NA']}  UNKNOWN {c['UNKNOWN']}")
    return 1 if has_findings(findings) else 0


def _cmd_ssp(args) -> int:
    try:
        inv = _load_inventory(args.inventory)
    except FileNotFoundError:
        print(f"error: file not found: {args.inventory}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = assess(inv)
    if args.format == "json":
        report = render_json(findings, inv, args.name, include_ssp=True)
    else:
        report = build_ssp(inv, findings, args.name)
    rc = _write(report, args.output, args.format)
    if rc != 0:
        return rc
    return 1 if has_findings(findings) else 0


def _cmd_poam(args) -> int:
    try:
        inv = _load_inventory(args.inventory)
    except FileNotFoundError:
        print(f"error: file not found: {args.inventory}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = assess(inv)
    rows = build_poam(findings)
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    else:
        print(f"POA&M — {len(rows)} open item(s)")
        print("-" * 72)
        for r in rows:
            print(f"#{r['item']:<3} {r['control']:<8} [{r['status']}] "
                  f"(w{r['weight']}) {r['weakness']}")
            print(f"      finding: {r['finding']}")
            if r["remediation"]:
                print(f"      fix: {r['remediation']}")
    return 1 if rows else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "controls": _cmd_controls,
        "families": _cmd_families,
        "assess": _cmd_assess,
        "score": _cmd_score,
        "ssp": _cmd_ssp,
        "poam": _cmd_poam,
    }
    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        return 0
    try:
        return fn(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pylint: disable=broad-except
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
