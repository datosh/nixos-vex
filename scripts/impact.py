#!/usr/bin/env python3
"""What a pull request changes, at identical inputs.

Compares two grype reports of the same SBOM and DB: one scanned with the
base branch's generated feed, one with the head's. Differences therefore come
from triage only. Prints Markdown for the job summary:
- untriaged before and after
- newly suppressed (not_affected/fixed), newly acknowledged (affected)
- regressed: triaged with the base feed, untriaged with the head feed
- statements added, removed and changed between the two source feeds

Informational only: the zero gate (zero.py) decides; this exits non-zero only
on unreadable input.

Usage: impact.py --base-report R --base-vex V --base-feed F
                 --head-report R --head-vex V --head-feed F
"""

import argparse
import json
import pathlib
import sys
from typing import NoReturn, cast

from zero import Report, active, load_acknowledged, triage


def die(msg: str) -> NoReturn:
    print(f"impact: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: str) -> object:
    try:
        return cast("object", json.loads(pathlib.Path(path).read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path}: {e}")


def side(report_path: str, vex_path: str) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """(active findings, untriaged findings) as (CVE, purl) pairs."""
    report = cast("Report", read_json(report_path))
    _, untriaged = triage(report, load_acknowledged(vex_path))
    return set(active(report)), {(u.cve, u.purl) for u in untriaged}


def statements(feed_path: str) -> dict[str, str]:
    """@id -> the statement as canonical JSON."""
    doc = cast("dict[str, object]", read_json(feed_path))
    return {
        cast("str", st["@id"]): json.dumps(st, sort_keys=True)
        for st in cast("list[dict[str, object]]", doc.get("statements", []))
    }


def listing(title: str, pairs: set[tuple[str, str]]) -> list[str]:
    if not pairs:
        return []
    lines = ["", f"<details><summary>{title} ({len(pairs)})</summary>", ""]
    lines += [f"- {cve} {purl.removeprefix('pkg:nix/')}" for cve, purl in sorted(pairs, key=lambda p: (p[1], p[0]))]
    return [*lines, "", "</details>"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for which in ("base", "head"):
        for what in ("report", "vex", "feed"):
            _ = parser.add_argument(f"--{which}-{what}", required=True)
    args = cast("dict[str, str]", vars(parser.parse_args()))

    def arg(key: str) -> str:
        return args[key]

    active_b, untriaged_b = side(arg("base_report"), arg("base_vex"))
    active_h, untriaged_h = side(arg("head_report"), arg("head_vex"))
    suppressed = active_b - active_h
    acknowledged = (untriaged_b & active_h) - untriaged_h
    regressed = untriaged_h - untriaged_b

    base, head = statements(arg("base_feed")), statements(arg("head_feed"))
    added = head.keys() - base.keys()
    removed = base.keys() - head.keys()
    changed = {i for i in base.keys() & head.keys() if base[i] != head[i]}

    lines = [
        "## Impact of this pull request",
        "",
        f"At this branch's pins: **{len(untriaged_b)} untriaged with the base feed → {len(untriaged_h)} with this branch's feed.**",
        "",
        "| Findings | Count |",
        "|---|---|",
        f"| Newly suppressed (`not_affected`, `fixed`) | {len(suppressed)} |",
        f"| Newly acknowledged (`affected`) | {len(acknowledged)} |",
        f"| Still untriaged | {len(untriaged_b & untriaged_h)} |",
        f"| **Regressed** (triaged on base, untriaged here) | {len(regressed)} |",
        "",
        f"Statements: {len(added)} added, {len(changed)} changed, {len(removed)} removed.",
    ]
    lines += listing("Regressed", regressed)
    lines += listing("Still untriaged", untriaged_b & untriaged_h)
    lines += listing("Newly acknowledged", acknowledged)
    lines += listing("Newly suppressed", suppressed)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
