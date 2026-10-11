#!/usr/bin/env python3
"""Daily report for a scanned system: reads the grype report
(reports/<host>.vulns.json), the SBOM, the source feed and two flake.lock
files, and writes a Markdown summary and, when something needs a human, the
body of the tracking issue.

The summary holds:
- a one-line status record (key=value) for later plotting
- every flake input as committed and as scanned
- active / acknowledged / untriaged counts with the grype DB build date
- the untriaged findings, grouped by package
- versioned statements that no longer match: their package moved to a
  version the feed has no statement for (what carry-forward must cover)
- watched CVE records ([vexlint:watch_record=<dateUpdated>]) whose
  dateUpdated changed

The issue body is written only when there are untriaged findings or changed
watched records; otherwise an existing issue file is removed. It ends with an
HTML comment holding a hash of what needs a human (no dates, no run links),
so the workflow can tell a changed backlog from a re-run. Untriaged
findings are backlog, not an error: the script exits non-zero only on
unreadable input.

Paths are relative to the repository root, whatever the working directory.

Usage: daily-report.py <host> --vex <feed.json> --base-lock <committed flake.lock>
         --summary <out.md> --issue <out.md> [--offline]
"""

import argparse
import datetime
import hashlib
import http.client
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from typing import NoReturn, NotRequired, TypedDict, cast

from zero import REPORTS, Descriptor, Report, Untriaged, db_built, load_acknowledged, triage

ROOT = pathlib.Path(__file__).resolve().parent.parent
CVE_API = "https://cveawg.mitre.org/api/cve/"
WATCH = re.compile(r"\[vexlint:watch_record=([^\]]+)\]")
# GitHub rejects issue bodies above 65536 characters.
ISSUE_LIMIT = 60000
# Marks the hash of what needs a human in the issue body.
ISSUE_KEY = "nixos-vex-daily-key: "


class Locked(TypedDict):
    type: NotRequired[str]
    owner: NotRequired[str]
    repo: NotRequired[str]
    rev: NotRequired[str]
    lastModified: NotRequired[int]


class LockNode(TypedDict):
    inputs: NotRequired[dict[str, str | list[str]]]
    locked: NotRequired[Locked]


class Lock(TypedDict):
    root: str
    nodes: dict[str, LockNode]


class Vuln(TypedDict):
    name: str


class Statement(TypedDict):
    vulnerability: Vuln
    # Each product is {"@id": <purl>}; "@id" is no valid TypedDict key.
    products: list[dict[str, str]]
    status: str
    status_notes: NotRequired[str]


class Feed(TypedDict):
    statements: list[Statement]


class Component(TypedDict):
    name: str
    purl: NotRequired[str]


class Tool(TypedDict):
    name: NotRequired[str]
    version: NotRequired[str]


class SbomMetadata(TypedDict):
    tools: NotRequired[list[Tool]]


class Sbom(TypedDict):
    components: NotRequired[list[Component]]
    metadata: NotRequired[SbomMetadata]


class CveMetadata(TypedDict):
    dateUpdated: NotRequired[str]


class CveRecord(TypedDict):
    cveMetadata: NotRequired[CveMetadata]


class Input(TypedDict):
    rev: str
    date: str


class Moved(TypedDict):
    package: str
    version: str
    now: list[str]
    statements: int


class Watched(TypedDict):
    cve: str
    marker: str
    current: str


def die(msg: str) -> NoReturn:
    print(f"daily-report: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: pathlib.Path) -> object:
    try:
        return cast("object", json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path}: {e}")


def lock_inputs(path: pathlib.Path) -> dict[str, Input]:
    """The root inputs of a flake.lock: name -> locked rev and date."""
    lock = cast("Lock", read_json(path))
    root = lock["nodes"][lock["root"]].get("inputs", {})
    out: dict[str, Input] = {}
    for name, ref in sorted(root.items()):
        if not isinstance(ref, str):
            continue  # a `follows` path, not a locked node of its own
        locked = lock["nodes"][ref].get("locked", Locked())
        modified = locked.get("lastModified")
        date = (
            datetime.datetime.fromtimestamp(modified, datetime.UTC).strftime("%Y-%m-%d")
            if modified is not None
            else "?"
        )
        out[name] = Input(rev=locked.get("rev", "?"), date=date)
    return out


def purl_parts(purl: str) -> tuple[str, str | None]:
    """pkg:nix/name@version?q#s -> (name, version or None)."""
    base = purl.split("?", 1)[0].split("#", 1)[0].removeprefix("pkg:nix/")
    name, _, version = base.partition("@")
    return name, version or None


def moved_statements(feed: Feed, sbom: Sbom) -> list[Moved]:
    """Versioned statements for a package the SBOM now ships at other versions."""
    shipped: dict[str, set[str]] = defaultdict(set)
    for c in sbom.get("components", []):
        name, version = purl_parts(c.get("purl", ""))
        if version is not None:
            shipped[name].add(version)
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for st in feed["statements"]:
        for p in st["products"]:
            name, version = purl_parts(p.get("@id", ""))
            if version is not None and name in shipped and version not in shipped[name]:
                counts[(name, version)] += 1
    return [
        Moved(package=name, version=version, now=sorted(shipped[name]), statements=n)
        for (name, version), n in sorted(counts.items())
    ]


def watched_records(feed: Feed, offline: bool) -> tuple[list[Watched], list[str]]:
    """Watched statements whose CVE record changed, and records that could not be read."""
    changed: list[Watched] = []
    errors: list[str] = []
    for st in feed["statements"]:
        found = WATCH.search(st.get("status_notes", ""))
        if found is None:
            continue
        cve, marker = st["vulnerability"]["name"], found.group(1)
        if offline:
            errors.append(f"{cve}: not checked (--offline)")
            continue
        try:
            with cast("http.client.HTTPResponse", urllib.request.urlopen(CVE_API + cve, timeout=30)) as resp:
                record = cast("CveRecord", json.loads(resp.read()))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            errors.append(f"{cve}: {e}")
            continue
        current = record.get("cveMetadata", CveMetadata()).get("dateUpdated", "?")
        if current != marker:
            changed.append(Watched(cve=cve, marker=marker, current=current))
    return changed, errors


def sbomnix_version(sbom: Sbom) -> str:
    for t in sbom.get("metadata", SbomMetadata()).get("tools", []):
        if t.get("name") == "sbomnix":
            return t.get("version", "?")
    return "?"


def input_cell(i: Input | None) -> str:
    return f"`{i['rev'][:12]}` ({i['date']})" if i else "-"


def grouped(untriaged: list[Untriaged]) -> list[str]:
    """Markdown lines: one heading per package, its findings most severe first."""
    by_pkg: dict[str, list[Untriaged]] = defaultdict(list)
    for u in untriaged:
        by_pkg[u.purl.removeprefix("pkg:nix/")].append(u)
    lines: list[str] = []
    for pkg, items in sorted(by_pkg.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"\n**{pkg}** ({len(items)})\n")
        lines.extend(f"- {u.cve} ({u.severity})" for u in items)
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("host")
    _ = parser.add_argument("--vex", action="append", default=[], help="OpenVEX document the scan used (repeatable)")
    _ = parser.add_argument("--base-lock", required=True, help="flake.lock as committed")
    _ = parser.add_argument("--summary", required=True, help="Markdown summary to write")
    _ = parser.add_argument("--issue", required=True, help="issue body to write (removed when nothing needs a human)")
    _ = parser.add_argument("--offline", action="store_true", help="do not fetch watched CVE records")
    args = parser.parse_args()
    host = cast("str", args.host)
    vex_paths = cast("list[str]", args.vex)
    if not vex_paths:
        die("at least one --vex document is required")
    issue_path = pathlib.Path(cast("str", args.issue))

    report = cast("Report", read_json(REPORTS / f"{host}.vulns.json"))
    feed = cast("Feed", read_json(ROOT / "vex" / "baseline.openvex.json"))
    sbom = cast("Sbom", read_json(ROOT / "sboms" / f"{host}.cdx.json"))
    base = lock_inputs(pathlib.Path(cast("str", args.base_lock)))
    now = lock_inputs(ROOT / "flake.lock")

    acked = [pair for path in vex_paths for pair in load_acknowledged(path)]
    active, untriaged = triage(report, acked)
    built = db_built(report)
    moved = moved_statements(feed, sbom)
    changed, errors = watched_records(feed, cast("bool", args.offline))
    grype_version = report.get("descriptor", Descriptor()).get("version", "?")
    nixpkgs = now.get("nixpkgs", Input(rev="?", date="?"))

    server, repo, run = (os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    run_url = f"{server}/{repo}/actions/runs/{run}" if server and repo and run else None

    status = " ".join(
        f"{k}={v}"
        for k, v in {
            "host": host,
            "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nixpkgs": nixpkgs["rev"],
            "nixpkgs_date": nixpkgs["date"],
            "db_built": built,
            "active": active,
            "acknowledged": active - len(untriaged),
            "untriaged": len(untriaged),
            "moved_statements": sum(m["statements"] for m in moved),
            "watched_changed": len(changed),
        }.items()
    )
    counts = (
        f"**{active} active, {active - len(untriaged)} acknowledged, {len(untriaged)} untriaged** "
        + f"(grype DB built {built}; grype {grype_version}; sbomnix {sbomnix_version(sbom)})"
    )

    s = [f"# Daily scan: {host}", "", "```", status, "```", "", counts, "", "## Inputs", ""]
    s += ["| Input | Committed | Scanned |", "|---|---|---|"]
    for name in sorted(base.keys() | now.keys()):
        b, n = base.get(name), now.get(name)
        s.append(f"| {name} | {input_cell(b)} | {input_cell(n)}{'' if b == n else ' (moved)'} |")
    s += ["", f"## Untriaged findings ({len(untriaged)})"]
    s += grouped(untriaged) if untriaged else ["", "None."]
    s += ["", f"## Versioned statements that no longer match ({sum(m['statements'] for m in moved)})", ""]
    if moved:
        s += ["| Package | Feed version | Scanned version(s) | Statements |", "|---|---|---|---|"]
        s += [f"| {m['package']} | {m['version']} | {', '.join(m['now'])} | {m['statements']} |" for m in moved]
    else:
        s.append("None.")
    s += ["", "## Watched CVE records", ""]
    s += [f"- **changed:** {w['cve']}: marker {w['marker']}, record now {w['current']}" for w in changed]
    s += [f"- could not check {e}" for e in errors]
    if not changed and not errors:
        s.append("No change.")
    _ = pathlib.Path(cast("str", args.summary)).write_text("\n".join(s) + "\n")

    if not untriaged and not changed:
        issue_path.unlink(missing_ok=True)
        return
    i = [f"Daily scan of `{host}`" + (f" ([run]({run_url}))" if run_url else "") + ".", "", counts, ""]
    i += [f"nixpkgs `{nixpkgs['rev'][:12]}` ({nixpkgs['date']})."]
    if changed:
        i += ["", "## Watched CVE records changed", ""]
        i += [f"- {w['cve']}: marker {w['marker']}, record now {w['current']}" for w in changed]
    if untriaged:
        i += ["", f"## Untriaged findings ({len(untriaged)})", *grouped(untriaged)]
    body = "\n".join(i) + "\n"
    if len(body) > ISSUE_LIMIT:
        body = body[:ISSUE_LIMIT] + "\n\n(truncated; the run summary has the full list)\n"
    # What needs a human, without dates or run links: the issue job comments
    # (and so notifies) only when this changes.
    key = "\n".join(
        [f"{u.cve} {u.purl}" for u in untriaged] + [f"{w['cve']} {w['marker']} {w['current']}" for w in changed]
    )
    body += f"\n<!-- {ISSUE_KEY}{hashlib.sha256(key.encode()).hexdigest()} -->\n"
    _ = issue_path.write_text(body)


if __name__ == "__main__":
    main()
