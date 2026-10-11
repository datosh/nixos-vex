#!/usr/bin/env python3
"""Carry decided verdicts forward to the versions a bump brought in
(`make carry-forward`).

Reads the scan after `make bump` (reports/<host>.vulns.json), the SBOM, the
kernel drafts of kernel-cna-triage.py (reports/kernel-triage-<host>.json) and
the feed. Only untriaged findings are considered, and only those whose CVE
and package already have a verdict for another version. New CVEs, and
anything the rules below cannot prove, stay untriaged for a human.

Rules (the earlier verdict is the newest statement for that CVE and package):
- kernel, the draft is an automatic class with the same status: extend
- kernel, earlier `fixed`, no stable release up to ours reverts the fix: extend
- kernel, earlier `affected`, the draft is an automatic `fixed` class: new
  statement from the draft
- kernel, earlier `affected`, not fixed yet: extend (listed for a re-check)
- userland, the SBOM's patch pedigree resolves the CVE: extend an earlier
  `fixed`, otherwise a new `fixed` statement
- userland, earlier `fixed` or `affected` on the same release line (the same
  first two version numbers, not older): extend (`affected` listed for a
  re-check). Not for a `fixed` whose text names a patch: a nixpkgs patch
  carries over only through the pedigree rule above
- earlier `not_affected` outside the kernel's automatic classes: left

"Extend" adds the new version's purl to the statement's products, sets its
last_updated and appends (once per rule) a sentence to status_notes saying
why the later versions are covered; the original text stays as the record of
the first triage. A new statement gets the plain @id fragment (#<CVE>-<pkg>)
when it is free, otherwise the version is appended (#<CVE>-<pkg>-<version>),
and its timestamp is today (the document's timestamp predates it). Writes go through feed.py, which bumps
the feed's version once per branch and logs each one under triage/ as a
decision of the rule's name (signed off per class).

Writes the feed in place, a Markdown report (for the PR description) and
reports/carry-forward-<host>.json (for triage-report.py). --dry-run writes
only the reports: the preview the user signs off per rule.

Paths are relative to the repository root, whatever the working directory.

Usage: carry-forward.py <host> --vex <generated feed> [--report out.md] [--dry-run]
"""

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict
from typing import NoReturn, NotRequired, TypedDict, cast

from feed import Feed, rule_origin
from zero import REPORTS, Report, Untriaged, load_acknowledged, triage

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The rules, by the name decisions are logged under, with the report heading.
RULES = {
    "kernel-auto-agrees": "extended: the kernel draft's automatic class agrees",
    "kernel-no-revert": "extended: earlier fixed, no revert in the stable ChangeLogs",
    "kernel-now-fixed": "new fixed statement from the kernel draft, earlier affected",
    "kernel-still-unfixed": "extended: earlier affected, still unfixed",
    "pedigree-extend": "extended: nixpkgs patch (SBOM pedigree)",
    "pedigree-new": "new fixed statement: nixpkgs patch (SBOM pedigree)",
    "line-fixed": "extended: earlier fixed on the same release line",
    "line-affected": "extended: earlier affected on the same release line",
}

# Appended to status_notes (once each) when a rule extends a statement.
WHY_AUTO = "Later versions in products: the same upstream data gives the same verdict for them."
WHY_NO_REVERT = "Later versions in products: carried forward; no stable release since reverts the fix."
WHY_KERNEL_UNFIXED = "Later versions in products: carried forward; their stable ChangeLogs contain no fix yet."
WHY_PEDIGREE = "Later versions in products: their SBOM patch pedigree still lists the patch."
WHY_LINE_FIXED = "Later versions in products: later releases on the same release line keep the fix."
WHY_LINE_AFFECTED = (
    "Later versions in products: carried forward on the same release line; no fix confirmed for them yet."
)


class Vuln(TypedDict):
    name: str


class Statement(TypedDict):
    vulnerability: Vuln
    # Each product is {"@id": <purl>}; "@id" is no valid TypedDict key.
    products: list[dict[str, str]]
    status: str


class Done(TypedDict):
    rule: str
    cve: str
    purl: str
    severity: str
    statement: str
    detail: str
    written: NotRequired[dict[str, object]]  # a new statement, as written


class Left(TypedDict):
    reason: str
    cve: str
    purl: str
    severity: str


class Result(TypedDict):
    total: int
    done: list[Done]
    recheck: list[str]
    left: list[Left]


class Draft(TypedDict):
    cve: str
    klass: str
    statement: dict[str, object] | None
    reverts: list[str]


class Resolves(TypedDict):
    type: NotRequired[str]
    id: NotRequired[str]
    references: NotRequired[list[str]]


class Patch(TypedDict):
    resolves: NotRequired[list[Resolves]]


class Pedigree(TypedDict):
    patches: NotRequired[list[Patch]]


class Component(TypedDict):
    purl: NotRequired[str]
    pedigree: NotRequired[Pedigree]


class Sbom(TypedDict):
    components: NotRequired[list[Component]]


def die(msg: str) -> NoReturn:
    print(f"carry-forward: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: pathlib.Path) -> object:
    try:
        return cast("object", json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path}: {e}")


def purl_parts(purl: str) -> tuple[str, str | None]:
    """pkg:nix/name@version?q#s -> (name, version or None)."""
    base = purl.split("?", 1)[0].split("#", 1)[0].removeprefix("pkg:nix/")
    name, _, version = base.partition("@")
    return name, version or None


def numbers(version: str) -> list[int]:
    """The numbers of a version, in order: 2.44-25 -> [2, 44, 25], 10.5p1 -> [10, 5, 1]."""
    return [int(n) for n in cast("list[str]", re.findall(r"\d+", version))]


def same_line_not_older(old: str, new: str) -> bool:
    """Same release line (first two numbers) and new is not older than old."""
    o, n = numbers(old), numbers(new)
    return len(o) >= 2 and o[:2] == n[:2] and n >= o


def pedigree_fixes(sbom: Sbom) -> dict[tuple[str, str], list[str]]:
    """(CVE, purl) -> the names of the nixpkgs patches resolving it, in SBOM
    order. sbomnix records them per component under
    pedigree.patches[].resolves[] (type "security", id = CVE); grype ignores
    that field."""
    fixes: dict[tuple[str, str], list[str]] = {}
    for comp in sbom.get("components", []):
        purl = comp.get("purl")
        if not purl:
            continue
        pedigree = comp.get("pedigree") or Pedigree()
        for patch in pedigree.get("patches", []):
            for resolves in patch.get("resolves", []):
                vuln_id = resolves.get("id")
                if resolves.get("type") != "security" or not vuln_id:
                    continue
                names = fixes.setdefault((vuln_id, purl), [])
                for ref in resolves.get("references", []):
                    # file:///nix/store/<hash>-<name>.patch -> <name>.patch
                    name = ref.rsplit("/", 1)[-1].split("-", 1)[-1]
                    if name not in names:
                        names.append(name)
    return fixes


def rests_on_patch(st: dict[str, object]) -> bool:
    """A verdict that a nixpkgs patch provides (its text names a patch)."""
    return "patch" in cast("str", st.get("status_notes", "")).lower()


def earlier(feed: Feed, cve: str, name: str) -> dict[str, object] | None:
    """The newest statement (last in feed order) for this CVE and package."""
    found: dict[str, object] | None = None
    for st in feed.statements:
        s = cast("Statement", cast("object", st))
        if s["vulnerability"]["name"] == cve and any(purl_parts(p.get("@id", ""))[0] == name for p in s["products"]):
            found = st
    return found


def newest_version(st: dict[str, object], name: str) -> str | None:
    versions = [
        v
        for p in cast("list[dict[str, str]]", st["products"])
        for n, v in [purl_parts(p.get("@id", ""))]
        if n == name and v
    ]
    return max(versions, key=numbers) if versions else None


def pedigree_statement(cve: str, name: str, version: str, patches: list[str], pin: str) -> dict[str, object]:
    return {
        "vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{cve}", "name": cve},
        "products": [{"@id": f"pkg:nix/{name}@{version}"}],
        "status": "fixed",
        "status_notes": f"nixpkgs applies {', '.join(patches) or 'a patch named after this CVE'} to {name} {version} "
        + f"at the pinned nixpkgs revision ({pin}), as recorded in the sbomnix SBOM's patch pedigree.",
    }


def nixpkgs_pin() -> str:
    lock = cast("dict[str, dict[str, dict[str, object]]]", read_json(ROOT / "flake.lock"))
    root = cast("dict[str, str]", lock["nodes"]["root"]["inputs"])
    return cast("dict[str, str]", lock["nodes"][root["nixpkgs"]]["locked"])["rev"][:7]


class Run:
    """The rules' writes to the feed, and what they did, for the reports."""

    def __init__(self, feed: Feed, total: int) -> None:
        self.feed: Feed = feed
        self.result: Result = {"total": total, "done": [], "recheck": [], "left": []}

    def done(self, u: Untriaged, rule: str, sid: str, detail: str = "") -> None:
        self.result["done"].append(
            {"rule": rule, "cve": u.cve, "purl": u.purl, "severity": u.severity, "statement": sid, "detail": detail}
        )

    def extend(self, u: Untriaged, rule: str, st: dict[str, object], why: str, detail: str = "") -> None:
        _ = self.feed.extend(st, u.purl, why, rule_origin(__file__, rule))
        self.done(u, rule, cast("str", st["@id"]), detail)

    def add(self, u: Untriaged, rule: str, st: dict[str, object], detail: str = "") -> None:
        name, version = purl_parts(u.purl)
        sid = self.feed.add(st, u.cve, name, version or "", rule_origin(__file__, rule))
        self.done(u, rule, sid, detail)
        self.result["done"][-1]["written"] = cast("dict[str, object]", self.feed.by_id(sid))

    def leave(self, u: Untriaged, reason: str) -> None:
        self.result["left"].append({"reason": reason, "cve": u.cve, "purl": u.purl, "severity": u.severity})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("host")
    _ = parser.add_argument("--vex", action="append", default=[], help="OpenVEX document the scan used (repeatable)")
    _ = parser.add_argument("--report", help="Markdown report to write (default: stdout)")
    _ = parser.add_argument("--dry-run", action="store_true", help="write only the reports, not the feed")
    args = parser.parse_args()
    host = cast("str", args.host)
    vex_paths = cast("list[str]", args.vex)
    if not vex_paths:
        die("at least one --vex document is required")

    report = cast("Report", read_json(REPORTS / f"{host}.vulns.json"))
    sbom = cast("Sbom", read_json(ROOT / "sboms" / f"{host}.cdx.json"))
    drafts_path = REPORTS / f"kernel-triage-{host}.json"
    drafts = {d["cve"]: d for d in cast("list[Draft]", read_json(drafts_path))} if drafts_path.exists() else {}
    feed = Feed(dry_run=cast("bool", args.dry_run))
    fixes = pedigree_fixes(sbom)
    pin = nixpkgs_pin()

    acked = [pair for path in vex_paths for pair in load_acknowledged(path)]
    _, untriaged = triage(report, acked)

    run = Run(feed, len(untriaged))
    for u in untriaged:
        name, version = purl_parts(u.purl)
        label = f"{u.cve} {name}@{version} ({u.severity})"

        if version is None:
            run.leave(u, "no version in the purl")
            continue
        prior = earlier(feed, u.cve, name)
        status = cast("str", prior["status"]) if prior else None
        if name == "linux":
            draft = drafts.get(u.cve)
            if draft is None:
                run.leave(u, "no kernel draft (run kernel-cna-triage.py first)")
                continue
            auto = draft["statement"]
            if prior is None:
                run.leave(u, "new CVE (no earlier verdict)")
            elif auto is not None and auto.get("status") == status:
                run.extend(u, "kernel-auto-agrees", prior, WHY_AUTO, draft["klass"])
            elif status == "fixed":
                since = newest_version(prior, name) or ""
                reverted = [r for r in draft["reverts"] if numbers(r) > numbers(since)]
                if reverted:
                    run.leave(u, f"earlier fixed, but reverted in {', '.join(reverted)}")
                else:
                    run.extend(u, "kernel-no-revert", prior, WHY_NO_REVERT)
            elif status == "affected" and auto is not None and auto.get("status") == "fixed":
                run.add(u, "kernel-now-fixed", dict(auto), draft["klass"])
            elif status == "affected":
                run.extend(u, "kernel-still-unfixed", prior, WHY_KERNEL_UNFIXED)
                run.result["recheck"].append(label)
            else:
                run.leave(u, f"earlier {status}, kernel draft {draft['klass']}")
            continue

        patches = fixes.get((u.cve, u.purl))
        if patches is not None:
            if prior is not None and status == "fixed":
                run.extend(u, "pedigree-extend", prior, WHY_PEDIGREE)
            else:
                run.add(u, "pedigree-new", pedigree_statement(u.cve, name, version, patches, pin))
            continue
        if prior is None:
            run.leave(u, "new CVE (no earlier verdict)")
            continue
        since = newest_version(prior, name)
        if status == "fixed" and rests_on_patch(prior):
            # The fix is a nixpkgs patch: only the SBOM pedigree (above) can
            # show that this version's build still applies it.
            run.leave(u, "earlier fixed by a nixpkgs patch, not in this version's pedigree")
        elif status in ("fixed", "affected") and since and same_line_not_older(since, version):
            if status == "fixed":
                run.extend(u, "line-fixed", prior, WHY_LINE_FIXED)
            else:
                run.extend(u, "line-affected", prior, WHY_LINE_AFFECTED)
                run.result["recheck"].append(label)
        else:
            run.leave(u, f"earlier {status} for {since or 'another version'}")

    feed.write()
    _ = (REPORTS / f"carry-forward-{host}.json").write_text(json.dumps(run.result, indent=2) + "\n")
    out = render(run.result, feed)
    report_path = cast("str | None", args.report)
    if report_path:
        _ = pathlib.Path(report_path).write_text(out)
    else:
        print(out, end="")


def render(result: Result, feed: Feed) -> str:
    done: dict[str, list[str]] = defaultdict(list)
    for d in result["done"]:
        frag = d["statement"].rsplit("#", 1)[1]
        extra = f" ({d['detail']})" if d["detail"] else ""
        done[RULES[d["rule"]]].append(
            f"{d['cve']} {d['purl'].removeprefix('pkg:nix/')} ({d['severity']}) -> {frag}{extra}"
        )
    left: dict[str, list[str]] = defaultdict(list)
    for item in result["left"]:
        left[item["reason"]].append(f"{item['cve']} {item['purl'].removeprefix('pkg:nix/')} ({item['severity']})")
    if feed.dry_run:
        state = " Dry run: the feed is unchanged."
    elif feed.changed:
        state = f" Feed version {feed.doc['version']}."
    else:
        state = " The feed is unchanged."
    lines = [
        "## Carry-forward",
        "",
        f"**{result['total']} untriaged before, {len(result['done'])} carried, {len(result['left'])} left for a human.**{state}",
    ]
    for title, items in sorted(done.items()):
        lines += ["", f"### {title} ({len(items)})", ""] + [f"- {i}" for i in items]
    if result["recheck"]:
        lines += ["", f"### Carried `affected`, re-check for a fix ({len(result['recheck'])})", ""] + [
            f"- {i}" for i in result["recheck"]
        ]
    for title, items in sorted(left.items()):
        lines += ["", f"### Left: {title} ({len(items)})", ""] + [f"- {i}" for i in items]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
