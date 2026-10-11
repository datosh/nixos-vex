#!/usr/bin/env python3
"""Zero-untriaged check for a scanned system: reads reports/<host>.vulns.json
(written by `make scan`) and passes when every active grype match is
acknowledged.

grype suppresses only not_affected/fixed statements; an "affected" finding
stays active. A finding is acknowledged when an "affected" statement in one
of the --vex documents names its vulnerability and covers its purl: a
versioned product purl covers that exact version, a versionless one any
version. Everything else is untriaged. There is no policy here: every
severity counts.

"Zero" holds per grype DB snapshot, so the DB build date is printed with it.

Fails closed: a missing or unreadable report, an invalid VEX document (an
"affected" statement without an action_statement included), or any untriaged
finding exits non-zero.

Paths (reports/) are relative to the repository root, whatever the working
directory.

Usage: zero.py <host> --vex <openvex.json> [--vex ...]
"""

import argparse
import json
import pathlib
import sys
from typing import NamedTuple, NoReturn, NotRequired, TypedDict, cast

REPORTS = pathlib.Path(__file__).resolve().parent.parent / "reports"
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Negligible": 4, "Unknown": 5}


class Vulnerability(TypedDict):
    id: str
    severity: NotRequired[str]


class Artifact(TypedDict):
    name: str
    version: NotRequired[str]
    purl: NotRequired[str]


class Match(TypedDict):
    vulnerability: Vulnerability
    artifact: Artifact


class DbStatus(TypedDict):
    built: NotRequired[str]


class Db(TypedDict):
    status: NotRequired[DbStatus]


class Descriptor(TypedDict):
    version: NotRequired[str]
    db: NotRequired[Db]


class Report(TypedDict):
    matches: NotRequired[list[Match]]
    descriptor: NotRequired[Descriptor]


class Untriaged(NamedTuple):
    cve: str
    purl: str
    severity: str


def die(msg: str) -> NoReturn:
    print(f"zero: {msg}")
    sys.exit(1)


def purl_base(purl: str) -> str:
    """Drop purl qualifiers and subpath: pkg:nix/x@1?a=b#c -> pkg:nix/x@1."""
    return purl.split("?", 1)[0].split("#", 1)[0]


def purl_covers(product: str, artifact: str) -> bool:
    """A versioned product purl matches exactly; a versionless one any version."""
    product, artifact = purl_base(product), purl_base(artifact)
    if "@" in product:
        return product == artifact
    return artifact.split("@", 1)[0] == product


def load_acknowledged(path: str) -> list[tuple[str, str]]:
    """(CVE, product purl) pairs of the affected statements in one document,
    which must be well-formed throughout."""
    try:
        doc_obj = cast("object", json.loads(pathlib.Path(path).read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"invalid VEX document: cannot read {path}: {e}")
    if not isinstance(doc_obj, dict):
        die(f"invalid VEX document {path}: not a JSON object")
    statements = cast("dict[str, object]", doc_obj).get("statements")
    if not isinstance(statements, list):
        die(f"invalid VEX document {path}: no statements array")
    acked: list[tuple[str, str]] = []
    for i, st_obj in enumerate(cast("list[object]", statements)):
        where = f"{path} statements[{i}]"
        if not isinstance(st_obj, dict):
            die(f"invalid VEX document: {where} is not an object")
        st = cast("dict[str, object]", st_obj)
        vuln = st.get("vulnerability")
        name = cast("dict[str, object]", vuln).get("name") if isinstance(vuln, dict) else None
        if not isinstance(name, str) or not name:
            die(f"invalid VEX document: {where} has no vulnerability.name")
        status = st.get("status")
        if status not in STATUSES:
            die(f"invalid VEX document: {where} ({name}) has status {status!r}")
        products = st.get("products")
        if not isinstance(products, list) or not products:
            die(f"invalid VEX document: {where} ({name}) has no products")
        purls: list[str] = []
        for p in cast("list[object]", products):
            purl = cast("dict[str, object]", p).get("@id") if isinstance(p, dict) else None
            if not isinstance(purl, str) or not purl.startswith("pkg:"):
                die(f"invalid VEX document: {where} ({name}) has a product without a purl @id")
            purls.append(purl)
        if status != "affected":
            continue
        action = st.get("action_statement")
        if not isinstance(action, str) or not action.strip():
            die(f"invalid VEX document: {where} ({name}) is affected without an action_statement")
        acked.extend((name, purl) for purl in purls)
    return acked


def db_built(report: Report) -> str:
    return report.get("descriptor", Descriptor()).get("db", Db()).get("status", DbStatus()).get("built", "unknown")


def active(report: Report) -> dict[tuple[str, str], Match]:
    """One finding per (vulnerability, package) pair, however many ways grype matched it."""
    findings: dict[tuple[str, str], Match] = {}
    for m in report.get("matches", []):
        a = m["artifact"]
        purl = a.get("purl") or f"{a['name']}@{a.get('version', '')}"
        _ = findings.setdefault((m["vulnerability"]["id"], purl), m)
    return findings


def triage(report: Report, acked: list[tuple[str, str]]) -> tuple[int, list[Untriaged]]:
    """The number of active findings, and the untriaged ones (most severe first)."""
    findings = active(report)

    untriaged: list[Untriaged] = []
    for (cve, purl), m in findings.items():
        # A match without a purl cannot be covered by a statement (fail closed).
        has_purl = "purl" in m["artifact"]
        if has_purl and any(c == cve and purl_covers(prod, purl) for c, prod in acked):
            continue
        untriaged.append(Untriaged(cve, purl, m["vulnerability"].get("severity", "Unknown")))
    untriaged.sort(key=lambda u: (SEV_ORDER.get(u.severity, 9), u.cve, u.purl))
    return len(findings), untriaged


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("host")
    _ = parser.add_argument(
        "--vex",
        action="append",
        default=[],
        help="OpenVEX document the scan used; its affected statements acknowledge findings (repeatable)",
    )
    args = parser.parse_args()
    host = cast("str", args.host)
    vex_paths = cast("list[str]", args.vex)
    if not vex_paths:
        die("at least one --vex document is required")
    acked = [pair for path in vex_paths for pair in load_acknowledged(path)]

    path = REPORTS / f"{host}.vulns.json"
    try:
        report = cast("Report", json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path} (run `make scan` first): {e}")
    built = db_built(report)
    n, untriaged = triage(report, acked)

    for u in untriaged:
        print(f"  untriaged: {u.cve} {u.purl} ({u.severity})")
    summary = (
        f"{n} active, {n - len(untriaged)} acknowledged, {len(untriaged)} untriaged " + f"(grype DB built {built})"
    )
    if untriaged:
        print(f"zero {host}: FAIL - {summary}")
        print(
            f"zero {host}: each untriaged finding needs a statement (not_affected, fixed, or affected with an action_statement)"
        )
        sys.exit(1)
    print(f"zero {host}: PASS - {summary}")


if __name__ == "__main__":
    main()
