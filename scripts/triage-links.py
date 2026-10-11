#!/usr/bin/env python3
"""Triage helper: gather scan context and research links for one CVE.

The script:
+ shows the CVE's matches in the grype reports (reports/*.vulns.json, written
  by `make scan`), active or suppressed
+ prints research links for given CVE
+ --check-nixpkgs also evaluates the package version in current nixpkgs-unstable
+ --cna-contact resolves the CVE's CNA and prints its contact/escalation info
  (for reporting stale or wrong records upstream)

Paths (reports/) are relative to the repository root, whatever the working
directory.

Usage: triage-links.py CVE-2007-2768 [--check-nixpkgs] [--cna-contact]
"""

import argparse
import json
import pathlib
import subprocess
import urllib.error
import urllib.request
from http.client import HTTPResponse
from typing import NotRequired, TypedDict, cast

REPORTS = pathlib.Path(__file__).resolve().parent.parent / "reports"

LINKS: list[tuple[str, str]] = [
    ("NVD", "https://nvd.nist.gov/vuln/detail/{cve}"),
    ("NVD API (CPE ranges)", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"),
    ("CVE record (CNA ranges)", "https://cveawg.mitre.org/api/cve/{cve}"),
    ("OSV", "https://osv.dev/vulnerability/{cve}"),
    ("Debian tracker", "https://security-tracker.debian.org/tracker/{cve}"),
    ("Red Hat", "https://access.redhat.com/security/cve/{cve}"),
    ("Ubuntu", "https://ubuntu.com/security/{cve}"),
    ("SUSE", "https://www.suse.com/security/cve/{cve}.html"),
    ("Nixpkgs security tracker", "https://tracker.security.nixos.org/suggestions/by-cve/{cve}/"),
    ("nixpkgs issue search", "https://github.com/NixOS/nixpkgs/issues?q={cve}"),
]

# Official CVE Program partner directory (backs cve.org "List of Partners")
CNAS_URL = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"


class EpssEntry(TypedDict):
    epss: NotRequired[float]
    percentile: NotRequired[float]


class Fix(TypedDict):
    state: NotRequired[str]
    versions: NotRequired[list[str]]


class Vulnerability(TypedDict):
    id: str
    severity: NotRequired[str]
    epss: NotRequired[list[EpssEntry]]
    fix: NotRequired[Fix]


class Artifact(TypedDict):
    name: str
    version: NotRequired[str]
    purl: NotRequired[str]


class Found(TypedDict):
    versionConstraint: NotRequired[str]
    cpes: NotRequired[list[str]]


class MatchDetail(TypedDict):
    type: NotRequired[str]
    found: NotRequired[Found]


class Match(TypedDict):
    vulnerability: Vulnerability
    artifact: Artifact
    matchDetails: NotRequired[list[MatchDetail]]


class Report(TypedDict):
    matches: NotRequired[list[Match]]
    ignoredMatches: NotRequired[list[Match]]


class CveMetadata(TypedDict):
    assignerShortName: NotRequired[str]
    dateUpdated: NotRequired[str]


class VersionEntry(TypedDict):
    version: NotRequired[str]
    lessThan: NotRequired[str]
    lessThanOrEqual: NotRequired[str]


class CnaAffected(TypedDict):
    versions: NotRequired[list[VersionEntry]]


class CnaContainer(TypedDict):
    affected: NotRequired[list[CnaAffected]]


class Containers(TypedDict):
    cna: NotRequired[CnaContainer]


class CveRecord(TypedDict):
    cveMetadata: NotRequired[CveMetadata]
    containers: NotRequired[Containers]


class EmailEntry(TypedDict):
    emailAddr: NotRequired[str]


class UrlEntry(TypedDict):
    url: NotRequired[str]


class ContactBlock(TypedDict):
    email: NotRequired[list[EmailEntry]]
    form: NotRequired[list[UrlEntry]]
    contact: NotRequired[list[UrlEntry]]


class RootCna(TypedDict):
    shortName: NotRequired[str]
    organizationName: NotRequired[str]


class CnaInfo(TypedDict):
    root: NotRequired[RootCna]


class SecurityAdvisories(TypedDict):
    advisories: NotRequired[list[UrlEntry]]


class CnaEntry(TypedDict):
    shortName: NotRequired[str]
    organizationName: NotRequired[str]
    country: NotRequired[str]
    contact: NotRequired[list[ContactBlock]]
    disclosurePolicy: NotRequired[list[UrlEntry]]
    securityAdvisories: NotRequired[SecurityAdvisories]
    CNA: NotRequired[CnaInfo]


def fetch_json(url: str) -> object | None:
    try:
        response = cast("HTTPResponse", urllib.request.urlopen(url, timeout=30))
        with response:
            return cast("object", json.load(response))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"  fetch failed: {url} ({e})")
        return None


def cna_contact(cve: str) -> None:
    record_obj = fetch_json(f"https://cveawg.mitre.org/api/cve/{cve}")
    if not record_obj:
        return
    record = cast("CveRecord", record_obj)
    meta = record.get("cveMetadata", CveMetadata())
    short = meta.get("assignerShortName")
    print(f"\nCNA owning {cve}: {short}")
    print(
        f"  record last updated: {meta.get('dateUpdated')} "
        + "(watch for changes at https://github.com/CVEProject/cvelistV5)"
    )
    # Who owns a bad affected-range? Modern records carry structured version
    # data in the CNA container (NVD mirrors it -> report to the CNA). Legacy
    # records (bulk-converted 2024-08) only have 'n/a' -> the unbounded CPE
    # config was authored by NVD analysts -> report to nvd@nist.gov instead.
    versions = [
        v
        for a in record.get("containers", Containers()).get("cna", CnaContainer()).get("affected", [])
        for v in a.get("versions", [])
    ]
    has_ranges = any(
        v.get("version") not in (None, "", "n/a") or v.get("lessThan") or v.get("lessThanOrEqual") for v in versions
    )
    if has_ranges:
        print("  cna version data: present -> range defects are CNA-owned, report to the CNA below")
    else:
        print("  cna version data: none (legacy record) -> CPE range defects are NVD-owned, report to nvd@nist.gov")
    cnas_obj = fetch_json(CNAS_URL)
    if not cnas_obj:
        return
    cnas = cast("list[CnaEntry]", cnas_obj)
    entry = next((c for c in cnas if c.get("shortName") == short), None)
    if entry is None:
        print(f"  '{short}' not in CNAsList.json -> https://www.cve.org/PartnerInformation/ListofPartners")
        return
    print(f"  organization: {entry.get('organizationName')} ({entry.get('country')})")
    for c in entry.get("contact", []):
        for e in c.get("email", []):
            print(f"  email: {e.get('emailAddr')}")
        for form in c.get("form", []):
            print(f"  form: {form.get('url', '')}")
        for u in c.get("contact", []):
            print(f"  contact: {u.get('url', '')}")
    for p in entry.get("disclosurePolicy", []):
        if policy_url := p.get("url"):
            print(f"  disclosure policy: {policy_url}")
    for adv in entry.get("securityAdvisories", SecurityAdvisories()).get("advisories", []):
        if adv_url := adv.get("url"):
            print(f"  advisories: {adv_url}")
    root = entry.get("CNA", CnaInfo()).get("root", RootCna())
    root_short = root.get("shortName")
    if root_short and root_short != "n/a":
        print(
            f"  escalation: root CNA = {root.get('organizationName')} "
            + f"({root_short}); program-level: https://cveform.mitre.org/"
        )


def nixpkgs_version(attr: str) -> str | None:
    cmd = [
        "nix",
        "eval",
        "--raw",
        f"github:NixOS/nixpkgs/nixos-unstable#{attr}.version",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        return None
    return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else None


def find_matches(cve: str) -> list[tuple[str, bool, Match]]:
    hits: list[tuple[str, bool, Match]] = []
    for path in sorted(REPORTS.glob("*.vulns.json")):
        host = path.name.split(".")[0]
        data = cast("Report", json.loads(path.read_text()))
        for matches, active in ((data.get("matches", []), True), (data.get("ignoredMatches", []), False)):
            hits += [(host, active, m) for m in matches if m["vulnerability"]["id"] == cve]
    return hits


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("cve", help="CVE id, e.g. CVE-2007-2768")
    _ = parser.add_argument("--check-nixpkgs", action="store_true", help="eval package version in nixpkgs-unstable")
    _ = parser.add_argument(
        "--cna-contact", action="store_true", help="resolve the CVE's CNA and print contact/escalation info"
    )
    args = parser.parse_args()
    cve = cast("str", args.cve).upper()

    hits = find_matches(cve)
    if not hits:
        print(f"{cve}: no matches in reports/*.vulns.json (run make scan first?)")
    packages: set[tuple[str, str]] = set()
    for host, active, m in hits:
        v, a = m["vulnerability"], m["artifact"]
        packages.add((a["name"], a.get("version", "")))
        state = "ACTIVE" if active else "ignored (VEX/suppressed)"
        print(f"[{host}] {a['name']} {a.get('version', '')}  ({a.get('purl', '')})  -> {state}")
        epss_str = ", ".join(f"{e.get('epss', 0.0):.2%} (p{e.get('percentile', 0.0):.0%})" for e in v.get("epss", []))
        print(f"    severity: {v.get('severity')}  epss: {epss_str}")
        fix = v.get("fix", Fix())
        print(f"    grype fix data: state={fix.get('state') or 'unknown'} " + f"versions={fix.get('versions') or '-'}")
        for md in m.get("matchDetails", []):
            found = md.get("found", Found())
            constraint = found.get("versionConstraint") or found.get("cpes")
            print(f"    matched via: {md.get('type')} constraint={constraint}")

    print(f"\nResearch links for {cve}:")
    for name, url in LINKS:
        print(f"  {name:26s} {url.format(cve=cve)}")

    if cast("bool", args.cna_contact):
        cna_contact(cve)

    if cast("bool", args.check_nixpkgs) and packages:
        print("\nnixpkgs-unstable versions (exact attribute eval, no heuristics):")
        for name, local in sorted(packages):
            current = nixpkgs_version(name)
            if current is None:
                print(f"  {name}: attribute not found in nixpkgs-unstable -> unknown, check manually")
            else:
                marker = "same as local" if current == local else f"local has {local}"
                print(f"  {name}: unstable={current} ({marker})")


if __name__ == "__main__":
    main()
