#!/usr/bin/env python3
"""Draft VEX verdicts for Linux kernel findings from upstream data.

For every linux finding in reports/<host>.vulns.json (written by `make scan`)
this classifies the CVE against the exact kernel the host ships, using
(first match wins):

  1. the CNA record's per-branch version data (kernel.org CNA),
  2. the 6.<x>.y stable ChangeLogs (backports a stale record does not list),
     by the record's fix SHA; a commit with the fix's subject but another
     SHA is only noted, as is a fix in none of them up to ours,
  3. for records of non-kernel CNAs: the referenced fix commits (those tagged
     as patches when the references tag any), each of which must be an
     ancestor of our mainline tag or backported to our stable branch. A
     commit cited from a subsystem tree on git.kernel.org (e.g.
     bluetooth-next) counts through its mainline twin: the one mainline
     commit with exactly its subject (GitHub commit search). Then the Debian
     security tracker's fixed version, when it is on our branch; then the
     Ubuntu CVE tracker's break-fix commits (when Debian has no verdict or
     only one on an older branch): `not-built-arch` when they change only
     other architectures' code, `fixed-ubuntu` when every one is in our
     kernel,
  4. the kernel build config (is the vulnerable code compiled at all?).

Nothing is written to a VEX feed by default: drafts land in
reports/kernel-triage-<host>.{json,md} for review. `--apply CLASS|CVE ...`
appends the drafts of approved classes or CVEs to the feed (through
feed.py, which logs them under triage/).

Network (cveawg.mitre.org, cdn.kernel.org, git.kernel.org, GitHub API via
`gh`, retried on transient errors) is cached under reports/cache/; only
definite ancestry answers are cached. CVE records and the Debian tracker are refetched once
older than 12 hours (records get corrected); ChangeLogs, kbuild data and NVD
stay cached. The nixpkgs pin named in statements comes from flake.lock.

Each draft also records the fix commits and the stable releases (up to ours)
whose ChangeLog reverts one of them; carry-forward.py relies on both.

Paths (reports/, the feed) are relative to the repository root, whatever the
working directory.

Usage: kernel-cna-triage.py <host> [--apply CLASS|CVE ...]
       (the reference system: kernel-cna-triage.py baseline)
"""

import argparse
import http.client
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import NotRequired, TypedDict, cast

from feed import Feed, rule_origin

REPO = pathlib.Path(__file__).resolve().parent.parent
REPORTS = REPO / "reports"
CACHE = REPORTS / "cache"
FEED_ID = "https://github.com/datosh/nixos-vex/blob/main/vex/baseline.openvex.json"
# Refetch age of CVE records and the Debian tracker (see the docstring).
FRESH = 12 * 3600

# Classes whose drafts are statements; "manual-*" classes only carry evidence.
AUTO_CLASSES = (
    "fixed-branch",
    "fixed-debian",
    "fixed-mainline",
    "fixed-changelog",
    "fixed-ancestor",
    "fixed-ubuntu",
    "not-present-version",
    "not-built-arch",
    "not-built-config",
    "affected-update",
)

type Version = tuple[int, ...]


class VersionEntry(TypedDict):
    version: str
    status: str
    versionType: NotRequired[str]
    lessThan: NotRequired[str]
    lessThanOrEqual: NotRequired[str]


class Affected(TypedDict):
    vendor: NotRequired[str]
    product: NotRequired[str]
    defaultStatus: NotRequired[str]
    programFiles: NotRequired[list[str]]
    versions: NotRequired[list[VersionEntry]]


class Description(TypedDict):
    value: str


class Reference(TypedDict):
    url: str
    tags: NotRequired[list[str]]


class ProviderMetadata(TypedDict):
    shortName: str
    dateUpdated: NotRequired[str]


class Cna(TypedDict):
    providerMetadata: ProviderMetadata
    descriptions: NotRequired[list[Description]]
    affected: NotRequired[list[Affected]]
    references: NotRequired[list[Reference]]


class Adp(TypedDict):
    references: NotRequired[list[Reference]]


class Containers(TypedDict):
    cna: Cna
    adp: NotRequired[list[Adp]]


class CveRecord(TypedDict):
    containers: Containers


class Artifact(TypedDict):
    name: str
    version: str
    purl: NotRequired[str]


class Vulnerability(TypedDict):
    id: str
    severity: NotRequired[str]


class Match(TypedDict):
    vulnerability: Vulnerability
    artifact: Artifact


class Report(TypedDict):
    matches: NotRequired[list[Match]]


@dataclass
class Draft:
    cve: str
    severity: str
    cna: str
    title: str
    klass: str
    evidence: list[str] = field(default_factory=list)
    statement: dict[str, object] | None = None
    # The fix commits named by the record, and the stable releases up to ours
    # whose ChangeLog reverts one of them (carry-forward of `fixed` verdicts).
    fix_shas: list[str] = field(default_factory=list)
    reverts: list[str] = field(default_factory=list)


# --- helpers -----------------------------------------------------------------


def parse_version(s: str) -> Version | None:
    if not re.fullmatch(r"\d+(\.\d+)*", s):
        return None
    return tuple(int(x) for x in s.split("."))


def fmt(v: Version) -> str:
    return ".".join(str(x) for x in v)


def fetch(url: str, cache_name: str, max_age: float | None = None) -> str | None:
    """The cached copy of url; refetched when older than max_age seconds
    (None: cached forever). A failed refetch falls back to the stale copy."""
    path = CACHE / cache_name
    if path.exists():
        if max_age is None or time.time() - path.stat().st_mtime < max_age:
            return path.read_text()
        try:
            return refetch(url, path)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"kernel-cna-triage: using stale {cache_name} ({e})", file=sys.stderr)
            return path.read_text()
    return refetch(url, path)


def refetch(url: str, path: pathlib.Path) -> str | None:
    try:
        # git.kernel.org rejects urllib's default User-Agent.
        req = urllib.request.Request(url, headers={"User-Agent": "nixos-vex-triage"})
        resp = cast("http.client.HTTPResponse", urllib.request.urlopen(req, timeout=60))
        with resp:
            data = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(data)
    return data


def cve_record(cve: str) -> CveRecord:
    text = fetch(f"https://cveawg.mitre.org/api/cve/{cve}", f"cve/{cve}.json", FRESH)
    if text is None:
        sys.exit(f"kernel-cna-triage: no CVE record for {cve}")
    return cast("CveRecord", json.loads(text))


def nix_out(attr: str) -> str:
    out = subprocess.run(
        ["nix", "build", "--no-link", "--print-out-paths", attr],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def title_of(cna: Cna) -> str:
    desc = (cna.get("descriptions") or [{"value": ""}])[0]["value"]
    prefix = "In the Linux kernel, the following vulnerability has been resolved:"
    desc = desc.removeprefix(prefix)
    first = desc.strip().split("\n", 1)[0].strip()
    if len(first) <= 160:
        return first
    # Long descriptions (non-kernel CNAs): end at a sentence, else at a word.
    cut = first[:160]
    end = cut.rfind(". ")
    return cut[: end + 1] if end > 40 else cut[: cut.rfind(" ")] + " …"


# --- 1. CNA branch data ------------------------------------------------------


def covers(e: VersionEntry, ours: Version) -> bool:
    """Does a semver range entry include our version?"""
    start = parse_version(e["version"])
    if start is None or ours < start:
        return False
    if "lessThan" in e:
        end = parse_version(e["lessThan"])
        return end is not None and ours < end
    if "lessThanOrEqual" in e:
        le = e["lessThanOrEqual"]
        if le == "*":
            return True
        if le.endswith(".*"):
            branch = parse_version(le[:-2])
            return branch is not None and ours[: len(branch)] == branch
        end = parse_version(le)
        return end is not None and ours <= end
    return ours == start


def classify_branch(aff: list[Affected], ours: Version) -> tuple[str, str] | None:
    """Kernel CNA semver data -> (class, evidence) or None if undecided."""
    entries = [e for a in aff for e in a.get("versions", []) if e.get("versionType", "semver") != "git"]
    if not entries:
        return None
    branch = f"{ours[0]}.{ours[1]}.*"
    for e in entries:
        if e["status"] != "unaffected" or not covers(e, ours):
            continue
        if e.get("lessThanOrEqual") == branch:
            return "fixed-branch", f"CNA record: unaffected from {e['version']} on the {branch} branch"
        if e.get("lessThanOrEqual") == "*":
            return "fixed-mainline", f"CNA record: unaffected from {e['version']} (mainline)"
        if e["version"] == "0" and "lessThan" in e:
            return "not-present-version", f"CNA record: unaffected before {e['lessThan']} (introduced later)"
        return (
            "not-present-version",
            f"CNA record: unaffected range {e['version']}..{e.get('lessThan') or e.get('lessThanOrEqual')}",
        )
    # A bare "affected: X" entry marks where the flaw was introduced: from X on.
    affected_hit = any(
        e["status"] == "affected"
        and (
            covers(e, ours)
            if ("lessThan" in e or "lessThanOrEqual" in e)
            else (start := parse_version(e["version"])) is not None and ours >= start
        )
        for e in entries
    )
    default = next(
        (
            a.get("defaultStatus", "affected")
            for a in aff
            if any(e.get("versionType", "semver") != "git" for e in a.get("versions", []))
        ),
        "affected",
    )
    if not affected_hit and default == "unaffected":
        ranges = ", ".join(
            f"{e['version']}..{e.get('lessThan', e.get('lessThanOrEqual', ''))}"
            for e in entries
            if e["status"] == "affected"
        )
        return "not-present-version", f"CNA record: affected only in {ranges}; default unaffected"
    for e in entries:
        if e["status"] == "unaffected" and e.get("lessThanOrEqual") == branch:
            return "affected-update", f"CNA record: fixed on the {branch} branch only from {e['version']}"
    return None


# --- 2./3. stable ChangeLogs and commit ancestry -----------------------------


def changelogs(ours: Version) -> dict[int, str]:
    """Stable ChangeLogs of our branch: every release up to ours, plus the
    newer ones (until the first missing), which tell where a fix lands later.
    Newer releases are re-checked on each run (not cached negatively)."""
    major, minor, patch = ours[0], ours[1], ours[2]
    logs: dict[int, str] = {}
    n = 1
    while True:
        name = f"ChangeLog-{major}.{minor}.{n}"
        text = fetch(f"https://cdn.kernel.org/pub/linux/kernel/v{major}.x/{name}", f"changelog/{name}")
        if text is None:
            if n > patch:
                break
        else:
            logs[n] = text
        n += 1
    return logs


def find_reverts(shas: list[str], title: str, logs: dict[int, str]) -> list[int]:
    """Releases whose ChangeLog reverts one of the fix commits (by sha, or by
    a 'Revert "<title>"' subject when the title is the commit subject)."""
    subject = re.escape(title.strip())
    hits: list[int] = []
    for n in sorted(logs):
        by_sha = any(re.search(rf"This reverts commit {sha[:12]}", logs[n]) for sha in shas)
        by_subject = bool(subject) and re.search(rf'^\s*Revert "{subject}"', logs[n], re.MULTILINE) is not None
        if by_sha or by_subject:
            hits.append(n)
    return hits


def find_in_changelogs(shas: list[str], logs: dict[int, str]) -> tuple[int, str] | None:
    for n in sorted(logs):
        for sha in shas:
            if re.search(rf"^\s*commit {sha[:12]}[0-9a-f]* upstream\.|^commit {sha[:12]}", logs[n], re.MULTILINE):
                return n, sha
    return None


def find_title_in_changelogs(subject: str, logs: dict[int, str]) -> int | None:
    """The first release whose ChangeLog has a commit with exactly this
    subject line (a backport the record's SHA does not name)."""
    pattern = re.compile(rf"^\s+{re.escape(subject.strip())}\s*$", re.MULTILINE)
    return next((n for n in sorted(logs) if subject.strip() and pattern.search(logs[n])), None)


def gh(*args: str) -> str | None:
    """`gh api` output, retried on transient errors; None on a 4xx or when
    the retries run out."""
    for attempt in range(3):
        out = subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=False)
        if out.returncode == 0:
            return out.stdout
        if re.search(r"HTTP 4\d\d", out.stderr) and "HTTP 429" not in out.stderr:
            return None
        time.sleep(2 * (attempt + 1))
    return None


def is_ancestor(sha: str, tag: str) -> bool | None:
    """Whether a mainline commit is in tag's history; None when GitHub cannot
    say (only definite answers are cached)."""
    cache = CACHE / "ancestry" / f"{sha}-{tag}"
    if cache.exists():
        return cache.read_text() == "yes"
    status = gh(f"repos/torvalds/linux/compare/{sha}...{tag}", "--jq", ".status")
    if status is None:
        # GitHub answers 404 for a commit that is not in torvalds/linux at all.
        return None
    result = "yes" if status.strip() in ("ahead", "identical") else "no"
    cache.parent.mkdir(parents=True, exist_ok=True)
    _ = cache.write_text(result)
    return result == "yes"


def mainline_for(sha: str, url: str) -> tuple[str, str] | None:
    """The mainline commit with the same subject as a commit referenced in a
    subsystem tree on git.kernel.org (e.g. bluetooth-next), and that subject.
    Records of non-kernel CNAs often cite the subsystem tree's SHA."""
    cache = CACHE / "mainline" / f"{sha}.json"
    if cache.exists():
        cached = cast("list[str]", json.loads(cache.read_text()))
        return (cached[0], cached[1]) if cached else None
    if "git.kernel.org" not in url or "/commit/" not in url:
        return None
    try:
        patch = fetch(url.replace("/commit/", "/patch/"), f"patch/{sha}")
    except urllib.error.URLError, TimeoutError:
        return None
    found = re.search(r"^Subject: (.*(?:\n .*)*)", patch or "", re.MULTILINE)
    if found is None:
        return None
    subject = re.sub(r"\s+", " ", found[1]).removeprefix("[PATCH] ").strip()
    out = gh(
        "-X",
        "GET",
        "search/commits",
        "-f",
        f'q=repo:torvalds/linux "{subject}"',
        "--jq",
        '.items[] | [.sha, (.commit.message | split("\n")[0])] | @tsv',
    )
    if out is None:
        return None
    hits = [line.split("\t", 1)[0] for line in out.splitlines() if line.split("\t", 1)[-1] == subject]
    result = (hits[0], subject) if len(hits) == 1 and hits[0] != sha else None
    cache.parent.mkdir(parents=True, exist_ok=True)
    _ = cache.write_text(json.dumps(list(result) if result else []))
    return result


COMMIT_RE = re.compile(r"(?:[?&;]id=|/commit/|h=)([0-9a-f]{12,40})")


class NvdCve(TypedDict):
    references: NotRequired[list[Reference]]


class NvdItem(TypedDict):
    cve: NvdCve


class NvdResponse(TypedDict):
    vulnerabilities: NotRequired[list[NvdItem]]


def nvd_references(cve: str) -> list[Reference]:
    """NVD's reference list (often carries the fix commit old records lack).
    The public API allows 5 requests per 30 s without a key."""
    cached = (CACHE / "nvd" / f"{cve}.json").exists()
    text = fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", f"nvd/{cve}.json")
    if not cached:
        time.sleep(6.5)
    if text is None:
        return []
    resp = cast("NvdResponse", json.loads(text))
    return [r for v in resp.get("vulnerabilities", []) for r in v["cve"].get("references", [])]


def referenced_commits(rec: CveRecord, cve: str) -> tuple[dict[str, str], bool]:
    """Kernel commits the record references, and whether they are the ones
    tagged as patches (sha -> the URL citing it). References may also point
    at the commit that introduced the flaw, so when any reference is tagged
    as a patch only those count."""
    containers = rec["containers"]
    refs = list(containers["cna"].get("references", []))
    refs += [r for a in containers.get("adp", []) for r in a.get("references", [])]
    if not commits_in(refs):
        refs = nvd_references(cve)
    patches = [r for r in refs if any(t.lower() == "patch" for t in r.get("tags", []))]
    if commits_in(patches):
        return commits_in(patches), True
    return commits_in(refs), False


def commits_in(refs: list[Reference]) -> dict[str, str]:
    shas: dict[str, str] = {}
    for ref in refs:
        url = ref["url"]
        if "git.kernel.org" in url or "github.com/torvalds/linux" in url:
            for m in cast("list[str]", COMMIT_RE.findall(url)):
                _ = shas.setdefault(m, url)
    return shas


class DebianRelease(TypedDict):
    status: str
    fixed_version: NotRequired[str]
    urgency: NotRequired[str]


class DebianEntry(TypedDict):
    releases: dict[str, DebianRelease]


def debian_linux() -> dict[str, DebianEntry]:
    text = fetch("https://security-tracker.debian.org/tracker/data/json", "debian-tracker.json", FRESH)
    if text is None:
        return {}
    return cast("dict[str, dict[str, DebianEntry]]", json.loads(text)).get("linux", {})


def classify_debian(cve: str, debian: dict[str, DebianEntry], ours: Version) -> tuple[str, str] | None:
    sid = debian.get(cve, {"releases": {}})["releases"].get("sid")
    if sid is None or sid["status"] != "resolved":
        return None
    fixed = sid.get("fixed_version", "")
    if fixed == "0":
        # Debian may be unaffected because of its own kernel config, which
        # does not carry over to nixpkgs: evidence only, review by hand.
        return "manual-debian-not-affected", "Debian security tracker: linux marked not affected (verify why)"
    upstream = parse_version(fixed.split("-", 1)[0].split("~", 1)[0])
    if upstream is None or len(upstream) < 2:
        return None
    if upstream[:2] == ours[:2]:
        if upstream <= ours:
            return (
                "fixed-debian",
                f"Debian security tracker: fixed in linux {fixed} (sid), on our {fmt(ours[:2])} branch at or before {fmt(ours)}",
            )
        return None
    if upstream[:2] < ours[:2]:
        # A fix on an older branch says nothing certain about ours: sid may
        # have lagged mainline, and the mainline fix may postdate our branch.
        return (
            "manual-debian-older-branch",
            f"Debian security tracker: fixed in linux {fixed} (sid), an older branch than {fmt(ours[:2])} (verify the fix is in {fmt(ours)})",
        )
    return None


UCT = "https://git.launchpad.net/ubuntu-cve-tracker/plain/{}/{}"


def ubuntu_fixes(cve: str) -> tuple[list[str], str] | None:
    """The fix commits the Ubuntu CVE tracker names for linux (its
    `break-fix: <introduced> <fix>` lines) and the file's URL, or None
    without such data. A
    CVE's file moves between active/, retired/ and ignored/ over time."""
    for folder in ("active", "retired", "ignored"):
        url = UCT.format(folder, cve)
        text = fetch(url, f"uct/{folder}/{cve}", FRESH)
        if text is not None:
            break
    else:
        return None
    section = re.search(r"^Patches_linux:\n((?:[ \t].*\n?)*)", text, re.MULTILINE)
    if section is None:
        return None
    # A fix may be given as alternatives, "<sha>|local-<name>": the upstream
    # commit or Ubuntu's own patch.
    fixes = [
        next((alt for alt in field.split("|") if re.fullmatch(r"[0-9a-f]{40}", alt)), field)
        for field in cast("list[str]", re.findall(r"break-fix:\s+\S+\s+(\S+)", section[1]))
    ]
    return (fixes, url) if fixes else None


def commit_files(sha: str) -> list[str] | None:
    """The files a mainline commit changes."""
    cache = CACHE / "files" / f"{sha}.json"
    if cache.exists():
        return cast("list[str]", json.loads(cache.read_text()))
    out = gh(f"repos/torvalds/linux/commits/{sha}", "--jq", ".files[].filename")
    if out is None:
        return None
    files = out.split()
    cache.parent.mkdir(parents=True, exist_ok=True)
    _ = cache.write_text(json.dumps(files))
    return files


def classify_ubuntu(d: Draft, ours: Version, older: dict[int, str], tree: KernelTree) -> tuple[str, str] | None:
    """Old CVEs of non-kernel CNAs often name no fix commit; the Ubuntu CVE
    tracker's break-fix data does. Code that is not built (by the files the
    fix changes) wins over `fixed`, as for any other verdict."""
    found_fixes = ubuntu_fixes(d.cve)
    if found_fixes is None:
        return None
    fixes, url = found_fixes
    if not all(re.fullmatch(r"[0-9a-f]{40}", f) for f in fixes):
        d.evidence.append(f"Ubuntu CVE tracker: fixed by a local Ubuntu patch ({', '.join(fixes)}), not upstream")
        return None
    files = [f for sha in fixes for f in commit_files(sha) or []]
    if files and all(f.startswith("arch/") and not f.startswith("arch/x86/") for f in files):
        other = sorted({f.split("/")[1] for f in files})
        return "not-built-arch", (
            f"the Ubuntu CVE tracker's fix commits ({', '.join(f[:12] for f in fixes)}) change only "
            + f"{', '.join(other)} code ({url})"
        )
    built = classify_config(files, tree, "x86")
    if built and built[0] in ("not-built-arch", "not-built-config"):
        return built[0], f"the Ubuntu CVE tracker's fix commits ({', '.join(f[:12] for f in fixes)}) change {built[1]}"
    tag = f"v{fmt(ours[:2])}"
    where: list[str] = []
    for sha in fixes:
        if is_ancestor(sha, tag):
            where.append(f"{sha[:12]} is an ancestor of {tag}")
        elif found := find_in_changelogs([sha], older):
            where.append(f"{sha[:12]} backported in {fmt(ours[:2])}.{found[0]}")
        else:
            d.evidence.append(f"Ubuntu CVE tracker names fix {sha[:12]}, which is not in {tag} or up to {fmt(ours)}")
            return None
    d.fix_shas = fixes
    return "fixed-ubuntu", f"every fix commit the Ubuntu CVE tracker names ({url}): " + "; ".join(where)


# --- 4. build config ----------------------------------------------------------


class KernelTree:
    """Kbuild Makefiles + .config of the exact kernel, to answer 'is it built?'."""

    def __init__(self, src_tarball: str, configfile: str) -> None:
        self.config: dict[str, str] = {}
        for line in pathlib.Path(configfile).read_text().splitlines():
            if m := re.fullmatch(r"(CONFIG_\w+)=(.*)", line):
                self.config[m[1]] = m[2]
        self.makefiles: dict[str, str] = {}
        self.files: set[str] = set()
        cache = CACHE / "kbuild" / (pathlib.Path(src_tarball).name + ".json")
        if cache.exists():
            cached = cast("dict[str, dict[str, str]]", json.loads(cache.read_text()))
            self.makefiles, self.files = cached["makefiles"], set(cached["files"])
            return
        with tarfile.open(src_tarball) as tar:
            for member in tar:
                base = member.name.split("/", 1)[-1]
                if not member.isfile():
                    continue
                self.files.add(base)
                if base.rsplit("/", 1)[-1] in ("Makefile", "Kbuild"):
                    f = tar.extractfile(member)
                    if f is not None:
                        self.makefiles[base] = f.read().decode("utf-8", errors="replace")
        cache.parent.mkdir(parents=True, exist_ok=True)
        _ = cache.write_text(json.dumps({"makefiles": self.makefiles, "files": dict.fromkeys(sorted(self.files), "")}))

    def value(self, sym: str) -> str:
        return self.config.get(sym, "n")

    def _lines(self, d: str) -> list[str]:
        text = self.makefiles.get(f"{d}/Kbuild") or self.makefiles.get(f"{d}/Makefile") or ""
        return text.replace("\\\n", " ").splitlines()

    def conditions(self, path: str, depth: int = 0) -> list[str] | None:
        """CONFIG symbols that must all be enabled for `path` (a .c file or a
        directory) to be built, or None if the Makefiles do not tell."""
        if depth > 12:
            return None
        d, name = path.rsplit("/", 1) if "/" in path else ("", path)
        target = name[:-2] + ".o" if name.endswith(".c") else name + "/"
        if d == "":
            return []
        conds: list[str] | None = None
        # The object may be listed in its own directory's Makefile or, with a
        # relative path (kvm-amd-y += svm/nested.o), in an ancestor's.
        rel = target
        while True:
            hit = self._find(d, rel)
            if hit is not None or "/" not in d:
                break
            d, last = d.rsplit("/", 1)
            rel = f"{last}/{rel}"
        if hit is None:
            if name.endswith(".c"):
                return None
            return []
        lhs, sym = hit
        here = [sym] if sym else []
        if lhs == "obj":
            conds = here
        else:  # composite object: lhs.o is linked from lhs-<...> parts
            parent = self.conditions(f"{d}/{lhs}.c", depth + 1)
            if parent is None:
                return None
            conds = here + parent
        parent_dir = self.conditions(d, depth + 1)
        if parent_dir is None:
            return conds
        return conds + parent_dir

    def _find(self, d: str, target: str) -> tuple[str, str] | None:
        for line in self._lines(d):
            m = re.match(r"\s*([\w-]+?)-(\$\((CONFIG_\w+)\)|y|objs|m)\s*[+:]?=\s*(.*)", line)
            if not m or target not in m[4].split():
                continue
            return m[1], m[3] or ""
        return None


def classify_config(files: list[str], tree: KernelTree, arch: str) -> tuple[str, str] | None:
    sources = list(dict.fromkeys(f for f in files if f.endswith(".c")))
    if not sources:
        return None
    other_arch = [f for f in sources if f.startswith("arch/") and not f.startswith(f"arch/{arch}/")]
    if other_arch and len(other_arch) == len(sources):
        return "not-built-arch", f"all program files are under non-{arch} arch/ trees: {', '.join(other_arch[:4])}"
    missing = [f for f in sources if f not in tree.files]
    if len(missing) == len(sources):
        return "manual-file-missing", f"no program file exists in this source tree: {', '.join(missing[:4])}"
    reasons: list[str] = []
    states: list[str] = []
    for f in sources:
        if f in missing:
            reasons.append(f"{f}: not in source tree")
            states.append("n")
            continue
        if f.startswith("arch/") and not f.startswith(f"arch/{arch}/"):
            reasons.append(f"{f}: other architecture")
            states.append("n")
            continue
        conds = tree.conditions(f)
        if conds is None:
            return "manual-unknown", f"cannot map {f} to a Kconfig symbol"
        off = [c for c in conds if tree.value(c) == "n"]
        if off:
            reasons.append(f"{f}: needs {off[0]} (not set)")
            states.append("n")
        elif any(tree.value(c) == "m" for c in conds):
            mods = [c for c in conds if tree.value(c) == "m"]
            reasons.append(f"{f}: {mods[0]}=m")
            states.append("m")
        else:
            reasons.append(f"{f}: built in ({', '.join(conds) or 'unconditional'})")
            states.append("y")
    if all(s == "n" for s in states):
        return "not-built-config", "; ".join(reasons)
    if "y" in states:
        return "manual-builtin", "; ".join(reasons)
    return "manual-module", "; ".join(reasons)


# --- statements ----------------------------------------------------------------


def nixpkgs_pin() -> str:
    """The short nixpkgs revision locked in flake.lock."""
    lock = cast("dict[str, dict[str, dict[str, object]]]", json.loads((REPO / "flake.lock").read_text()))
    root = cast("dict[str, str]", lock["nodes"]["root"]["inputs"])
    locked = cast("dict[str, str]", lock["nodes"][root["nixpkgs"]]["locked"])
    return locked["rev"][:7]


def statement(d: Draft, ours: str, ev: str, pin: str) -> dict[str, object]:
    base: dict[str, object] = {
        "@id": f"{FEED_ID}#{d.cve}-linux",
        "vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{d.cve}", "name": d.cve},
        "products": [{"@id": f"pkg:nix/linux@{ours}"}],
    }
    shipped = f"nixpkgs ships Linux {ours} at the pinned nixpkgs revision ({pin})."
    # A shortened title already ends in "…"; it takes no full stop.
    title = d.title if d.title.endswith("…") else d.title.rstrip(".") + "."
    found = ev[:1].upper() + ev[1:]
    record = f"https://cveawg.mitre.org/api/cve/{d.cve}"
    if d.klass.startswith("fixed"):
        base["status"] = "fixed"
        base["status_notes"] = f"{title} {found}. CVE record: {record}. {shipped}"
    elif d.klass == "affected-update":
        base["status"] = "affected"
        branch = ".".join(ours.split(".")[:2])
        base["action_statement"] = (
            f"Update to the fixed {branch} stable release named in the CNA record (not packaged by nixpkgs at the pinned revision)."
        )
        base["status_notes"] = f"{title} {found}. CVE record: {record}. {shipped}"
    else:
        base["status"] = "not_affected"
        base["justification"] = "vulnerable_code_not_present"
        base["impact_statement"] = f"{title} {found}. Source: {record}. {shipped}"
        # Build-based verdicts hold only for the triaged architecture, and
        # config-based ones only for nixpkgs' kernel config.
        if d.klass == "not-built-arch":
            base["impact_statement"] += " Applies only while the system is x86_64-linux."
            base["status_notes"] = "[nixos-vex:condition=x86-64]"
        elif d.klass == "not-built-config":
            base["impact_statement"] += (
                " Applies only while the system is x86_64-linux and runs nixpkgs' default kernel unmodified,"
                + " whose build configuration this verdict rests on."
            )
            base["status_notes"] = "[nixos-vex:condition=x86-64] [nixos-vex:condition=stock-kernel]"
    return base


def classify(
    cve: str,
    sev: str,
    ours: Version,
    logs: dict[int, str],
    tree: KernelTree,
    debian: dict[str, DebianEntry],
    pin: str,
) -> Draft:
    rec = cve_record(cve)
    cna = rec["containers"]["cna"]
    short = cna["providerMetadata"]["shortName"]
    d = Draft(cve=cve, severity=sev, cna=short, title=title_of(cna), klass="manual-unknown")
    aff = cna.get("affected", [])
    ev: str | None = None

    if short == "Linux":
        hit = classify_branch(aff, ours)
        if hit and hit[0] != "affected-update":
            d.klass, ev = hit
        else:
            fix_shas = [
                e["lessThan"]
                for a in aff
                for e in a.get("versions", [])
                if e.get("versionType") == "git" and "lessThan" in e
            ]
            d.fix_shas = fix_shas
            older = {n: t for n, t in logs.items() if n <= ours[2]}
            newer = {n: t for n, t in logs.items() if n > ours[2]}
            found = find_in_changelogs(fix_shas, older)
            later = find_in_changelogs(fix_shas, newer)
            if found:
                d.klass = "fixed-changelog"
                ev = (
                    f"fix {found[1][:12]} backported in {fmt(ours[:2])}.{found[0]} "
                    + f"(ChangeLog-{fmt(ours[:2])}.{found[0]}); the CNA record lists no {fmt(ours[:2])} entry "
                    + f"[vexlint:watch_record={cna['providerMetadata'].get('dateUpdated', '')}]"
                )
            elif hit:
                d.klass, ev = hit
            else:
                branch = fmt(ours[:2])
                if later:
                    d.evidence.append(
                        f"fix {later[1][:12]} backported only in {branch}.{later[0]} (newer than {fmt(ours)})"
                    )
                # A backport the record's SHA misses: same subject line. Evidence
                # only, as subjects are not unique.
                if titled := find_title_in_changelogs(d.title, older):
                    reverted = [n for n in find_reverts(fix_shas, d.title, older) if n > titled]
                    d.evidence.append(
                        f"a commit with the fix's subject is in ChangeLog-{branch}.{titled}, not under the record's "
                        + "SHA: verify it is the fix"
                        + (f" (reverted in {branch}.{reverted[0]})" if reverted else "")
                    )
                elif fix_shas and not later:
                    d.evidence.append(
                        f"fix not in any {branch}.y ChangeLog up to {fmt(ours)} (searched by SHA "
                        + f"{', '.join(s[:12] for s in fix_shas)} and by subject)"
                    )
    else:
        urls, tagged = referenced_commits(rec, cve)
        shas = list(urls)
        d.fix_shas = shas
        tag = f"v{fmt(ours[:2])}"
        older = {n: t for n, t in logs.items() if n <= ours[2]}
        # Every referenced fix commit must be in our kernel: a fix may span
        # several commits, and an untagged reference may be the commit that
        # introduced the flaw rather than the fix.
        where: list[str] = []
        for sha in shas:
            if is_ancestor(sha, tag):
                where.append(f"{sha[:12]} is an ancestor of {tag}")
            elif found := find_in_changelogs([sha], older):
                where.append(
                    f"{sha[:12]} backported in {fmt(ours[:2])}.{found[0]} (ChangeLog-{fmt(ours[:2])}.{found[0]})"
                )
            elif (main := mainline_for(sha, urls[sha])) and is_ancestor(main[0], tag):
                # A subsystem tree's SHA (e.g. bluetooth-next): its mainline twin
                # by exact subject is what our kernel contains.
                where.append(f'{sha[:12]} is mainline {main[0][:12]} ("{main[1]}"), an ancestor of {tag}')
            else:
                break
        source = "patch references" if tagged else "references"
        if shas and len(where) == len(shas):
            d.klass = "fixed-ancestor" if all("ancestor" in w for w in where) else "fixed-changelog"
            ev = f"every fix commit in the CVE {source}: " + "; ".join(where)
        elif (deb := classify_debian(cve, debian, ours)) and deb[0] == "fixed-debian":
            d.klass, ev = deb
        # Debian's "not affected" hints at code mainline never had: a human
        # decides, whatever Ubuntu maps as the fix.
        elif (deb is None or deb[0] == "manual-debian-older-branch") and (uct := classify_ubuntu(d, ours, older, tree)):
            d.klass, ev = uct
        elif deb:
            d.klass, ev = deb
        elif shas:
            d.evidence.append(
                f"referenced commits ({source}) not all in {tag} or its stable releases up to {fmt(ours)}: {', '.join(s[:12] for s in shas)}"
            )
        else:
            d.evidence.append("no fix commit referenced, no Debian fixed version")

    if ev is None:
        files = [f for a in aff for f in a.get("programFiles", [])]
        hit = classify_config(files, tree, "x86")
        if hit:
            d.klass, ev = hit
        elif not files:
            d.evidence.append("no programFiles in the CNA record")
    d.reverts = [
        f"{fmt(ours[:2])}.{n}"
        for n in find_reverts(d.fix_shas, d.title, {n: t for n, t in logs.items() if n <= ours[2]})
    ]
    if ev is not None:
        d.evidence.insert(0, ev)
        if d.klass in AUTO_CLASSES:
            d.statement = statement(d, fmt(ours), ev, pin)
    return d


# --- output --------------------------------------------------------------------


def write_reports(host: str, drafts: list[Draft]) -> None:
    out = REPORTS
    _ = (out / f"kernel-triage-{host}.json").write_text(json.dumps([asdict(d) for d in drafts], indent=2) + "\n")
    lines = [f"# Kernel triage drafts: {host}", ""]
    order = [
        *AUTO_CLASSES,
        "manual-debian-not-affected",
        "manual-debian-older-branch",
        "manual-file-missing",
        "manual-module",
        "manual-builtin",
        "manual-unknown",
    ]
    for k in order:
        group = [d for d in drafts if d.klass == k]
        if not group:
            continue
        lines += [f"## {k} ({len(group)})", "", "| CVE | Sev | CNA | Title | Evidence |", "|---|---|---|---|---|"]
        for d in group:
            ev = "; ".join(d.evidence).replace("|", "\\|")
            lines.append(f"| {d.cve} | {d.severity} | {d.cna} | {d.title.replace('|', '/')} | {ev} |")
        lines.append("")
    _ = (out / f"kernel-triage-{host}.md").write_text("\n".join(lines))


def apply(drafts: list[Draft], selectors: list[str]) -> None:
    """Append the drafts of the selected classes or CVEs through feed.py,
    which logs each as a decision of its class (signed off per class)."""
    feed = Feed()
    for d in drafts:
        if d.statement is None or not (d.klass in selectors or d.cve in selectors):
            continue
        if f"{FEED_ID}#{d.cve}-linux" in feed.ids:
            continue
        version = cast("list[dict[str, str]]", d.statement["products"])[0]["@id"].rsplit("@", 1)[1]
        _ = feed.add(dict(d.statement), d.cve, "linux", version, rule_origin(__file__, d.klass))
    if not feed.changed:
        # Nothing new: the document is unchanged, so its version stays.
        print("kernel-cna-triage: no new statement(s); the feed is unchanged")
        return
    feed.write()
    print(f"kernel-cna-triage: added {len(feed.events)} statement(s) to the feed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("host")
    _ = parser.add_argument("--apply", nargs="+", default=[], metavar="CLASS|CVE")
    args = parser.parse_args()
    host = cast("str", args.host)

    vulns = REPORTS / f"{host}.vulns.json"
    if not vulns.exists():
        sys.exit(f"kernel-cna-triage: {vulns} missing; run `make scan` first")
    report = cast("Report", json.loads(vulns.read_text()))
    findings: dict[str, str] = {}
    versions: set[str] = set()
    for m in report.get("matches", []):
        if m["artifact"]["name"] == "linux":
            findings[m["vulnerability"]["id"]] = m["vulnerability"].get("severity", "Unknown")
            versions.add(m["artifact"]["version"])
    if len(versions) != 1:
        sys.exit(f"kernel-cna-triage: expected one linux version, got {sorted(versions)}")
    ours_s = versions.pop()
    ours = parse_version(ours_s)
    if ours is None or len(ours) != 3:
        sys.exit(f"kernel-cna-triage: unsupported kernel version {ours_s}")

    kernel = f"{REPO}#nixosConfigurations.{host}.config.boot.kernelPackages.kernel"
    tree = KernelTree(nix_out(f"{kernel}.src"), nix_out(f"{kernel}.configfile"))
    logs = changelogs(ours)
    debian = debian_linux()
    pin = nixpkgs_pin()
    drafts = [classify(cve, sev, ours, logs, tree, debian, pin) for cve, sev in sorted(findings.items())]
    write_reports(host, drafts)

    for k, n in Counter(d.klass for d in drafts).most_common():
        print(f"  {n:4d} {k}")
    print(f"kernel-cna-triage: {len(drafts)} finding(s), drafts in {REPORTS / f'kernel-triage-{host}.md'}")
    selectors = cast("list[str]", args.apply)
    if selectors:
        apply(drafts, selectors)


if __name__ == "__main__":
    main()
