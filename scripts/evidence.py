#!/usr/bin/env python3
"""Check the claims of a triage decision against their sources.

A claim is a sentence the reviewer can follow to its source. It may carry
something a machine can check:
- `excerpt`: text that must appear verbatim in the source (whitespace is
  normalised; HTML is reduced to its text, JSON to its string values)
- `check`:
  - {"type": "absent", "needle": "...", "sources": ["<url>", ...]}: the text
    appears neither in the source nor in any of the optional further sources
    (e.g. a fix missing from every stable ChangeLog of a branch). A source
    that cannot be fetched fails the check.
  - {"type": "ancestor", "repo": "torvalds/linux", "commit": "<sha>",
    "ref": "<tag>"}: the commit is in the ref's history (GitHub compare)
  - {"type": "not_ancestor", ...}: the same fields; the commit is not in the
    ref's history
  - {"type": "eval", "attr": "<attr>", "value": <JSON>, "apply": "<fn>"}: an
    attribute of the reference system (`.#nixosConfigurations.baseline.<attr>`,
    e.g. `config.services.openssh.enable`), optionally passed through a Nix
    function (`--apply`, e.g. "p: p ? opie" on `pkgs`), evaluates to `value`
  - {"type": "build", "attr": "<attr>", "path": "<glob>", "line": "..."}: the
    built attribute (or the one file `path` matches inside it) has a line
    equal to `line`, e.g. "CONFIG_SMC=m" in
    `config.boot.kernelPackages.kernel.configfile` or "alias net-pf-43 smc"
    in `config.system.modulesTree` at `lib/modules/*/modules.alias`. With
    `no_line_prefix` instead: no line starts with it ("CONFIG_X=" for a
    symbol that is not set).
  For `eval` and `build` the claim's `source` names what was evaluated (e.g.
  "nix:config.boot.kernelPackages.kernel.configfile"); nothing is fetched.

verify() returns the claim with `verified` (true or false) and, for fetched
or built sources, their `sha256` (of all of them, in order); a claim with
nothing to check is returned unchanged (the reviewer checks it). Fetches and
GitHub calls are retried on transient errors. Sources are cached under
reports/cache/evidence/ and refetched once older than 12 hours.

Usage: evidence.py <decision.json>...   (prints each claim's result)
"""

import functools
import glob
import hashlib
import html
import http.client
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import NotRequired, TypedDict, cast

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / "reports" / "cache" / "evidence"
HOST = "baseline"
FRESH = 12 * 3600
ATTEMPTS = 3


class Check(TypedDict):
    type: str
    needle: NotRequired[str]
    sources: NotRequired[list[str]]
    repo: NotRequired[str]
    commit: NotRequired[str]
    ref: NotRequired[str]
    attr: NotRequired[str]
    value: NotRequired[object]
    apply: NotRequired[str]
    path: NotRequired[str]
    line: NotRequired[str]
    no_line_prefix: NotRequired[str]


class Claim(TypedDict):
    text: str
    source: str
    excerpt: NotRequired[str]
    check: NotRequired[Check]
    sha256: NotRequired[str]
    verified: NotRequired[bool]


def transient(e: Exception) -> bool:
    """Worth retrying: a network error or a server-side HTTP status, not a 4xx."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500 or e.code == 429
    return True


def fetch(url: str) -> bytes | None:
    path = CACHE / hashlib.sha256(url.encode()).hexdigest()[:24]
    if path.exists() and time.time() - path.stat().st_mtime < FRESH:
        return path.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": "nixos-vex-triage"})
    for attempt in range(ATTEMPTS):
        try:
            resp = cast("http.client.HTTPResponse", urllib.request.urlopen(req, timeout=60))
            with resp:
                data = resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            if transient(e) and attempt + 1 < ATTEMPTS:
                time.sleep(2 * (attempt + 1))
                continue
            return path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True, exist_ok=True)
        _ = path.write_bytes(data)
        return data
    return None


def strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in cast("dict[str, object]", value).values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in cast("list[object]", value) for s in strings(v)]
    return []


def searchable(raw: bytes) -> str:
    """The source as text a quote can be found in."""
    text = raw.decode("utf-8", errors="replace")
    try:
        text = "\n".join(strings(cast("object", json.loads(text))))
    except json.JSONDecodeError:
        # Only HTML pages lose their markup; XML (a D-Bus policy, an SVG)
        # keeps its tags, so an excerpt may quote them.
        if re.search(r"<html\b|<!doctype\s+html", text[:2000], re.IGNORECASE):
            text = re.sub(r"<(script|style)\b.*?</\1>", " ", text, flags=re.DOTALL | re.IGNORECASE)
            text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return normalise(text)


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compare(repo: str, commit: str, ref: str) -> str | None:
    """GitHub's compare status of commit...ref ("ahead", "identical",
    "behind", "diverged"), or None if it cannot be had."""
    for attempt in range(ATTEMPTS):
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/compare/{commit}...{ref}", "--jq", ".status"],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode == 0:
            return out.stdout.strip()
        # An unknown commit or ref is a 404 or 422: retrying will not help.
        if re.search(r"HTTP 4\d\d", out.stderr) or attempt + 1 == ATTEMPTS:
            return None
        time.sleep(2 * (attempt + 1))
    return None


def system_attr(attr: str) -> str:
    return f"{ROOT}#nixosConfigurations.{HOST}.{attr}"


@functools.cache
def nix_eval(attr: str, apply: str | None) -> object:
    cmd = ["nix", "eval", "--json", system_attr(attr)] + (["--apply", apply] if apply else [])
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise ValueError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "nix eval failed")
    return cast("object", json.loads(out.stdout))


@functools.cache
def nix_build(attr: str) -> pathlib.Path:
    out = subprocess.run(
        ["nix", "build", "--no-link", "--print-out-paths", system_attr(attr)],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise ValueError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "nix build failed")
    return pathlib.Path(out.stdout.strip())


def verify_eval(out: Claim, check: Check) -> tuple[Claim, str]:
    attr = check.get("attr", "")
    try:
        value = nix_eval(attr, check.get("apply"))
    except ValueError as e:
        out["verified"] = False
        return out, f"cannot evaluate {attr}: {e}"
    out["verified"] = value == check.get("value")
    return out, f"{attr} evaluates to {json.dumps(value)[:80]}"


def verify_build(out: Claim, check: Check) -> tuple[Claim, str]:
    attr = check.get("attr", "")
    try:
        built = nix_build(attr)
    except ValueError as e:
        out["verified"] = False
        return out, f"cannot build {attr}: {e}"
    target = built
    if pattern := check.get("path"):
        matches = glob.glob(str(built / pattern))
        if len(matches) != 1:
            out["verified"] = False
            return out, f"{pattern} matches {len(matches)} files in {attr}, not one"
        target = pathlib.Path(matches[0])
    raw = target.read_bytes()
    out["sha256"] = hashlib.sha256(raw).hexdigest()
    lines = [line.strip() for line in raw.decode("utf-8", errors="replace").splitlines()]
    if "line" in check:
        want = check["line"].strip()
        out["verified"] = bool(want) and want in lines
        return out, f"line {want!r} {'found in' if out['verified'] else 'not in'} {attr}"
    prefix = check.get("no_line_prefix", "")
    hit = next((line for line in lines if line.startswith(prefix)), None) if prefix else ""
    out["verified"] = hit is None
    return out, f"no line starts with {prefix!r} in {attr}" if hit is None else f"found {hit!r} in {attr}"


def verify(claim: Claim) -> tuple[Claim, str]:
    """The claim with its check result, and a short explanation."""
    out = Claim(**claim)
    check = claim.get("check")
    kind = check["type"] if check else None
    if check and kind in ("ancestor", "not_ancestor"):
        repo, commit, ref = check.get("repo", ""), check.get("commit", ""), check.get("ref", "")
        status = compare(repo, commit, ref)
        if status is None:
            out["verified"] = False
            return out, f"cannot compare {commit[:12]} with {ref} in {repo}"
        inside = status in ("ahead", "identical")
        out["verified"] = inside == (kind == "ancestor")
        return out, f"{commit[:12]} {'is' if inside else 'is not'} in the history of {ref}"
    if check and kind == "eval":
        return verify_eval(out, check)
    if check and kind == "build":
        return verify_build(out, check)
    if "excerpt" not in claim and not check:
        return out, "nothing to check; the reviewer follows the source"
    if check and kind != "absent":
        out["verified"] = False
        return out, f"unknown check type {kind!r}"
    urls = [claim["source"], *(check.get("sources", []) if check else [])]
    raws: list[bytes] = []
    for url in urls:
        raw = fetch(url)
        if raw is None:
            out["verified"] = False
            return out, f"cannot fetch {url}"
        raws.append(raw)
    digest = hashlib.sha256()
    for raw in raws:
        digest.update(raw)
    out["sha256"] = digest.hexdigest()
    texts = [searchable(raw) for raw in raws]
    if check:
        needle = normalise(check.get("needle", ""))
        found = [url for url, text in zip(urls, texts, strict=True) if needle in text]
        out["verified"] = bool(needle) and not found
        where = "the source" if len(urls) == 1 else f"all {len(urls)} sources"
        return out, f"{needle!r} absent from {where}" if out["verified"] else f"{needle!r} found in {found[:1]}"
    excerpt = normalise(claim.get("excerpt", ""))
    out["verified"] = bool(excerpt) and excerpt in texts[0]
    return out, "excerpt found in the source" if out["verified"] else "excerpt not found in the source"


def main() -> None:
    failed = False
    for path in sys.argv[1:]:
        decision = cast("dict[str, object]", json.loads(pathlib.Path(path).read_text()))
        for claim in cast("list[Claim]", decision.get("claims", [])):
            checked, detail = verify(claim)
            result = checked.get("verified")
            mark = "--" if result is None else "ok" if result else "FAIL"
            failed |= result is False
            print(f"{mark:4} {path}: {claim['text']}\n     {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
