#!/usr/bin/env python3
"""Move every scan pin to its latest version (`make bump`).

- flake inputs (nixpkgs, nixpkgs-tools, sbomnix): `nix flake update`
- tools/pins.json cpedictRev: the head of tiiuae/cpedict's main branch
- tools/pins.json grypeDb: Anchore's latest v6 DB (latest.json)

Prints what moved. Regenerating the SBOM and scanning is left to make
(`make bump` runs `make scan` afterwards). The daily run does the same and
never commits; a bump branch commits the result and triages what the scan
shows until `make zero` passes.

GITHUB_TOKEN, when set, authenticates the GitHub API call (rate limits).

Paths are relative to the repository root, whatever the working directory.

Usage: bump.py
"""

import argparse
import base64
import http.client
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
from typing import NoReturn, TypedDict, cast

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = ROOT / "tools" / "pins.json"
DB_BASE = "https://grype.anchore.io/databases/v6/"
CPEDICT_HEAD = "https://api.github.com/repos/tiiuae/cpedict/commits/main"


class GrypeDb(TypedDict):
    url: str
    hash: str
    built: str
    name: str


class Pins(TypedDict):
    cpedictRev: str
    grypeDb: GrypeDb


class Latest(TypedDict):
    schemaVersion: str
    built: str
    path: str
    checksum: str


class Commit(TypedDict):
    sha: str


def die(msg: str) -> NoReturn:
    print(f"bump: {msg}", file=sys.stderr)
    sys.exit(1)


def fetch_json(url: str, headers: dict[str, str] | None = None) -> object:
    # grype.anchore.io (Cloudflare) rejects urllib's default User-Agent.
    req = urllib.request.Request(url, headers={"User-Agent": "nixos-vex-bump", **(headers or {})})
    try:
        with cast("http.client.HTTPResponse", urllib.request.urlopen(req, timeout=60)) as resp:
            return cast("object", json.loads(resp.read()))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        die(f"cannot fetch {url}: {e}")


def latest_db() -> GrypeDb:
    latest = cast("Latest", fetch_json(DB_BASE + "latest.json"))
    algo, _, digest = latest["checksum"].partition(":")
    if algo != "sha256" or len(digest) != 64:
        die(f"unexpected checksum in latest.json: {latest['checksum']}")
    return GrypeDb(
        url=DB_BASE + latest["path"],
        hash="sha256-" + base64.b64encode(bytes.fromhex(digest)).decode(),
        built=latest["built"],
        name=f"grype-db-{latest['schemaVersion']}-{latest['built'][:10]}",
    )


def cpedict_head() -> str:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return cast("Commit", fetch_json(CPEDICT_HEAD, headers))["sha"]


def main() -> None:
    _ = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    # Resolve everything before changing anything, so a network failure
    # leaves the tree as it was.
    old = cast("Pins", json.loads(PINS.read_text()))
    new = Pins(cpedictRev=cpedict_head(), grypeDb=latest_db())
    if subprocess.run(["nix", "flake", "update"], cwd=ROOT, check=False).returncode != 0:
        die("nix flake update failed")
    _ = PINS.write_text(json.dumps(new, indent=2) + "\n")

    if old["cpedictRev"] != new["cpedictRev"]:
        print(f"bump: cpedict {old['cpedictRev'][:12]} -> {new['cpedictRev'][:12]}")
    if old["grypeDb"] != new["grypeDb"]:
        print(f"bump: grype DB built {old['grypeDb']['built']} -> {new['grypeDb']['built']}")


if __name__ == "__main__":
    main()
