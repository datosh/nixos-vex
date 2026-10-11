#!/usr/bin/env python3
"""Check that a committed SBOM is exactly what sbomnix produces now (the zero
gate).

sbomnix takes every component's derivation from the target's evaluated
derivation closure, not from the store's recorded derivers, so the SBOM is a
function of the flake lock and the tool pins: the same on every machine. The
only fields that differ between runs are the random serialNumber and the
timestamp, which are ignored.

A stale or edited SBOM fails, and the differences are listed. The gate scans
the regenerated SBOM, so the committed one never decides a verdict.

Usage: sbom-check.py <committed.cdx.json> <regenerated.cdx.json>
"""

import argparse
import json
import pathlib
import sys
from typing import NoReturn, NotRequired, TypedDict, cast

# "bom-ref" is not an identifier, hence the functional syntax.
Component = TypedDict("Component", {"bom-ref": str, "name": NotRequired[str], "version": NotRequired[str]})


class Dependency(TypedDict):
    ref: str
    dependsOn: NotRequired[list[str]]


class Metadata(TypedDict):
    timestamp: NotRequired[str]


class Sbom(TypedDict):
    serialNumber: NotRequired[str]
    metadata: NotRequired[Metadata]
    components: NotRequired[list[Component]]
    dependencies: NotRequired[list[Dependency]]


def die(msg: str) -> NoReturn:
    print(f"sbom-check: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path: str) -> Sbom:
    try:
        sbom = cast("Sbom", json.loads(pathlib.Path(path).read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path}: {e}")
    _ = sbom.pop("serialNumber", None)
    _ = sbom.get("metadata", Metadata()).pop("timestamp", None)
    return sbom


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def components(sbom: Sbom) -> dict[str, Component]:
    return {c["bom-ref"]: c for c in sbom.get("components", [])}


def label(ref: str, c: Component) -> str:
    return f"{c.get('name', '?')} {c.get('version', '')} ({ref.rsplit('/', 1)[-1]})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _ = parser.add_argument("committed")
    _ = parser.add_argument("regenerated")
    args = parser.parse_args()
    committed, regenerated = load(cast("str", args.committed)), load(cast("str", args.regenerated))

    if canonical(committed) == canonical(regenerated):
        print(
            f"sbom-check: the committed SBOM equals the regenerated one ({len(committed.get('components', []))} components)"
        )
        return

    problems = [
        f"{key} differs"
        for key in sorted((set(committed) | set(regenerated)) - {"components", "dependencies"})
        if canonical(committed.get(key)) != canonical(regenerated.get(key))
    ]
    a, b = components(committed), components(regenerated)
    problems += [f"only committed: {label(r, a[r])}" for r in sorted(a.keys() - b.keys())]
    problems += [f"only regenerated: {label(r, b[r])}" for r in sorted(b.keys() - a.keys())]
    problems += [
        f"changed: {label(r, a[r])}" for r in sorted(a.keys() & b.keys()) if canonical(a[r]) != canonical(b[r])
    ]
    deps_a = {d["ref"]: sorted(d.get("dependsOn", [])) for d in committed.get("dependencies", [])}
    deps_b = {d["ref"]: sorted(d.get("dependsOn", [])) for d in regenerated.get("dependencies", [])}
    changed_deps = sum(deps_a.get(r) != deps_b.get(r) for r in deps_a.keys() | deps_b.keys())
    if changed_deps:
        problems.append(f"{changed_deps} dependency entries differ")

    print("sbom-check: FAIL - the committed SBOM differs from what sbomnix produces for this commit")
    for p in problems[:40]:
        print(f"  {p}")
    if len(problems) > 40:
        print(f"  … and {len(problems) - 40} more")
    print("sbom-check: run `make sbom` and commit sboms/")
    sys.exit(1)


if __name__ == "__main__":
    main()
