#!/usr/bin/env python3
"""The one writer of the feed (vex/baseline.openvex.json) and the triage log
(triage/).

Every tool that writes statements goes through Feed, so the conventions in
CLAUDE.md hold whoever writes:
- a new statement gets the @id <doc @id>#<CVE>-<pkg>, or
  <doc @id>#<CVE>-<pkg>-<version> when that is taken (IDs are immutable),
  and a timestamp (today); it is appended to the feed
- an extended statement gets the new purl in its products, the reason
  sentence in its status_notes (once) and last_updated (today)
- the document version is bumped once per branch: one more than the base
  branch's (origin/main), whatever number of writes; last_updated is today

Every write is also a decision event in the triage log: one file per
statement, triage/<CVE>-<pkg>[-<version>].json, holding the statement's
@id and its events in order. An event records the product it covers, the
status, its origin (a rule of a script at the script's revision, or "ai"),
the AI's reason class, finding type, claims and re-check triggers, and the
sign-off (who, when, per class or per finding, amended or not). Reason
classes are internal; they never appear in statements.

The CLI applies decision records drafted by the triage skill
(reports/decisions/*.json) after the user signed them off per finding:

  feed.py apply <decision.json>... [--amended]

A record proposes one new statement, or names an existing one to extend
(`extends`). It needs at least one claim; claims with an excerpt or a check
are verified again (evidence.py) and stored with the source's sha256. A
failed check refuses the whole run. --amended records that the user changed
the AI's proposal before signing it off.
"""

import argparse
import datetime
import json
import pathlib
import subprocess
import sys
from typing import NoReturn, NotRequired, TypedDict, cast

from evidence import Claim, verify

ROOT = pathlib.Path(__file__).resolve().parent.parent
FEED = ROOT / "vex" / "baseline.openvex.json"
TRIAGE = ROOT / "triage"
BASE_REF = "origin/main"

STATUSES = ("not_affected", "affected", "fixed")
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
STATEMENT_FIELDS = ("status", "justification", "impact_statement", "action_statement", "status_notes", "products")
FINDING_TYPES = ("matching-error", "version-range", "reachability", "no-upstream-fix")


class Signoff(TypedDict):
    by: str
    date: str
    scope: str  # "class" (deterministic rules) or "finding"
    amended: bool


class EventDetails(TypedDict, total=False):
    reason_class: str
    finding_type: str
    claims: list[Claim]
    counter_evidence: str
    recheck: list[str]


class Event(TypedDict):
    date: str
    action: str  # "new" or "extend"
    purl: str
    status: str
    origin: str
    signoff: Signoff
    decision: NotRequired[EventDetails]  # AI decisions: reason class, claims, ...


class LogFile(TypedDict):
    statement: str
    events: list[Event]


class Decision(TypedDict):
    cve: str
    package: str
    version: str
    finding_type: str
    reason_class: str
    # status plus justification/impact_statement/action_statement/status_notes;
    # products default to the versioned purl. With `extends`: only an optional
    # status_notes sentence saying why the version is covered.
    statement: dict[str, object]
    extends: NotRequired[str]
    claims: list[Claim]
    counter_evidence: str
    recheck: NotRequired[list[str]]


def die(msg: str) -> NoReturn:
    print(f"feed: {msg}", file=sys.stderr)
    sys.exit(1)


def read_json(path: pathlib.Path) -> object:
    try:
        return cast("object", json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read {path}: {e}")


def git(*args: str) -> str | None:
    out = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False)
    return out.stdout.strip() if out.returncode == 0 else None


def rule_origin(script: str, rule: str) -> str:
    """rule:<script>:<rule>@<last commit of the script>[+dirty]."""
    path = pathlib.Path(script).resolve()
    rev = git("log", "-1", "--format=%h", "--", str(path)) or "unknown"
    if git("diff", "--quiet", "HEAD", "--", str(path)) is None:
        rev += "+dirty"
    return f"rule:{path.stem}:{rule}@{rev}"


def signer() -> str:
    return git("config", "user.name") or "unknown"


def base_version() -> int | None:
    """The feed's document version on the base branch, if there is one."""
    raw = git("show", f"{BASE_REF}:{FEED.relative_to(ROOT)}")
    if raw is None:
        return None
    return cast("int", cast("dict[str, object]", json.loads(raw))["version"])


def today() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT00:00:00Z")


class Feed:
    def __init__(self, scope: str = "class", amended: bool = False, dry_run: bool = False) -> None:
        self.doc: dict[str, object] = cast("dict[str, object]", read_json(FEED))
        self.statements: list[dict[str, object]] = cast("list[dict[str, object]]", self.doc["statements"])
        self.ids: set[str] = {cast("str", st["@id"]) for st in self.statements}
        self.base: str = cast("str", self.doc["@id"])
        self.today: str = today()
        self.dry_run: bool = dry_run
        self.signoff: Signoff = {"by": signer(), "date": self.today, "scope": scope, "amended": amended}
        self.events: list[tuple[str, Event]] = []

    @property
    def changed(self) -> bool:
        return bool(self.events)

    def by_id(self, sid: str) -> dict[str, object] | None:
        return next((st for st in self.statements if st["@id"] == sid), None)

    def _event(
        self, sid: str, action: str, purl: str, st: dict[str, object], origin: str, details: EventDetails | None
    ) -> None:
        event: Event = {
            "date": self.today,
            "action": action,
            "purl": purl,
            "status": cast("str", st["status"]),
            "origin": origin,
            "signoff": self.signoff,
        }
        if details:
            event["decision"] = details
        self.events.append((sid, event))

    def extend(
        self, st: dict[str, object], purl: str, why: str, origin: str, details: EventDetails | None = None
    ) -> bool:
        """Add purl to the statement's products and, once, the sentence saying
        why later versions are covered. False if the purl was there already."""
        products = cast("list[dict[str, str]]", st["products"])
        if any(p.get("@id") == purl for p in products):
            return False
        products.append({"@id": purl})
        notes = cast("str", st.get("status_notes", ""))
        if why and why not in notes:
            st["status_notes"] = f"{notes} {why}".strip()
        st["last_updated"] = self.today
        self._event(cast("str", st["@id"]), "extend", purl, st, origin, details)
        return True

    def add(
        self, st: dict[str, object], cve: str, name: str, version: str, origin: str, details: EventDetails | None = None
    ) -> str:
        """Append a new statement (without @id) and return its @id."""
        fragment = f"{cve}-{name}"
        sid = f"{self.base}#{fragment}"
        if sid in self.ids:
            sid = f"{self.base}#{fragment}-{version}"
        if sid in self.ids:
            die(f"statement {sid} exists already")
        # The document timestamp predates it; the statement says when it was written.
        new = {"@id": sid, **{k: v for k, v in st.items() if k != "@id"}, "timestamp": self.today}
        self.statements.append(new)
        self.ids.add(sid)
        products = cast("list[dict[str, str]]", new["products"])
        self._event(sid, "new", products[0]["@id"], new, origin, details)
        return sid

    def write(self) -> None:
        if not self.changed or self.dry_run:
            return
        base = base_version()
        current = cast("int", self.doc["version"])
        # Once per branch: main is what is published.
        self.doc["version"] = max(current, base + 1) if base is not None else current + 1
        self.doc["last_updated"] = self.today
        _ = FEED.write_text(json.dumps(self.doc, indent=2, ensure_ascii=False) + "\n")
        for sid, event in self.events:
            log_event(sid, event)


def log_event(sid: str, event: Event) -> None:
    path = TRIAGE / f"{sid.rsplit('#', 1)[1]}.json"
    log: LogFile = cast("LogFile", read_json(path)) if path.exists() else {"statement": sid, "events": []}
    log["events"].append(event)
    TRIAGE.mkdir(exist_ok=True)
    _ = path.write_text(json.dumps(log, indent=2, ensure_ascii=False) + "\n")


def read_log() -> list[LogFile]:
    return [cast("LogFile", read_json(p)) for p in sorted(TRIAGE.glob("*.json"))]


# --- decision records ----------------------------------------------------------


def check_decision(d: Decision, feed: Feed) -> list[str]:
    """What is wrong with a decision record (empty when it can be applied)."""
    errors: list[str] = []
    st = d["statement"]
    if d["finding_type"] not in FINDING_TYPES:
        errors.append(f"finding_type {d['finding_type']!r} is not one of {', '.join(FINDING_TYPES)}")
    if not d["reason_class"]:
        errors.append("no reason_class")
    if not d["claims"]:
        errors.append("no claims")
    if not d["counter_evidence"]:
        errors.append("no counter_evidence")
    if unknown := sorted(set(st) - set(STATEMENT_FIELDS)):
        errors.append(f"unknown statement fields: {', '.join(unknown)}")
    if "extends" in d:
        target = feed.by_id(d["extends"])
        if target is None:
            errors.append(f"extends {d['extends']}, which is not in the feed")
        elif "status" in st and st["status"] != target["status"]:
            errors.append(f"extends a {target['status']} statement with status {st['status']}")
        if set(st) - {"status", "status_notes"}:
            errors.append("extends takes only a status_notes sentence")
        return errors
    status = st.get("status")
    if status not in STATUSES:
        errors.append(f"status {status!r} is not one of {', '.join(STATUSES)}")
    if status == "not_affected":
        if st.get("justification") not in JUSTIFICATIONS:
            errors.append(f"not_affected needs a justification out of {', '.join(JUSTIFICATIONS)}")
        if not st.get("impact_statement"):
            errors.append("not_affected needs an impact_statement")
    if status == "affected" and not st.get("action_statement"):
        errors.append("affected needs an action_statement")
    if status != "not_affected" and ("justification" in st or "impact_statement" in st):
        errors.append("justification and impact_statement belong to not_affected only")
    return errors


def details_of(d: Decision, claims: list[Claim]) -> EventDetails:
    details: EventDetails = {
        "reason_class": d["reason_class"],
        "finding_type": d["finding_type"],
        "claims": claims,
        "counter_evidence": d["counter_evidence"],
    }
    if "recheck" in d:
        details["recheck"] = d["recheck"]
    return details


def apply(paths: list[str], amended: bool) -> None:
    feed = Feed(scope="finding", amended=amended)
    decisions = [(p, cast("Decision", read_json(pathlib.Path(p)))) for p in paths]
    problems: list[str] = []
    verified: list[list[Claim]] = []
    for p, d in decisions:
        problems += [f"{p}: {e}" for e in check_decision(d, feed)]
        claims: list[Claim] = []
        for c in d["claims"]:
            checked, detail = verify(c)
            if checked.get("verified") is False:
                problems.append(f"{p}: claim failed its check ({detail}): {c['text']}")
            claims.append(checked)
        verified.append(claims)
    if problems:
        die("nothing written:\n  " + "\n  ".join(problems))

    for (_, d), claims in zip(decisions, verified, strict=True):
        purl = f"pkg:nix/{d['package']}@{d['version']}"
        st = dict(d["statement"])
        if "extends" in d:
            target = cast("dict[str, object]", feed.by_id(d["extends"]))
            if not feed.extend(target, purl, cast("str", st.get("status_notes", "")), "ai", details_of(d, claims)):
                die(f"{d['extends']} covers {purl} already")
            print(f"feed: extended {d['extends'].rsplit('#', 1)[1]} to {purl}")
            continue
        _ = st.setdefault("products", [{"@id": purl}])
        new: dict[str, object] = {
            "vulnerability": {"@id": f"https://nvd.nist.gov/vuln/detail/{d['cve']}", "name": d["cve"]},
            "products": st["products"],
            **{k: st[k] for k in STATEMENT_FIELDS if k in st and k != "products"},
        }
        sid = feed.add(new, d["cve"], d["package"], d["version"], "ai", details_of(d, claims))
        print(f"feed: added {sid.rsplit('#', 1)[1]} ({new['status']})")
    feed.write()
    print(
        f"feed: {FEED.relative_to(ROOT)} at version {feed.doc['version']}; decisions logged under {TRIAGE.relative_to(ROOT)}/"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_apply = sub.add_parser("apply", help="write signed-off decision records as statements")
    _ = p_apply.add_argument("decisions", nargs="+")
    _ = p_apply.add_argument("--amended", action="store_true", help="the user changed the proposal before signing off")
    args = parser.parse_args()
    if cast("str", args.command) == "apply":
        apply(cast("list[str]", args.decisions), cast("bool", args.amended))


if __name__ == "__main__":
    main()
